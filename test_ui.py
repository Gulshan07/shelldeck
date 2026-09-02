"""Browser-level checks, driven through Chrome DevTools Protocol.

Four bugs so far lived purely in DOM semantics and were invisible to the other
suites: el.hidden vs author CSS, a 0x0 resize killing a session, an upload that
outran the socket, and a hidden input surviving form.reset(). This is the guard.

Skips cleanly when Chrome is absent.
Run: .venv/bin/python test_ui.py
"""
import asyncio, json, os, random, shutil, socket, subprocess, sys, tempfile, threading, time
import urllib.request

CHROME = next((c for c in ("google-chrome", "chromium", "chromium-browser") if shutil.which(c)), None)
if not CHROME:
    print("skip: no chrome on PATH")
    sys.exit(0)

os.environ["EAZY_HOME"] = tempfile.mkdtemp()
import asyncssh, uvicorn, websockets
from eazyconnector import store, server

MASTER = "ui-master-pw"


async def serve():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    uv = uvicorn.Server(uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=uv.run, daemon=True).start()
    for _ in range(60):
        await asyncio.sleep(0.1)
        if uv.started:
            break
    assert uv.started, "uvicorn did not start"
    return port


class Chrome:
    def __init__(self):
        self.dbg = random.randint(9200, 9990)
        self.proc = subprocess.Popen(
            [CHROME, "--headless", "--disable-gpu", "--no-sandbox",
             f"--remote-debugging-port={self.dbg}", "--window-size=1400,800",
             f"--user-data-dir={tempfile.mkdtemp()}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.n = 0

    async def __aenter__(self):
        for _ in range(80):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.dbg}/json/list"))
                page = next(t for t in tabs if t["type"] == "page")
                break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            raise RuntimeError("chrome never came up")
        self.ws = await websockets.connect(page["webSocketDebuggerUrl"], max_size=32 * 1024 * 1024)
        await self.call("Page.enable")
        return self

    async def __aexit__(self, *e):
        await self.ws.close()
        self.proc.terminate()

    async def call(self, method, **params):
        self.n += 1
        await self.ws.send(json.dumps({"id": self.n, "method": method, "params": params}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    async def js(self, expr):
        r = await self.call("Runtime.evaluate", expression=expr, awaitPromise=True,
                            returnByValue=True)
        if r.get("exceptionDetails"):
            raise RuntimeError(str(r["exceptionDetails"])[:300])
        return r["result"].get("value")


async def main():
    store.init_home()
    port = await serve()
    store.save_config({"connections": [
        {"id": "a", "name": "alpha", "group": "g", "host": "10.0.0.1", "port": 22,
         "user": "u", "auth": "password", "jump": "", "forwards": []}],
        "vpns": [{"id": "v", "name": "vee", "username": "u", "dialect": "auto"}]})

    async with Chrome() as c:
        await c.call("Page.navigate", url=f"http://127.0.0.1:{port}/#{server.TOKEN}")
        await asyncio.sleep(2)

        # the gate must actually disappear: author display:grid beats UA [hidden]
        await c.js(f'document.querySelector("#master").value={MASTER!r};'
                   'document.querySelector("#unlock-form").dispatchEvent(new Event("submit"))')
        await asyncio.sleep(2)
        assert await c.js('document.querySelector("#gate").offsetParent === null'), \
            "the unlock gate is still visible after unlocking"
        assert await c.js('document.querySelector("#app").offsetParent !== null')
        print("ok  unlock hides the gate and shows the app")

        # only one auth block shows at a time, same [hidden] mechanism
        await c.js('openEditor(null); document.querySelector("#conn-form").auth.value="key";'
                   'syncAuthFields()')
        assert await c.js('document.querySelector(".auth-password").offsetParent === null'), \
            "password field still visible in key mode"
        await c.js('document.querySelector("#editor").close("cancel")')
        print("ok  auth fields toggle instead of stacking")

        # editing must update in place, and a later add must NOT reuse that id
        await c.js('openEditor(conns[0]); document.querySelector("#conn-form").name.value="alpha2";'
                   'document.querySelector("#editor").close("save")')
        await asyncio.sleep(1)
        assert await c.js("conns.length") == 1, "editing should not create a second entry"
        assert await c.js("conns[0].name") == "alpha2"

        await c.js('openEditor(null)')
        assert await c.js('document.querySelector("#conn-form").id.value') == "", \
            "hidden id survived reset(): a new entry would overwrite the edited one"
        await c.js('''const f = document.querySelector("#conn-form");
            f.name.value="beta"; f.host.value="10.0.0.2"; f.user.value="u";
            document.querySelector("#editor").close("save");''')
        await asyncio.sleep(1.2)
        names = sorted(await c.js("JSON.stringify(conns.map(c=>c.name))") and
                       json.loads(await c.js("JSON.stringify(conns.map(c=>c.name))")))
        assert names == ["alpha2", "beta"], f"expected both entries, got {names}"
        print("ok  edit updates in place, then add creates a new entry")

        # same hidden-input trap in the vpn form
        await c.js('openVpnEditor(vpns[0]); document.querySelector("#vpn-editor").close("cancel");'
                   'openVpnEditor(null)')
        assert await c.js('document.querySelector("#vpn-form").id.value') == "", \
            "vpn hidden id survived reset()"
        await c.js('document.querySelector("#vpn-editor").close("cancel")')
        print("ok  vpn form clears its hidden id too")

        assert await c.js('document.querySelectorAll("#help section").length') >= 6
        print("ok  F1 manual is populated")

    print("\nui passed")

asyncio.run(main())
