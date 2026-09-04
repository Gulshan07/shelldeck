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
SSHD_PORT, SSH_PW = 2294, "pw"


async def fake_sshd():
    async def handler(proc):
        proc.stdout.write("hi\r\n")
        proc.exit(0)

    class S(asyncssh.SSHServer):
        def begin_auth(self, u): return True
        def password_auth_supported(self): return True
        def validate_password(self, u, p): return p == SSH_PW

    await asyncssh.create_server(
        S, "127.0.0.1", SSHD_PORT, process_factory=handler, sftp_factory=True,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")])


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
    await fake_sshd()
    store.save_config({"connections": [
        {"id": "a", "name": "alpha", "group": "g", "host": "127.0.0.1", "port": SSHD_PORT,
         "user": "u", "auth": "password", "jump": "", "forwards": []}],
        "vpns": [{"id": "v", "name": "vee", "username": "u", "dialect": "auto"}]})

    # a directory with more rows than fit on screen, to test scroll containment
    big = os.path.join(os.environ["EAZY_HOME"], "big")
    os.makedirs(big, exist_ok=True)
    for i in range(120):
        with open(os.path.join(big, f"file-{i}.bin"), "wb") as fh:
            fh.write(b"x" * (i + 1))

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

        # --- accessibility: the app must be usable without a mouse -----------
        # Every visible control needs an accessible name, or a screen reader
        # announces "button" / the glyph's unicode name.
        unnamed = json.loads(await c.js("""JSON.stringify(
            [...document.querySelectorAll('button, [role=button]')]
              .filter(el => el.offsetParent !== null)
              // a bare glyph ("?", an emoji, a dingbat) is not a name a screen
              // reader can speak, so require letters in aria-label or text
              .filter(el => !/[a-z]/i.test((el.getAttribute('aria-label') || el.textContent).trim()))
              .map(el => el.className || el.id || el.outerHTML.slice(0, 60)))"""))
        assert unnamed == [], f"controls with no accessible name: {unnamed}"
        print(f"ok  every visible control has an accessible name")

        # A connection must be focusable and openable with the keyboard alone.
        assert await c.js('document.querySelector(".conn").focus(), '
                          'document.activeElement.classList.contains("conn")'), \
            "connections are not keyboard-focusable"
        before = await c.js("tabs.length")
        for t in ("keyDown", "keyUp"):     # a real key event, not a synthetic click
            await c.call("Input.dispatchKeyEvent", type=t, key="Enter", code="Enter",
                         windowsVirtualKeyCode=13, nativeVirtualKeyCode=13)
        await asyncio.sleep(1.5)
        assert await c.js("tabs.length") == before + 1, \
            "pressing Enter on a focused connection did not open a session"
        print("ok  keyboard-only: focus a connection, press Enter, session opens")

        # focus must be visible once focusable
        ring = await c.js("""(() => { const el = document.querySelector('.conn');
            el.focus(); return getComputedStyle(el).boxShadow !== 'none'; })()""")
        assert ring, "focused connection has no visible focus ring"
        print("ok  focused elements show a visible focus ring")

        # light/dark chrome theme toggles and persists
        await c.js('document.querySelector("#theme-btn").click()')
        assert await c.js('document.documentElement.getAttribute("data-theme")') == "light"
        assert await c.js('localStorage.getItem("chromeTheme")') == "light"
        await c.js('document.querySelector("#theme-btn").click()')
        assert await c.js('document.documentElement.getAttribute("data-theme")') == "dark"
        print("ok  chrome theme toggles light/dark and persists")

        # A long listing must scroll inside its pane, not stretch the page. Every
        # ancestor needs min-height:0 or the grid item grows and nothing scrolls.
        server.vault.put("a", {"password": SSH_PW})
        store.KNOWN_HOSTS.write_text(server.known_hosts_entry(
            "127.0.0.1", SSHD_PORT, await asyncssh.get_server_host_key("127.0.0.1", port=SSHD_PORT)))
        await c.js('openSession("a","sftp",false)')
        await asyncio.sleep(2)
        await c.js(f'activeTab.panes[0].ws.send(JSON.stringify({{op:"ls",path:{big!r}}}))')
        await asyncio.sleep(2)
        rows = await c.js('document.querySelectorAll(".sftp-list .row").length')
        assert rows >= 100, f"expected a long listing, got {rows} rows"
        m = json.loads(await c.js("""JSON.stringify({
            win: innerHeight, doc: document.documentElement.scrollHeight,
            scrollable: (() => { const l = document.querySelector(".sftp-list");
                                 return l.scrollHeight > l.clientHeight; })()})"""))
        assert m["doc"] <= m["win"] + 2, \
            f"page grew to {m['doc']}px for a {m['win']}px window: the listing is not contained"
        assert m["scrollable"], "the file list does not scroll, so the tail is unreachable"
        print(f"ok  {rows} files scroll inside the pane, page stays at {m['doc']}px")

    print("\nui passed")

asyncio.run(main())
