"""Browser-level checks, driven through Chrome DevTools Protocol.

Four bugs so far lived purely in DOM semantics and were invisible to the other
suites: el.hidden vs author CSS, a 0x0 resize killing a session, an upload that
outran the socket, and a hidden input surviving form.reset(). This is the guard.

Skips cleanly when Chrome is absent.
Run: .venv/bin/python test_ui.py
"""
import asyncio, json, os, random, re, shutil, socket, subprocess, sys, tempfile, threading, time
import urllib.request

CHROME = next((c for c in ("google-chrome", "chromium", "chromium-browser") if shutil.which(c)), None)
if not CHROME:
    print("skip: no chrome on PATH")
    sys.exit(0)

os.environ["SHELLDECK_HOME"] = tempfile.mkdtemp()
import asyncssh, uvicorn, websockets
from shelldeck import store, server

MASTER = "ui-master-pw"
MIGRATION = ("otpauth-migration://offline?data=CigKCkhlbGxvId6tvu8SC2d1bHNoYW5AdnBuGgdWaXRyYXlhIAEoATACCj4KIDEy"
             "MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyEgtvcHNAZXhhbXBsZRoHRXhhbXBsZSACKAIwAgojCg5jb3VudGVyLXNl"
             "Y3JldBIDb2xkGgZMZWdhY3kgASgBMAEQARgBIAA%3D")
MAX_INSTANCES = 7   # must match app.js
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
    big = os.path.join(os.environ["SHELLDECK_HOME"], "big")
    os.makedirs(big, exist_ok=True)
    for i in range(120):
        with open(os.path.join(big, f"file-{i}.bin"), "wb") as fh:
            fh.write(b"x" * (i + 1))

    async with Chrome() as c:
        await c.call("Page.navigate", url=f"http://127.0.0.1:{port}/#{server.TOKEN}")
        await asyncio.sleep(2)

        # first run asks twice: a typo here would lock the vault for good
        g = 'document.querySelector'
        assert await c.js(g + '("#master-confirm").offsetParent !== null'), "first run has no confirm field"
        assert await c.js(g + '("#unlock-form button").textContent') == "Create vault"
        await c.js(g + f'("#master").value={MASTER!r};' + g + '("#master-confirm").value="typo";'
                   + g + '("#unlock-form").requestSubmit()')
        await asyncio.sleep(1)
        assert "match" in await c.js(g + '("#gate-error").textContent')
        assert not store.VAULT.exists(), "a mismatched confirm still created the vault"
        print("ok  first run needs the master password twice")

        # the gate must actually disappear: author display:grid beats UA [hidden]
        await c.js(g + f'("#master").value={MASTER!r};' + g + f'("#master-confirm").value={MASTER!r};'
                   + g + '("#unlock-form").requestSubmit()')
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

        # authenticator chooser: only the chosen flow's field shows
        q = 'document.querySelector'
        vis = q + '("%s").offsetParent !== null'
        await c.js('openVpnEditor(null)')
        assert await c.js(q + '("#vpn-form").totp_ui.value') == "none"
        assert not await c.js(vis % "#totp-input") and not await c.js(vis % "#totp-qr-zone")
        await c.js(q + '("#vpn-form [name=totp_ui][value=qr]").click()')
        assert await c.js(vis % "#totp-qr-zone") and not await c.js(vis % "#totp-input")
        await c.js(q + '("#vpn-form [name=totp_ui][value=paste]").click()')
        assert await c.js(vis % "#totp-input") and not await c.js(vis % "#totp-qr-zone")
        assert not await c.js(vis % "#totp-accounts")
        print("ok  authenticator chooser shows one flow at a time")

        # several accounts in a pasted export -> picker, then the current code
        await c.js(f'''{q}("#vpn-form").name.value = "picker";
                      {q}("#totp-input").value = {MIGRATION!r}; saveVpn()''')
        await asyncio.sleep(1)
        assert await c.js(q + '("#vpn-editor").open'), "a save that needs an account pick closed the form"
        assert await c.js(q + '("#totp-accounts").options.length') == 2
        assert "Vitraya" in await c.js(q + '("#totp-accounts").options[0].textContent')
        # changing the pasted text makes the old account list meaningless
        await c.js(q + '("#totp-input").value = "JBSWY3DPEHPK3PXP";'
                   + q + '("#totp-input").dispatchEvent(new Event("input", {bubbles: true}))')
        assert not await c.js(vis % "#totp-accounts"), "a stale account picker survived new input"
        await c.js(q + f'("#totp-input").value = {MIGRATION!r}; saveVpn()')
        await asyncio.sleep(1)
        await c.js(q + '("#totp-accounts").value = "0"; saveVpn()')
        await asyncio.sleep(1)
        shown = await c.js(q + '("#totp-now").textContent')
        assert re.search(r"\d{3} \d{3}", shown), shown
        assert await c.js(q + '("#vpn-editor").open'), "the form closed before the code could be compared"
        assert "JBSWY" not in await c.js('document.documentElement.outerHTML'), "key rendered into the page"
        assert await c.js(q + '("#totp-input").value') == "", "the pasted link is still in the field"
        # an edit made after the code is shown must not be thrown away by "Done"
        assert await c.js(q + '("#vpn-save").textContent') == "Done"
        await c.js(q + '("#vpn-form").username.value = "late-edit";'
                   + q + '("#vpn-form").username.dispatchEvent(new Event("input", {bubbles: true}))')
        assert await c.js(q + '("#vpn-save").textContent') == "Save"
        await c.js('saveVpn()')
        await asyncio.sleep(1)
        assert await c.js('vpns.find((v) => v.name === "picker").username') == "late-edit"
        # cancelling leaves nothing key-bearing in the closed form
        await c.js('openVpnEditor(null);' + q + '("#vpn-form [name=totp_ui][value=paste]").click();'
                   + q + '("#totp-input").value = "JBSWY3DPEHPK3PXP";' + q + '("#vpn-editor").close("cancel")')
        assert await c.js(q + '("#totp-input").value') == "", "a cancelled form kept the key in the page"
        print("ok  pasted export: account picker, then the current code, never the key")

        # a stored key shows as stored; dropping it asks first, then deletes it
        await c.js('openVpnEditor(vpns.find((v) => v.name === "picker"))')
        assert await c.js(q + '("#vpn-form").totp_ui.value') == "paste"
        assert "stored" in await c.js(q + '("#totp-note").textContent')
        await c.js(q + '("#vpn-form [name=totp_ui][value=ask]").click(); saveVpn(); 0')
        await asyncio.sleep(0.5)
        assert await c.js(q + '("#confirm-dlg").open'), "deleting a stored key did not ask first"
        assert "cannot recover" in await c.js(q + '("#confirm-body").textContent')
        await c.js(q + '("#confirm-yes").click()')
        await asyncio.sleep(1)
        assert await c.js('vpns.find((v) => v.name === "picker").totp_mode') == "ask"
        assert not await c.js(q + '("#vpn-editor").open')
        print("ok  switching away from a stored key confirms, then deletes it")

        # status needs_code -> the code box opens once and posts what was typed
        await c.js('''window._posts = []; window._f = window.fetch; window._st = "needs_code";
            window.fetch = (u, o) => {
              if (String(u).includes("/api/vpn/code")) { _posts.push(o.body); window._st = "connecting";
                return Promise.resolve(new Response(JSON.stringify({state:"connecting",log:[]}))); }
              if (String(u).includes("/api/vpn/status")) return Promise.resolve(new Response(JSON.stringify(
                {state:_st, profile_id:"v", name:"vee", pending_code:_st === "needs_code", log:[]})));
              return _f(u, o); }; pollVpn()''')
        await asyncio.sleep(1)
        assert await c.js(q + '("#vpn-code").open'), "needs_code did not open the code box"
        assert "vee" in await c.js(q + '("#vpn-code-title").textContent')
        await c.js(q + '("#vpn-code-input").value = "123456";' + q + '("#vpn-code-form").requestSubmit()')
        await asyncio.sleep(1)
        assert await c.js('JSON.parse(_posts[0]).code') == "123456"
        assert not await c.js(q + '("#vpn-code").open')
        await c.js('window.fetch = window._f; pollVpn()')
        await asyncio.sleep(0.5)
        print("ok  needs_code opens the code box and submits the typed code")

        # a screenshot of a QR code is decoded in the page, never uploaded
        import base64 as _b64
        png = _b64.b64encode(open("testdata/otpauth-qr.png", "rb").read()).decode()
        blob = f'new Blob([Uint8Array.from(atob("{png}"), (ch) => ch.charCodeAt(0))], {{type:"image/png"}})'
        URI = "otpauth://totp/Shelldeck:test?secret=JBSWY3DPEHPK3PXP&issuer=Shelldeck"
        assert await c.js(f'decodeQrImage({blob})') == URI
        err = await c.js('decodeQrImage(new Blob(["not an image"], {type:"text/plain"}))'
                         '.then(() => "decoded", (e) => e.message)')
        assert err == "no QR code found in that image", err
        # choosing the file fills the hidden field and says so; saving then stores the key
        await c.js('window._seen = []; window._f = window.fetch;'
                   'window.fetch = (u, o) => { _seen.push(String(u)); return _f(u, o); };'
                   'openVpnEditor(null);' + q + '("#vpn-form").name.value = "from-qr";'
                   + q + '("#vpn-form [name=totp_ui][value=qr]").click();'
                   f'readQrInto({blob})')
        assert await c.js(q + '("#totp-input").value') == URI
        assert "QR code read" in await c.js(q + '("#totp-qr-status").textContent')
        assert not await c.js(vis % "#totp-input"), "the decoded link is shown on screen"
        await c.js('readQrInto(new Blob(["x"], {type:"text/plain"}))')
        assert await c.js(q + '("#totp-input").value') == ""
        assert "no QR code found" in await c.js(q + '("#totp-qr-status").textContent')
        await c.js(f'readQrInto({blob})')
        await c.js('saveVpn()')
        await asyncio.sleep(1)
        assert re.search(r"\d{3} \d{3}", await c.js(q + '("#totp-now").textContent'))
        assert await c.js('vpns.find((v) => v.name === "from-qr").totp_mode') == "stored"
        sent = await c.js('window.fetch = window._f; _seen.join(" ")')
        assert "/api/vpns" in sent and all("/api/vpn" in u for u in sent.split()), sent
        await c.js(q + '("#vpn-editor").close("cancel")')
        print("ok  QR screenshot decodes in the browser and stores the key; a non-image fails cleanly")

        assert await c.js('document.querySelectorAll("#help section").length') >= 6
        print("ok  F1 manual is populated")

        # Esc on the host-key prompt is a rejection, sent once -- not a session left hanging
        await c.js('''window._hk = []; const fake = {send: (m) => _hk.push(JSON.parse(m))};
            askHostKey(fake, {name: "n", host: "h:22", algo: "ssh-ed25519", fingerprint: "SHA256:x"});
            document.querySelector("#hostkey").dispatchEvent(new Event("cancel"));
            document.querySelector("#hostkey").close();
            askHostKey(fake, {name: "n", host: "h:22", algo: "ssh-ed25519", fingerprint: "SHA256:x"});
            document.querySelector("#hk-accept").click()''')
        await asyncio.sleep(0.3)
        assert await c.js("JSON.stringify(_hk)") == '[{"accept":false},{"accept":true}]', \
            await c.js("JSON.stringify(_hk)")
        print("ok  Esc on the host-key prompt rejects; Trust sends one answer")

        # a rejected save must hand the form back with what was typed
        await c.js(g + '("#editor").returnValue = ""; openEditor(null);'
                   + g + '("#conn-form").name.value = "keep-me";'
                   + g + '("#conn-form").host.value = "10.9.9.9";'
                   + g + '("#conn-form").forwards.value = "not a rule";'
                   + g + '("#editor").close("save")')
        await asyncio.sleep(1)
        assert await c.js(g + '("#editor").open'), "a failed save closed the editor"
        assert await c.js(g + '("#conn-form").name.value') == "keep-me", "a failed save lost the input"
        await c.js(g + '("#editor").close("cancel")')
        print("ok  a failed save reopens the editor with the input intact")

        # "Show as text" must show the text, whichever view is up
        await c.js('openLogView("missing.log")')
        await asyncio.sleep(0.5)
        await c.js(g + '("#log-toggle").click()')
        assert await c.js(g + '("#log-view-text").offsetParent !== null'), "Show as text hid the text"
        await c.js(g + '("#log-view").close()')
        print("ok  Show as text keeps the text visible")

        # With no session open the pane area is a large void, so it has to say
        # what to do next -- and its buttons have to be wired, not decoration.
        assert await c.js('document.querySelector(".pane-empty") !== null'), \
            "nothing is shown in the pane area when no session is open"
        assert await c.js("""['#pe-new','#pe-import','#pe-help']
            .every(s => typeof document.querySelector(s).onclick === 'function')"""), \
            "an empty-state button has no handler"

        # A group heading heads the rows beneath it, so it must not be smaller
        # than its own children -- it used to be 11px against their 13.5px.
        size = json.loads(await c.js("""JSON.stringify({
            group: parseFloat(getComputedStyle(document.querySelector('.group-name')).fontSize),
            row: parseFloat(getComputedStyle(document.querySelector('.conn-name')).fontSize)})"""))
        assert size["group"] > size["row"], f"group heading is not bigger than its rows: {size}"
        print(f"ok  empty state guides the user; group {size['group']}px > row {size['row']}px")

        # N instances: the picker must offer 2..7 and never more, and opening
        # them must really produce that many panes in one tab.
        opts = json.loads(await c.js("""(async () => {
            const p = askInstances(conns[0].id);
            await new Promise(r => setTimeout(r, 300));
            const labels = [...document.querySelectorAll('#pick-list .pick-row')]
                             .map(b => b.textContent.trim());
            document.querySelector('#pick-cancel').click();
            await p;
            return JSON.stringify(labels);
        })()"""))
        assert opts == [f"{n} instances" for n in range(2, 8)], opts
        before = await c.js("tabs.length")
        await c.js(f'openInstances(conns[0].id, {MAX_INSTANCES})')
        await asyncio.sleep(2)
        assert await c.js("tabs.length") == before + 1, "instances should open one tab"
        assert await c.js("activeTab.panes.length") == MAX_INSTANCES
        # asking for more than the cap must clamp, not open 20 unreadable panes
        await c.js('openInstances(conns[0].id, 20)')
        await asyncio.sleep(2)
        assert await c.js("activeTab.panes.length") == MAX_INSTANCES, \
            "the instance count is not capped"
        print(f"ok  instances: picker offers 2-{MAX_INSTANCES}, count is capped")
        while await c.js("tabs.length"):        # back to a clean slate
            await c.js("closeTab(tabs[0])")
        await asyncio.sleep(0.5)

        # Alt shortcuts must fire, and must NOT fire inside a terminal: Alt+B and
        # Alt+F are readline word-movement, which a shell user needs more.
        async def alt(code):
            for t in ("keyDown", "keyUp"):
                await c.call("Input.dispatchKeyEvent", type=t, key="Alt", code=code,
                             modifiers=1, windowsVirtualKeyCode=ord(code[-1]))
            await asyncio.sleep(0.4)

        await c.js('document.querySelector(".conn").focus()')
        await alt("KeyN")
        assert await c.js('document.querySelector("#editor").open'), \
            "Alt+N did not open the connection editor"
        await c.js('document.querySelector("#editor").close("cancel")')
        await asyncio.sleep(0.3)

        await c.js('document.querySelector(".conn").focus()')
        await alt("KeyE")
        assert await c.js('document.querySelector("#editor").open'), \
            "Alt+E on a focused connection did not open the editor"
        assert await c.js('document.querySelector("#conn-form").id.value') != "", \
            "Alt+E opened a blank editor instead of editing the focused connection"
        await c.js('document.querySelector("#editor").close("cancel")')
        print("ok  Alt+N and Alt+E fire, Alt+E edits the focused row")

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

        # --- search matches more than the name --------------------------------
        await c.js("""conns = [
          {id:'s1', name:'app1', group:'PROD', host:'10.2.137.119', port:22, user:'ubuntu',
           auth:'password', jump:'', forwards:[], proto:'ssh'},
          {id:'s2', name:'db-main', group:'PROD', host:'10.1.157.138', port:22, user:'azureuser',
           auth:'password', jump:'', forwards:[], proto:'ssh'},
          {id:'s3', name:'console', group:'LAB', host:'', port:22, user:'',
           auth:'password', jump:'', forwards:[], proto:'serial', serial_device:'/dev/ttyUSB0'}];
          renderTree();""")
        async def found(q):
            return await c.js(f"""(() => {{ document.querySelector('#filter').value = {q!r};
                renderTree(); return document.querySelectorAll('.conn').length; }})()""")
        assert await found("10.1.157") == 1, "should find a host by IP fragment"
        assert await found("10.2.137.119") == 1, "should find a host by full IP"
        assert await found("azureuser") == 1, "should find a connection by username"
        assert await found("ttyUSB0") == 1, "should find a serial connection by device"
        assert await found("PROD") == 2, "should find connections by group"
        # name+host used to be concatenated with no separator, so this matched app1
        assert await found("app110") == 0, "must not match across the name/host boundary"
        assert await found("prod db") == 1, "multiple terms should narrow (AND)"
        assert await found("") == 3, "an empty query shows everything"
        print("ok  search matches name, IP, user, device and group; terms narrow")
        # put the real list back: later checks open a session from it
        await c.js("document.querySelector('#filter').value = ''")
        await c.js("(async () => { await loadTree(); return conns.length; })()")

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
