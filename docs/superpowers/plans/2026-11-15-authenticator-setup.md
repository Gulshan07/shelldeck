# Authenticator Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A VPN profile's authenticator code can be typed at connect time, or generated from a key supplied as a raw key, an `otpauth://` link, a Google Authenticator export link or a QR image.

**Architecture:** One server-side parser in `shelldeck/vpn.py` turns any pasted text into TOTP accounts; `/api/vpns` stores the chosen key in the vault and a non-secret `totp_mode` in `config.json`. The OpenVPN driver gains a wait-for-code path fed by `POST /api/vpn/code`. The browser decodes QR images with a vendored jsQR and submits the decoded text through the same paste path.

**Tech Stack:** Python 3.10+ stdlib (`hmac`, `base64`, `urllib.parse`), starlette, plain JS, vendored jsQR 1.4.0 (Apache-2.0).

**Spec:** `docs/superpowers/specs/2026-11-15-authenticator-setup-design.md`

## Global Constraints

- No new Python dependency, no npm, no build step. jsQR is one vendored file.
- A TOTP key, or pasted text containing one, never reaches `config.json`, a log line, `Vpn.log`, or a response body. The only derived value sent to the browser is the current code, once, in the save response.
- No outbound network request.
- Tests are plain scripts: `.venv/bin/python test_x.py`, run unpiped. New test functions in `test_p0.py` must be added to its `__main__` list.
- Commits: plain messages in the repo's existing style (imperative sentence). **No `Co-Authored-By`, no "Generated with" lines.**
- Work on branch `design/authenticator-setup`; `main` takes pull requests only.
- `totp_mode` values are exactly `none`, `ask`, `stored`.

## Review Focus

1. A pasted key with spaces, lower case or `=` padding, or an `otpauth://` link with a lower-case secret and a URL-encoded label → stored normalised (upper case, no spaces, no padding). Test in Task 1.
2. A Google export link whose `data` arrives URL-encoded (`%2B`, `%3D`) or with `+` already turned into spaces → still decodes. Test in Task 1.
3. A code typed as `123 456` in the code box → accepted with the space stripped. Test in Task 3.
4. An old profile (no `totp_mode`, key in the vault) edited and saved without touching the authenticator section → key kept, mode `stored`. Test in Task 2.
5. Disconnecting while Shelldeck is waiting for a code → clean `disconnected`, no hung task, a later connect works. Test in Task 3.

---

### Task 1: TOTP input parser and hash algorithms

**Files:**
- Modify: `shelldeck/vpn.py` (`totp`, new `parse_totp_input`, new `code_for`)
- Test: `test_p0.py`

**Interfaces:**
- Produces:
  - `totp(secret_b32: str, when: float | None = None, digits: int = 6, period: int = 30, algorithm: str = "SHA1") -> str` — `algorithm` in `SHA1`, `SHA256`, `SHA512`.
  - `parse_totp_input(text: str) -> list[dict]` — each dict `{"label": str, "issuer": str, "secret": str, "digits": int, "period": int, "algorithm": str}`; `secret` is base32, upper case, no spaces, no `=`. Raises `ValueError` with a user-facing message.
  - `code_for(secret: dict, when: float | None = None) -> str` — current code from a vault entry, reading `totp_secret` and optional `totp_digits`, `totp_period`, `totp_algorithm`; `""` when there is no `totp_secret`.

- [ ] **Step 1: Write the failing tests** in `test_p0.py`

```python
MIGRATION = ("otpauth-migration://offline?data=CigKCkhlbGxvId6tvu8SC2d1bHNoYW5AdnBuGgdWaXRyYXlhIAEoATACCj4KIDEy"
             "MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyEgtvcHNAZXhhbXBsZRoHRXhhbXBsZSACKAIwAgojCg5jb3VudGVyLXNl"
             "Y3JldBIDb2xkGgZMZWdhY3kgASgBMAEQARgBIAA%3D")

def test_totp_algorithms():
    from shelldeck.vpn import totp
    import base64
    b32 = lambda raw: base64.b32encode(raw).decode()
    assert totp(b32(b"12345678901234567890123456789012"), when=59, digits=8, algorithm="SHA256") == "46119246"
    assert totp(b32(b"1234567890123456789012345678901234567890123456789012345678901234"),
                when=59, digits=8, algorithm="SHA512") == "90693936"

def test_parse_totp_input():
    from shelldeck.vpn import parse_totp_input, code_for, totp
    [a] = parse_totp_input(" jbsw y3dp ehpk 3pxp== ")
    assert a == {"label": "", "issuer": "", "secret": "JBSWY3DPEHPK3PXP",
                 "digits": 6, "period": 30, "algorithm": "SHA1"}
    [a] = parse_totp_input("otpauth://totp/Vitraya%3Agulshan%40vpn?secret=jbswy3dpehpk3pxp"
                           "&issuer=Vitraya&digits=8&period=60&algorithm=SHA256")
    assert a == {"label": "Vitraya:gulshan@vpn", "issuer": "Vitraya", "secret": "JBSWY3DPEHPK3PXP",
                 "digits": 8, "period": 60, "algorithm": "SHA256"}
    # Google export: two TOTP accounts; the HOTP entry is dropped
    accts = parse_totp_input(MIGRATION)
    assert [(x["label"], x["issuer"], x["digits"], x["algorithm"]) for x in accts] == [
        ("gulshan@vpn", "Vitraya", 6, "SHA1"), ("ops@example", "Example", 8, "SHA256")]
    assert accts[0]["secret"] == "JBSWY3DPEHPK3PXP" and accts[0]["period"] == 30
    # the same link after a '+' -> ' ' mangling and with the data left unencoded
    assert parse_totp_input(MIGRATION.replace("%3D", "=")) == accts
    for bad, msg in [("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "HOTP"),
                     ("hello world!", "not a TOTP key"),
                     ("otpauth://totp/x?issuer=nokey", "not a TOTP key"),
                     ("", "not a TOTP key")]:
        try:
            parse_totp_input(bad); raise AssertionError(bad)
        except ValueError as e:
            assert msg in str(e), (bad, e)
    assert code_for({"totp_secret": "JBSWY3DPEHPK3PXP"}, when=59) == totp("JBSWY3DPEHPK3PXP", when=59)
    assert code_for({"totp_secret": "JBSWY3DPEHPK3PXP", "totp_digits": 8, "totp_period": 60,
                     "totp_algorithm": "SHA256"}, when=59) == totp(
                         "JBSWY3DPEHPK3PXP", when=59, digits=8, period=60, algorithm="SHA256")
    assert code_for({}) == ""
```

- [ ] **Step 2: Run** `.venv/bin/python test_p0.py` — expected: `ImportError` / `TypeError` on the new names.

- [ ] **Step 3: Implement** in `shelldeck/vpn.py`.
  - Error messages, exact: `"counter-based (HOTP) codes are not supported"` and `"not a TOTP key, otpauth:// link or Google Authenticator export link"`. A migration link containing only HOTP entries raises the HOTP message.
  - Bare key: strip whitespace and `=`, upper-case, must be valid base32 of at least 10 characters, else the "not a TOTP key" error.
  - Migration payload: `data` is base64 (after `unquote`; restore spaces to `+`). Protobuf, decoded by a small varint/length-delimited reader — no dependency. Field map:

    ```
    MigrationPayload: 1 = repeated OtpParameters (length-delimited)
    OtpParameters:    1 secret (raw bytes -> base32)   2 name (-> label)   3 issuer
                      4 algorithm  1=SHA1 2=SHA256 3=SHA512 (0 -> SHA1)
                      5 digits     1=6    2=8               (0 -> 6)
                      6 type       1=HOTP 2=TOTP            (keep TOTP only)
    period is always 30. Unknown fields are skipped by wire type.
    ```
  - `answer_auth` in `_manage` switches from `totp(secret["totp_secret"])` to `code_for(secret)`.

- [ ] **Step 4: Run** `.venv/bin/python test_p0.py` and `.venv/bin/python test_vpn.py` — expected: all `ok`, no traceback.

- [ ] **Step 5: Commit** — `git commit -am "Parse otpauth and Google Authenticator export links into TOTP keys"`

---

### Task 2: Saving a profile's authenticator setting

**Files:**
- Modify: `shelldeck/server.py` (`vpns` handler, ~line 465-495), `shelldeck/vpn.py` (new `totp_mode_of`)
- Test: `test_live.py` (VPN storage block, ~line 397)

**Interfaces:**
- Consumes: `parse_totp_input`, `code_for` from Task 1.
- Produces:
  - `vpn.totp_mode_of(profile: dict, secret: dict) -> str` — `profile["totp_mode"]` if set, else `"stored"` when `secret.get("totp_secret")`, else `"none"`.
  - `GET /api/vpns` — each profile carries `totp_mode` (via `totp_mode_of`).
  - `POST /api/vpns` body fields: `totp_mode` (`none`|`ask`|`stored`, optional), `totp_input` (str, optional), `totp_account` (int, optional). The old `totp_secret` body field is removed; a bare key goes in `totp_input`.
    - `totp_input` present → parse; mode becomes `stored`. Several accounts and no `totp_account` → **409** `{"error": "choose an account", "accounts": [{"index": 0, "label": "...", "issuer": "..."}, ...]}`, nothing saved. Parse error or out-of-range index → **400** `{"error": <message>}`, nothing saved.
    - mode `stored`, no `totp_input`, no key already in the vault → **400** `{"error": "no authenticator key given"}`.
    - mode `none` or `ask` → `totp_secret`, `totp_digits`, `totp_period`, `totp_algorithm` are removed from the vault entry.
    - `totp_mode` absent and no `totp_input` → keep whatever `totp_mode_of` says today.
    - Vault stores `totp_digits` / `totp_period` / `totp_algorithm` only when they differ from 6 / 30 / `SHA1`.
    - Response: the profile, `detected`, `totp_mode`, and `totp_now` (current code) **only** when this request stored a new key.

- [ ] **Step 1: Write the failing tests.** In `test_live.py`, change the existing VPN save to send `"totp_input": "JBSWY3DPEHPK3PXP"` instead of `totp_secret`, and add after it (reuse `http`, `MIGRATION` copied from `test_p0.py`):

```python
        saved = r.json()
        assert saved["totp_mode"] == "stored" and len(saved["totp_now"]) == 6
        vid = saved["id"]
        base = {"id": vid, "name": "Vitraya", "username": "gulshan", "dialect": "auto"}

        r = await http.post("/api/vpns", json=base)                      # untouched edit
        assert r.json()["totp_mode"] == "stored" and "totp_now" not in r.json()
        assert server.vault.get("vpn:" + vid)["totp_secret"] == "JBSWY3DPEHPK3PXP"

        r = await http.post("/api/vpns", json={**base, "totp_input": MIGRATION})
        assert r.status_code == 409, r.text
        assert r.json()["accounts"] == [
            {"index": 0, "label": "gulshan@vpn", "issuer": "Vitraya"},
            {"index": 1, "label": "ops@example", "issuer": "Example"}]
        assert "JBSWY" not in r.text and "GEZDG" not in r.text, "a key travelled back to the browser"

        r = await http.post("/api/vpns", json={**base, "totp_input": MIGRATION, "totp_account": 1})
        kept = server.vault.get("vpn:" + vid)
        assert r.status_code == 200 and len(r.json()["totp_now"]) == 8
        assert (kept["totp_digits"], kept["totp_algorithm"]) == (8, "SHA256") and "totp_period" not in kept

        for bad in ({"totp_input": "hello world!"}, {"totp_input": MIGRATION, "totp_account": 7}):
            assert (await http.post("/api/vpns", json={**base, **bad})).status_code == 400

        r = await http.post("/api/vpns", json={**base, "totp_mode": "ask"})
        assert r.json()["totp_mode"] == "ask"
        assert not any(k.startswith("totp_") for k in server.vault.get("vpn:" + vid))
        assert (await http.post("/api/vpns", json={**base, "totp_mode": "stored"})).status_code == 400
        assert [v["totp_mode"] for v in (await http.get("/api/vpns")).json() if v["id"] == vid] == ["ask"]
        blob = store.CONFIG.read_bytes()
        assert b"otpauth" not in blob and b"JBSWY" not in blob and b"GEZDG" not in blob
        print("ok  authenticator key, link and account picker keep the key out of config and responses")
```

  Add a legacy check to `test_p0.py`:

```python
def test_totp_mode_default():
    from shelldeck.vpn import totp_mode_of
    assert totp_mode_of({}, {"totp_secret": "JBSWY3DPEHPK3PXP"}) == "stored"
    assert totp_mode_of({}, {}) == "none"
    assert totp_mode_of({"totp_mode": "ask"}, {"totp_secret": "X"}) == "ask"
```

- [ ] **Step 2: Run** `.venv/bin/python test_live.py` and `test_p0.py` — expected: fail on `totp_mode` / `totp_mode_of`.
- [ ] **Step 3: Implement** `totp_mode_of` and the handler rules above. Later lines in `test_live.py` that read `kept["totp_secret"] == "JBSWY3DPEHPK3PXP"` (~line 418) must be moved above the new block or updated to the state the new block leaves.
- [ ] **Step 4: Run** `.venv/bin/python test_live.py`, `test_p0.py` — expected: all `ok`.
- [ ] **Step 5: Commit** — `git commit -am "Store an authenticator mode per VPN profile and accept pasted links"`

---

### Task 3: Asking for the code at connect time

**Files:**
- Modify: `shelldeck/vpn.py` (`Vpn`, `_manage`, `_drain_output`), `shelldeck/server.py` (new route), `testbin/openvpn` (new mode)
- Test: `test_vpn.py`

**Interfaces:**
- Consumes: `totp_mode_of`, `code_for`.
- Produces:
  - `Vpn.state` may be `"needs_code"` (before the tunnel is first up only). `Vpn.pending_code: bool`. `Vpn.status()` adds `"pending_code"`.
  - `Vpn.submit_code(code: str) -> None` — strips spaces; raises `VpnError("enter the 6 to 8 digit code")` unless `^\d{6,8}$`; raises `VpnError("not waiting for a code")` when nothing is pending.
  - `POST /api/vpn/code` body `{"code": "123456"}` → `vpn.status()` JSON, or 400 `{"error": ...}` on `VpnError`.
  - Module constants: `CODE_WAIT = 300`; `REJECTED = "authentication rejected"`; `REJECTED_ASK = REJECTED + " — check the password and the code you typed"`; `REJECTED_STORED = REJECTED + " — if the password is right, check this computer's clock"`.
  - `testbin/openvpn`: `FAKE_VPN_MODE=reauth` — behaves as `ok`, then 0.5 s after `CONNECTED` sends a second `>PASSWORD:Need 'Auth' username/password` line, validates the next `password` line the same way, prints `REAUTH OK` or `REAUTH FAILED`, and keeps running until `signal SIGTERM`.

- Behaviour to implement in `_manage`:
  - Mode from `totp_mode_of(profile, secret)`. `stored` and `none` behave as today.
  - `ask`: on `>PASSWORD:Need 'Auth'` and on a `CRV1` challenge, wait for `submit_code` instead of answering. While waiting: if `state != "connected"` set `state = "needs_code"`, `detail = "waiting for authenticator code"`; always set `pending_code = True`. After the code arrives: `pending_code = False`, state back to `connecting` if it was `needs_code`, then answer in the profile's dialect (or `CRV1::<state>::<code>` for a challenge).
  - The 90 s connect deadline is extended by the time spent waiting. Waiting in `needs_code` longer than `CODE_WAIT` → `failed`, detail `"no authenticator code entered"`. On a connected tunnel the wait has no limit.
  - `up()` also refuses while `state == "needs_code"`. `down()` cancels a pending wait and clears `pending_code`.
  - Rejection: the `>PASSWORD:Verification Failed: 'Auth'` branch without a challenge, **and** a line containing `AUTH_FAILED` in `_drain_output`, set `state = "failed"` with `REJECTED_ASK` / `REJECTED_STORED` / `REJECTED` by mode. (Real openvpn reports `AUTH: Received control message: AUTH_FAILED,...` on stdout and exits; today that surfaces as a bare `GET_CONFIG`.)
  - Codes are never written to `self.log`.

- [ ] **Step 1: Write the failing tests** — append to `test_vpn.py`'s `main()`. Add a helper next to `run`:

```python
async def start(mode, ovpn, secret, prof_extra):
    os.environ.update(FAKE_VPN_MODE=mode, FAKE_VPN_PASSWORD=PW, FAKE_VPN_SEED=SEED)
    v = Vpn()
    await v.up({"id": "p1", "name": "Vitraya", "username": "gulshan", "dialect": "auto", **prof_extra}, secret)
    return v

async def until(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end and not cond():
        await asyncio.sleep(0.1)
    assert cond(), "timed out waiting"
```

```python
    ASK = {"totp_mode": "ask"}
    nokey = {"ovpn": OVPN_SC, "password": PW}

    v = await start("ok", OVPN_SC, nokey, ASK)
    await until(lambda: v.state == "needs_code")
    assert v.status()["pending_code"] is True
    for bad in ("12345", "abcdef", ""):
        try: v.submit_code(bad); raise AssertionError(bad)
        except VpnError: pass
    c = totp(SEED); v.submit_code(c[:3] + " " + c[3:])            # typed with a space
    await until(lambda: v.state == "connected")
    assert v.status()["pending_code"] is False
    assert not any(c in line for line in v.log), "the code was logged"
    try: v.submit_code(c); raise AssertionError("accepted a code nobody asked for")
    except VpnError: pass
    await v.down()
    print("ok  ask mode: waits for a typed code, then connects")

    v = await start("ok", OVPN_SC, nokey, ASK)
    await until(lambda: v.state == "needs_code")
    v.submit_code("000000")
    await until(lambda: v.state == "failed")
    assert v.detail == vpn_mod.REJECTED_ASK, v.detail
    print("ok  ask mode: a wrong code fails with a clear reason")

    v = await start("ok", OVPN_SC, nokey, ASK)
    await until(lambda: v.state == "needs_code")
    await v.down()
    assert v.state == "disconnected" and v.status()["pending_code"] is False
    v = await start("ok", OVPN_SC, nokey, ASK)                     # a later connect still works
    await until(lambda: v.state == "needs_code"); v.submit_code(totp(SEED))
    await until(lambda: v.state == "connected"); await v.down()
    print("ok  ask mode: disconnecting while waiting leaves nothing hung")

    vpn_mod.CONNECT_TIMEOUT, vpn_mod.CODE_WAIT = 2, 4
    v = await start("ok", OVPN_SC, nokey, ASK)
    await until(lambda: v.state == "needs_code")
    await asyncio.sleep(3)                                          # past the connect deadline
    assert v.state == "needs_code", (v.state, v.detail)
    await until(lambda: v.state == "failed", timeout=5)
    assert v.detail == "no authenticator code entered", v.detail
    vpn_mod.CONNECT_TIMEOUT, vpn_mod.CODE_WAIT = 90, 300
    print("ok  ask mode: the connect deadline pauses, the code wait has its own limit")

    v = await start("reauth", OVPN_SC, nokey, ASK)
    await until(lambda: v.state == "needs_code"); v.submit_code(totp(SEED))
    await until(lambda: v.state == "connected" and v.pending_code)
    assert v.state == "connected" and v.ip == "10.8.0.7"
    v.submit_code(totp(SEED))
    await until(lambda: any("REAUTH OK" in l for l in v.log))
    assert v.state == "connected" and not v.pending_code
    await v.down()
    print("ok  ask mode: re-auth on a live tunnel asks again without dropping")

    v = await start("ok", OVPN_SC, {"ovpn": OVPN_SC, "password": PW, "totp_secret": "GEZDGNBVGY3TQOJQ"}, {})
    await until(lambda: v.state == "failed")
    assert v.detail == vpn_mod.REJECTED_STORED, v.detail
    print("ok  stored key rejected: the reason points at the clock")
```

  with `import shelldeck.vpn as vpn_mod` at the top. `CONNECT_TIMEOUT` and `CODE_WAIT` must be read from the module at use time so the test can shorten them.

- [ ] **Step 2: Run** `.venv/bin/python test_vpn.py` — expected: the existing checks pass, the first new one fails (`needs_code` never reached).
- [ ] **Step 3: Implement** the `reauth` mode in `testbin/openvpn`, then the driver changes and the route (`Route("/api/vpn/code", vpn_code, methods=["POST"])`, decorated with `@api` like its neighbours).
- [ ] **Step 4: Run** `.venv/bin/python test_vpn.py` then `test_live.py` — expected: all `ok`.
- [ ] **Step 5: Commit** — `git commit -am "Ask for the authenticator code at connect time when no key is stored"`

---

### Task 4: The profile form and the code box

**Files:**
- Modify: `shelldeck/static/index.html` (`#vpn-editor`, new `#vpn-code` dialog, F1 manual VPN section), `shelldeck/static/app.js` (VPN section, ~lines 609-702), `shelldeck/static/style.css`
- Test: `test_ui.py`

**Interfaces:**
- Consumes: `POST /api/vpns` (Task 2), `GET /api/vpn/status` with `needs_code` / `pending_code`, `POST /api/vpn/code`, `POST /api/vpn/down` (Task 3).
- Produces (element ids and globals later tasks and tests use):
  - Radio group `name="totp_ui"` in `#vpn-form`, values `none`, `ask`, `paste`, `qr`.
  - `#totp-input` — text field (`type="password"`, `autocomplete="off"`) shown for `paste`; `#totp-qr-zone` — block shown for `qr` (filled in Task 5); `#totp-accounts` — `<select>` shown only after a 409; `#totp-now` — output line.
  - `#vpn-code` dialog with form `#vpn-code-form`, input `#vpn-code-input` (`inputmode="numeric"`, `autocomplete="one-time-code"`), a submit button and a cancel button.
  - `async function saveVpn()` — builds the body and posts it; used by Task 5 and by tests.

- Behaviour:
  - Opening the editor selects the radio from the profile's `totp_mode` (`stored` → `paste`, with the note "A key is stored. Leave this empty to keep it."); a new profile starts on `none`.
  - Body sent: `none` → `totp_mode: "none"`; `ask` → `totp_mode: "ask"`; `paste`/`qr` → `totp_mode: "stored"` plus `totp_input` when the field is non-empty, plus `totp_account` when the picker is showing.
  - Changing a profile whose `totp_mode` is `stored` to `none` or `ask` asks first: "The stored authenticator key will be deleted. Shelldeck cannot recover it. Continue?" (use the app's existing confirm helper).
  - Save no longer closes the dialog blindly. The Save button calls `saveVpn()`: a 409 fills `#totp-accounts` with `issuer — label` options and keeps the dialog open; a 400 shows the error by toast and keeps it open; success with `totp_now` shows `Current code: 123 456 — it should match your phone.` in `#totp-now` and turns Save into "Done"; success without `totp_now` closes.
  - `pollVpn`: when `vpnState.state === "needs_code" || vpnState.pending_code` and the code dialog is not open and was not dismissed for this request, open `#vpn-code` titled "Enter authenticator code for <name>", with the extra line "The VPN server is asking for a new code. Your connection stays up." when `pending_code` and state is `connected`. `needs_code` counts as busy for the 1.5 s poll interval and shows the connect button as "disconnect".
  - Submitting posts `{code}` to `/api/vpn/code`; a 400 shows its message inside the dialog and keeps it open. Cancel while `needs_code` posts `/api/vpn/down`; cancel while `pending_code` only closes, and the dialog does not reopen until `pending_code` has gone false once.
  - `resetForm` already clears hidden inputs; make sure `#totp-accounts`, `#totp-now` and the radio return to their initial state on every open.
  - F1 manual, VPN section: three sentences describing the four choices.

- [ ] **Step 1: Write the failing tests** — in `test_ui.py` after the "vpn form clears its hidden id too" check. The fake server already has profile `v`; give the page a `fetch` spy rather than a real openvpn:

```python
        # authenticator chooser: only the chosen flow's field shows
        await c.js('openVpnEditor(null)')
        vis = 'document.querySelector("%s").offsetParent !== null'
        assert await c.js('document.querySelector("#vpn-form").totp_ui.value') == "none"
        assert not await c.js(vis % "#totp-input")
        await c.js('document.querySelector("#vpn-form [name=totp_ui][value=paste]").click()')
        assert await c.js(vis % "#totp-input") and not await c.js(vis % "#totp-accounts")
        print("ok  authenticator chooser shows one flow at a time")

        # several accounts in a pasted export -> picker, then the current code
        await c.js(f'''document.querySelector("#vpn-form").name.value = "picker";
                      document.querySelector("#totp-input").value = {MIGRATION!r}; saveVpn()''')
        await asyncio.sleep(1)
        assert await c.js('document.querySelector("#vpn-editor").open')
        assert await c.js('document.querySelector("#totp-accounts").options.length') == 2
        await c.js('document.querySelector("#totp-accounts").value = "0"; saveVpn()')
        await asyncio.sleep(1)
        shown = await c.js('document.querySelector("#totp-now").textContent')
        assert re.search(r"\d{3} \d{3}", shown), shown
        assert "JBSWY" not in await c.js('document.documentElement.outerHTML'), "key rendered into the page"
        await c.js('document.querySelector("#vpn-editor").close()')
        print("ok  pasted export: account picker, then the current code, never the key")

        # status needs_code -> the code box opens once and posts what was typed
        await c.js('''window._posts = []; const _f = window.fetch;
            window.fetch = (u, o) => { if (String(u).includes("/api/vpn/code")) { _posts.push(o.body);
                return Promise.resolve(new Response(JSON.stringify({state:"connecting",log:[]}))); }
              if (String(u).includes("/api/vpn/status")) return Promise.resolve(new Response(JSON.stringify(
                {state:"needs_code", profile_id:"v", name:"vee", pending_code:true, log:[]})));
              return _f(u, o); }; pollVpn()''')
        await asyncio.sleep(1)
        assert await c.js('document.querySelector("#vpn-code").open')
        await c.js('document.querySelector("#vpn-code-input").value = "123456";'
                   'document.querySelector("#vpn-code-form").requestSubmit()')
        await asyncio.sleep(1)
        assert await c.js('JSON.parse(_posts[0]).code') == "123456"
        await c.js('window.fetch = _f')
        print("ok  needs_code opens the code box and submits the typed code")
```

  (`MIGRATION` copied from `test_p0.py`; add `import re` if missing. Restore `window.fetch` by keeping `_f` on `window`.)

- [ ] **Step 2: Run** `.venv/bin/python test_ui.py` — expected: fails at the chooser check.
- [ ] **Step 3: Implement** the markup, `saveVpn`, the poll hook and the styles. Match the existing dialog and note styles; no new colours.
- [ ] **Step 4: Run** `.venv/bin/python test_ui.py` — expected: all `ok`. Then start the app (`.venv/bin/python -m shelldeck`) and screenshot the VPN form on each of the four choices and the code box in dark and light theme with headless Chrome; check nothing overflows the dialog.
- [ ] **Step 5: Commit** — `git commit -am "VPN form: choose how the authenticator code is supplied"`

---

### Task 5: Reading a QR code image

**Files:**
- Create: `shelldeck/static/vendor/jsQR.js` (from `https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js`, unmodified), `testdata/otpauth-qr.png`
- Modify: `shelldeck/static/index.html` (script tag, `#totp-qr-zone`), `shelldeck/static/app.js`, `README.md` (Credits: jsQR, Apache-2.0, vendored)
- Test: `test_ui.py`

**Interfaces:**
- Consumes: `#totp-qr-zone`, `#totp-input`, `saveVpn()` from Task 4.
- Produces: `async function decodeQrImage(blob) -> string` — the QR's text; rejects with `Error("no QR code found in that image")`, also for a blob that is not an image.

- Behaviour:
  - `#totp-qr-zone` holds a file input (`accept="image/*"`) and the line "Choose, drop or paste a screenshot of the QR code." Dropping an image on the zone, or pasting one from the clipboard anywhere in `#vpn-editor` while the `qr` choice is selected, feeds `decodeQrImage`.
  - Decoding: `createImageBitmap` → canvas → `jsQR(data, w, h)`. Scale the image down so its longest side is at most 1600 px before decoding. If nothing is found, retry once at half size.
  - On success: put the text in `#totp-input` (which stays hidden for `qr`), show "QR code read." in the zone; Save then follows the Task 4 path, including the account picker. On failure: show the error in the zone, leave `#totp-input` empty.
  - The image is never sent to the server.

- [ ] **Step 1: Make the fixture.** In a throwaway venv outside the repo: `pip install "qrcode[pil]"`, then write a PNG encoding `otpauth://totp/Shelldeck:test?secret=JBSWY3DPEHPK3PXP&issuer=Shelldeck`, pasted onto a 900×700 white canvas at offset (200, 150) so the test image looks like a screenshot. Save as `testdata/otpauth-qr.png`. `qrcode` is not added to the project.
- [ ] **Step 2: Write the failing test** in `test_ui.py`:

```python
        import base64 as _b64
        png = _b64.b64encode(open("testdata/otpauth-qr.png", "rb").read()).decode()
        blob = f'new Blob([Uint8Array.from(atob("{png}"), ch => ch.charCodeAt(0))], {{type:"image/png"}})'
        assert await c.js(f'decodeQrImage({blob})', await_promise=True) == \
            "otpauth://totp/Shelldeck:test?secret=JBSWY3DPEHPK3PXP&issuer=Shelldeck"
        err = await c.js('decodeQrImage(new Blob(["not an image"], {type:"text/plain"}))'
                         '.then(() => "decoded", (e) => e.message)', await_promise=True)
        assert err == "no QR code found in that image", err
        print("ok  QR screenshot decodes in the browser; a non-image fails cleanly")
```

  If `c.js` has no promise-awaiting option, add `await_promise=False` to it, passing `awaitPromise` to `Runtime.evaluate`.

- [ ] **Step 3: Run** `.venv/bin/python test_ui.py` — expected: `decodeQrImage is not defined`.
- [ ] **Step 4: Implement.** Vendor the file, add `<script src="vendor/jsQR.js">` next to the xterm tags, write `decodeQrImage` and the zone handlers. Check `pyproject.toml` package-data (`static/vendor/*`) and `shelldeck.spec` already pick the new file up; they should.
- [ ] **Step 5: Run** `.venv/bin/python test_ui.py` — expected: all `ok`.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "Read an authenticator QR code from a screenshot"`

---

### Task 6: Documentation and full run

**Files:**
- Modify: `README.md` (VPN section: the four choices, the Google Authenticator export steps, the Microsoft Authenticator note), `CHANGELOG.md` (new `## Unreleased` section above v0.1.0), `PLAN.md` (mark done)

- [ ] **Step 1: Write the docs.** README wording for the two real cases, exact:
  - Google Authenticator: "Menu → Transfer accounts → Export accounts, take a screenshot of the QR code, and give it to Shelldeck under *Read a QR code image*."
  - Microsoft Authenticator: "It never reveals the key. Choose *Ask me each time I connect*, or ask your VPN admin to re-issue the QR code and scan it into Shelldeck as well as your phone."
- [ ] **Step 2: Run all seven suites**, unpiped, one at a time: `test_p0.py`, `test_e2e.py`, `test_live.py`, `test_vpn.py`, `test_raw.py`, `test_sudokey.py`, `test_ui.py` — expected: every line `ok`, exit 0.
- [ ] **Step 3: Commit** — `git commit -am "Document authenticator setup"`
