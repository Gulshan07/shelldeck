# EazyConnector

Ásbrú-style connection manager that runs anywhere Python runs. Local web server,
browser UI, encrypted vault. See [PLAN.md](PLAN.md) for the roadmap.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/eazyconnector
```

It prints a URL and opens your browser. First launch asks you to create a master
password; that password is the only thing that decrypts your secrets.

## Where things live

```
~/.eazyconnector/     (0700)
  config.json  (0600)  hosts, ports, groups — no secrets, safe to sync/diff
  vault.enc    (0600)  AES-256-GCM: passwords, private keys, passphrases
  known_hosts  (0600)  pinned SSH host keys
  url          (0600)  current session URL, incl. token
```

## Security notes

- Binds `127.0.0.1` on an ephemeral port. There is no flag to bind elsewhere.
- The session token is in the URL **fragment**, so the browser never sends it to
  the server and it stays out of logs. It is never passed on the command line
  (`/proc/<pid>/cmdline` is world-readable on a shared machine).
- Every request checks `Origin`; the WebSocket takes its token as the first
  message. Blocks CSRF and DNS rebinding from other pages in your browser.
- Secrets never reach the browser. The UI asks for "connect to host X"; the
  server does the authentication.
- Vault: `scrypt(n=2^17)` → AES-256-GCM. Auto-locks after 15 minutes idle.
- Unknown SSH host keys prompt with a fingerprint before trusting, at every hop
  of a jump-host chain. Verification is never disabled.

## Status: P1 + P2

Working: vault, connection tree, SSH terminals in tabs, split panes, jump
hosts / chained connections, port forwarding (L/R/D), SFTP browse with
upload and download, TOFU host-key pinning, idle auto-lock.

One-click OpenVPN with automatic password + TOTP is in: add a profile, press
connect. The second factor dialect is auto-detected from the `.ovpn`
(`static-challenge` → SCRV1, otherwise appended), and a dynamic `CRV1`
re-challenge is answered with a fresh code. The profile, private key included,
is stored encrypted in the vault and written to `~/.eazyconnector/run/` at
`0600` only while the tunnel is up, then deleted.

openvpn needs root: store a sudo password in the profile, or set
`EAZY_OPENVPN_NO_SUDO=1` if your openvpn already has the privileges it needs.

Import from `~/.ssh/config` and Ásbrú (`asbru.yml`) is in — the ↓ button in the
sidebar previews what will be created (grouped, jump links resolved, key files
noted) before you commit. Structure, hosts and key-file paths only; saved
passwords are never read. Duplicates (same host, user, port) are skipped, so
re-importing is safe.

A key file owned by root (unreadable by the app) is handled at connect time:
EazyConnector asks for your sudo password once, reads the key with `sudo cat`,
caches it in the vault, and never asks again. The sudo password is used
immediately and never stored — the alternative is `sudo chown` on the file.

The master password can be changed in place (button by Lock vault): the vault
is re-encrypted under a new password with a fresh salt, open sessions keep
running, and the old password stops working.

Session logging is opt-in per connection (a checkbox in the editor) and
**encrypted at rest** with your vault — a terminal log can contain a sudo
password or token, so it is never written in the clear. The 📜 button lists,
views (decrypted in memory) and deletes logs; they live in
`~/.eazyconnector/logs/*.eclog`, capped at 50 MB per session.

Per-connection **Advanced** options (in the editor): a local command run
before connecting, a command run on the server right after login, a local
command after disconnecting, and the keepalive interval. Terminal **theme,
font size and family** are set via the gear button and saved per browser.

**Share a setup with your team:** Import → *Export…* writes a JSON file with
your connections, groups, jump links and port-forward rules and **no** secrets
(no passwords, keys, passphrases, TOTP secrets, VPN profiles or macro bodies —
only key-file paths, so the recipient knows which key each host needs). They
import it via Import → *Shared file*: jump hosts are re-linked by name against
their own ids, duplicates are skipped, and re-importing is idempotent.

Clusters: open several servers as split panes in one tab, click **⇄ broadcast**,
and your typing goes to every terminal at once — run one command across a fleet.

Recording playback (replay a session log at real speed), macros (scripted
send/expect, run per-terminal or across a broadcast cluster), and Telnet +
Serial console access are in. Serial needs `pip install pyserial-asyncio`.

Wake-on-LAN skipped — it only wakes physical LAN machines, not cloud instances.

### Using it

- Click a connection to open it in a new tab; **Ctrl-click** to split it into
  the current tab beside what is already there.
- The folder icon on a row opens an SFTP pane (Ctrl-click to split it too).
- Ctrl-Shift-PageUp / PageDown switch tabs.
- **F1** (or the `?` button) opens the built-in manual: shortcuts, forwarding
  syntax, jump hosts, and what the security guarantees actually are.
- In an SFTP pane, type in the filter box to narrow the current folder; press
  **Enter** to search the server recursively below it. Sizes are shown for both.
- Port forwarding rules go in the connection editor, one per line:
  `L 8080:localhost:80`, `R 9090:localhost:22`, `D 1080`. They start with the
  session and stop when its pane closes. Local and SOCKS listeners bind
  `127.0.0.1` only — on a shared machine `0.0.0.0` would hand the tunnel to
  every other user on the box.

## Tests

```bash
.venv/bin/python test_p0.py    # vault crypto, file modes, origin guard
.venv/bin/python test_e2e.py   # full stack against an in-process sshd
.venv/bin/python test_live.py  # real uvicorn + real WebSocket handshake
.venv/bin/python test_vpn.py   # full OpenVPN management conversation (fake openvpn, no root)
.venv/bin/python test_ui.py    # browser-level checks over Chrome DevTools Protocol (skips without Chrome)
```

`test_e2e.py` uses Starlette's TestClient, which implements WebSockets
in-process — it cannot catch server-level transport problems. `test_live.py`
exists for those.
