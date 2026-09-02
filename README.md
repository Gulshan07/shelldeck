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

## Status: P1

Working: vault, connection tree, SSH terminals in tabs, split panes, jump
hosts / chained connections, port forwarding (L/R/D), SFTP browse with
upload and download, TOFU host-key pinning, idle auto-lock.

Not yet: ssh_config / PuTTY import, session logging (rest of P1);
one-click OpenVPN with TOTP (P2).

### Using it

- Click a connection to open it in a new tab; **Ctrl-click** to split it into
  the current tab beside what is already there.
- The folder icon on a row opens an SFTP pane (Ctrl-click to split it too).
- Ctrl-Shift-PageUp / PageDown switch tabs.
- Port forwarding rules go in the connection editor, one per line:
  `L 8080:localhost:80`, `R 9090:localhost:22`, `D 1080`. They start with the
  session and stop when its pane closes. Local and SOCKS listeners bind
  `127.0.0.1` only — on a shared machine `0.0.0.0` would hand the tunnel to
  every other user on the box.

No way to change the master password yet — wipe `vault.enc` and start over.

## Tests

```bash
.venv/bin/python test_p0.py    # vault crypto, file modes, origin guard
.venv/bin/python test_e2e.py   # full stack against an in-process sshd
.venv/bin/python test_live.py  # real uvicorn + real WebSocket handshake
```

`test_e2e.py` uses Starlette's TestClient, which implements WebSockets
in-process — it cannot catch server-level transport problems. `test_live.py`
exists for those.
