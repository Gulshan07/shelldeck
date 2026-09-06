# Shelldeck — Plan

Ásbrú-style connection manager, OS-independent, one binary-ish install, secrets never leave the machine.

## Decisions (locked)

| Thing | Choice | Why |
|---|---|---|
| Shape | Local web server on `127.0.0.1`, UI in your browser | Runs anywhere Python runs, incl. headless/remote. No Electron, no build step. |
| Protocols P1 | SSH, SFTP, Serial, Telnet | Covers ~90% of Ásbrú use. RDP/VNC deferred. |
| Vault | `~/.shelldeck/vault.enc`, master password | Portable, syncable, works headless. |
| VPN | System `openvpn` + management interface | Auditable, no reimplementation. |

## Stack

- **Backend:** Python 3.10+, `asyncssh` (SSH/SFTP/jump hosts/port forwarding/agent), `starlette`+`uvicorn` (HTTP + WebSocket), `pyserial-asyncio` (serial).
- **Crypto:** stdlib `hashlib.scrypt` for KDF + `cryptography` AES-256-GCM (already an asyncssh dep — no new dependency).
- **TOTP:** ~12 lines of stdlib `hmac` + `struct`. No `pyotp`.
- **Frontend:** vendored `xterm.js` + plain HTML/CSS/JS. No React, no bundler, no npm at runtime.
- **Install:** `pipx install shelldeck` → `shelldeck` opens the browser.

Total new runtime deps: 4.

## Security model

Threat: laptop stolen, or a random web page in your browser tries to talk to the local server.

1. Server binds `127.0.0.1` only. Never `0.0.0.0` — no flag to make it.
2. On launch it prints/opens `http://127.0.0.1:8790/#<random-32-byte-token>`. Every API call and the WebSocket must carry it. A malicious page can't guess it.
3. WebSocket `Origin` checked against `127.0.0.1:8790`; everything else rejected. Blocks DNS-rebinding + CSRF.
4. Vault: `scrypt(master_pw, salt, n=2**17)` → AES-256-GCM. Holds passwords, PEM key material, TOTP secrets, sudo passwords. On disk it is one opaque blob. Config (hostnames, ports, groups) sits **outside** in plain JSON so it's diffable/syncable — no secrets in it, ever.
5. Master key lives in process memory only. Auto-lock after 15 min idle → key zeroed, sessions stay up, new connects re-prompt.
6. PEM files: import copies the key *into* the vault; the original path is optional. Nothing readable on disk.
7. Secrets are never sent to the browser. The browser sends "connect to host X"; the server does auth. No password ever crosses the WebSocket to the UI.
8. Session logs are opt-in per connection, and vault-encrypted if on.

**Shared machine (this box is multi-user), so additionally:**

9. `~/.shelldeck/` is `0700`, every file `0600`, enforced on every write — not just at create.
10. Port is **ephemeral**, not a fixed 8790 — no port collisions between users, and no guessable target. The URL is written to `~/.shelldeck/url` (0600) and opened in the browser.
11. The token is **never** passed as a CLI argument (`/proc/<pid>/cmdline` is world-readable) and never in the URL path or query — it lives in the URL **fragment**, which the browser does not send to the server. JS reads it and puts it in an `Authorization` header. So it stays out of server logs and out of other users' reach.
12. Any `.ovpn`/PEM imported gets `chmod 600` and we warn if the source file was group/world-readable. (Your `profile-168.ovpn` was `rw-rw-r--` with an embedded `<key>` — already fixed to `600`.)
13. `umask 077` set at startup, before anything is written.
14. No temp files in `/tmp`. OpenVPN management uses a loopback socket, not a filesystem socket in a shared dir.

## Data model

```
~/.shelldeck/
  config.json     # tree, hosts, ports, protocols, options — NO secrets
  vault.enc       # AES-GCM blob: {cred_id: {password, key_pem, passphrase, totp_secret}}
  logs/           # opt-in session logs
  known_hosts
```
Connections reference `cred_id`. One credential reusable across many hosts.

## Phases

**Platform order: Linux first, macOS second, Windows third.** Anything platform-specific (elevation, keychain, serial device paths, browser launch) goes behind a tiny `platform.py` shim so 2 and 3 are a fill-in, not a rewrite.

### P0 — Skeleton  ✅ done
- Server + token auth + WebSocket.
- Vault create/unlock/lock.
- Connection tree CRUD in the UI.
- SSH terminal with password or key auth, xterm.js, resize, reconnect.
- **Verify:** SSH into a real server, run `top`, resize window, close cleanly.

### P1 — Ásbrú parity, daily-driver  ✅ done except PuTTY session import and Wake-on-LAN
- Tabs + split panes.
- Jump/proxy hosts (chained connections).
- Port forwarding: local `-L`, remote `-R`, dynamic SOCKS `-D`, per connection, auto-start on connect.
- SFTP browser: drag-drop up/down, in-place edit.
- Quick connect + fuzzy search over the tree.
- Import from `~/.ssh/config`, PuTTY sessions, Ásbrú YAML.
- Keepalive, pre/post-connect local commands, WOL.
- Terminal themes, font size, copy-on-select.
- **Verify:** replace Ásbrú for one full work week without falling back.

### P2 — OpenVPN one-click  ✅ done
Three TOTP dialects exist in the wild. All three supported, auto-detected from the .ovpn, overridable per profile:

| Dialect | Trigger in .ovpn | What we send as the password |
|---|---|---|
| **SCRV1** (your `profile-168`) | `static-challenge "..." 1` | `SCRV1:b64(password):b64(totp)` |
| **Concatenated** | nothing special | `password` + `totp` |
| **Dynamic challenge** | server replies `CRV1:...` mid-auth | `CRV1::<state>::<totp>` |

Flow:
```
openvpn --config x.ovpn --management 127.0.0.1 <ephemeral> --management-client-auth
  server: >PASSWORD:Need 'Auth' username/password
  us:     username "Auth" "<user>"
          password "Auth" "SCRV1:<b64 pw>:<b64 totp>"
  server: >STATE:...,CONNECTED,SUCCESS,<vpn ip>
```
Dynamic-challenge case: server answers `>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:<state>:<b64 user>:<prompt>']`
→ we regenerate a fresh TOTP and resend as `CRV1::<state>::<totp>`. Handles the "code expired mid-handshake" case too.

- Profile stores: .ovpn path, username, password, TOTP secret, and whether TOTP is appended to the password or answered as a challenge (both exist in the wild — configurable per profile).
- Elevation: one `sudo`/UAC prompt at VPN start, or install a small privileged helper later.
- Status pill in the UI: disconnected / connecting / connected + assigned IP + uptime.
- Auto-connect VPN before any connection tagged as needing it; disconnect when the last one closes (optional).
- **Verify:** one click → connected with no typing, on a real corporate profile.

### P3 — Power features  ✅ done
- Clusters: type once, send to N terminals.
- Macros / expect-send scripts (auto-sudo, auto-enable on network gear).
- Serial + Telnet.
- Session recording/playback.
- Optional encrypted export/import for moving to another machine.

### Later / maybe never
RDP, VNC, mobile UI, team sync. All deferred until asked.

## Answered
1. TOTP dialect — profile uses `static-challenge` → **SCRV1**. All three dialects supported anyway.
2. Shared machine → **yes**, hardening items 9-14 above.
3. Platform order → **Linux, macOS, Windows**.
