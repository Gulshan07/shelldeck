# Changelog

Notable changes per release. Dates are release dates.

## Unreleased

**VPN**
- Choose how a profile's authenticator code is supplied: typed at connect time
  (works with any authenticator app, Microsoft Authenticator included), or
  generated from a key given as a setup key, an `otpauth://` link, Google
  Authenticator's export link, or a screenshot of the QR code.
- A Google Authenticator export holding several accounts asks which one to use.
- The current code is shown once after saving a key, to compare with the phone.
- A login the server refuses now says so ("authentication rejected …") instead
  of stopping at `GET_CONFIG`, and points at the computer's clock when the code
  was generated.
- TOTP keys using SHA-256/SHA-512, 8 digits or a non-30-second period work.

## v0.1.0 — 2026-09-06

First public release. Linux only; Windows and macOS are written but unverified,
so they are not released yet.

The project was called EazyConnector before this release. Nothing was published
under that name, but a vault created by a pre-release build still opens: if
`~/.shelldeck` does not exist and `~/.eazyconnector` does, the old directory is
used in place.

**Sessions**
- SSH, Telnet and serial console sessions in tabs, with Ctrl-click split panes
  and a real terminal (xterm.js, vendored — no build step).
- Jump hosts chained to any depth, host key verified at every hop.
- Port forwarding: local, remote and SOCKS, started and torn down with the
  session. Local and SOCKS listeners bind `127.0.0.1` only.
- SFTP browser: navigate, upload with backpressure, download, and a recursive
  server-side search.

**Automation**
- Start 2–7 instances of one host side by side in a tab.
- Keyboard shortcuts on Alt (the browser owns the Ctrl combinations), listed
  under F1: new, search, broadcast, lock, and edit/clone/instances on the
  focused connection.
- Clusters — broadcast typing to every terminal in a tab, or open a whole group
  into one tab in a click.
- Macros — `expect`/`send`/`sleep` scripts, attachable per connection, able to
  run automatically on connect.
- Per-connection commands: locally before connecting, on the server after login,
  locally after disconnecting.

**Networking**
- One-click OpenVPN with the password and TOTP answered automatically, over
  OpenVPN's management interface. All three second-factor dialects: SCRV1
  `static-challenge`, appended, and dynamic `CRV1`.

**Records**
- Encrypted session logs, opt-in per connection, with timed playback at 1×–8×.

**Getting servers in and out**
- Clone a connection into the same group, credentials included, named `name-1`.
- Import from `~/.ssh/config` or Ásbrú, grouped, with jump hosts re-linked.
  Ásbrú's stored passwords are deliberately never decrypted.
- Export a secret-free bundle to share a setup with colleagues.

**Security**
- Vault: scrypt (n=2¹⁷) + AES-256-GCM under a master password, 15-minute idle
  auto-lock, change-password in place.
- Server binds `127.0.0.1` on an ephemeral port, with no option to bind
  elsewhere. Token lives in the URL fragment, never in a command line.
- `Origin` checked on every request; both WebSockets take the token as their
  first message.
- Files written `0600` inside a `0700` directory, re-applied on every write.
- Trust-on-first-use host key pinning, with the fingerprint shown for
  out-of-band checking. Never silently skipped.
