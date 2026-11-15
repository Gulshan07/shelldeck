# Authenticator setup for VPN profiles — design

Date: 2026-11-15. Status: approved by Gulshan, 2026-11-15.

## Why

A VPN profile's second factor can only be configured today by typing the raw
base32 TOTP key into the profile form. People who already use the VPN rarely
have that key to hand:

- **Google Authenticator** will export it, but only as a QR code holding an
  `otpauth-migration://` link. Getting the key out took a second phone to scan
  the QR and copying the key from the decoded text.
- **Microsoft Authenticator** never reveals the key. Those users cannot
  configure the VPN in Shelldeck at all without re-enrolling with their admin.

This is the first thing a new user with an existing VPN hits, and the project
is about to be published.

## Goals

1. A VPN works in Shelldeck with **any** authenticator app, with no key.
2. A Google Authenticator user gets one-click connect from **one paste or one
   screenshot**, on one device.
3. The user picks the flow in the profile form.

## Non-goals

- Extracting a key from Microsoft Authenticator (impossible).
- HOTP (counter-based) codes.
- Camera capture of a QR code. Image file, drop or clipboard paste only.
- Any outbound network request (no online clock check).

## Anti-goals

- A TOTP key, or a pasted link containing one, must never be written to
  `config.json`, logged, or sent back to the browser.
- No npm, no build step, no new Python dependency.

## Approaches considered

| | What | Trade-off |
|---|---|---|
| A | Ask for the 6-digit code at connect time | Works for everyone; costs one-click |
| B | Accept a raw key, an `otpauth://` link or a Google export link | One paste for Google users; nothing for Microsoft users |
| C | Decode a QR image in the browser | No link to copy; needs a vendored QR decoder |

**Chosen: all three, selectable per profile** (Gulshan, 2026-11-15). A alone
loses one-click; B and C alone leave Microsoft users out.

## Design

### Profile setting

Each VPN profile gains a non-secret `totp_mode` in `config.json`:

| `totp_mode` | Meaning |
|---|---|
| `none` | No second factor. Password is sent as is. |
| `ask` | No key stored. Shelldeck asks for the code when the server wants it. |
| `stored` | Key is in the vault; code generated automatically (today's behaviour). |

A profile saved before this change has no `totp_mode`: treat it as `stored`
when the vault holds a `totp_secret`, otherwise `none`.

The form replaces the "TOTP secret (base32)" field with a chooser:

```
Authenticator code
 ( ) None
 ( ) Ask me each time I connect
 ( ) Paste a key or link     [ raw key / otpauth:// / Google export link ]
 ( ) Read a QR code image    [ choose, drop or paste a screenshot ]
```

"Paste" and "QR" both end in `totp_mode: stored`. Editing a profile that
already has a key shows "key stored" and leaves it untouched unless the user
supplies a new one (same rule the form uses for the password today).

Switching a profile from `stored` to `none` or `ask` **deletes the stored key**
from the vault, after a confirmation that says it cannot be recovered from
Shelldeck. (My call: an unused secret should not stay in the vault.)

The existing "Second factor" dialect selector (auto / SCRV1 / appended) is
unchanged; it decides how a code is delivered, whichever way it was obtained.

### A — ask at connect time

- `Vpn` gains a state `needs_code`. In `ask` mode, when openvpn's management
  interface sends `>PASSWORD:Need 'Auth'` (or a `CRV1` dynamic challenge),
  the driver sets `needs_code` and waits instead of answering.
- New endpoint `POST /api/vpn/code` with `{"code": "123456"}`. It hands the
  code to the waiting driver, which answers in the profile's dialect and
  returns to `connecting`. Only digits, 6–8 long, are accepted.
- The UI already polls `/api/vpn/status`. On `needs_code` it opens a small
  dialog, "Enter authenticator code for <name>", once per request.
- The 90-second connect deadline does not run while waiting for the code.
  Cancelling the dialog disconnects.
- A rejected login ends as `failed`; the user clicks connect again. No
  automatic retry loop. The server does not always say whether the password
  or the code was wrong, so the message names both: "authentication rejected
  — check the password and the code you typed".
- A re-authentication prompt on a live tunnel goes through the same path, so
  an `ask` profile can be re-authenticated without dropping. In that case the
  state **stays `connected`** (IP and uptime keep showing) and the status
  payload carries a separate `pending_code: true`; `needs_code` is used only
  before the tunnel is first up. (My call.)
- Waiting has a limit only on first connect: 5 minutes, then `failed` with
  "no authenticator code entered". On a live tunnel Shelldeck keeps waiting;
  if nobody answers, the server drops the tunnel and the normal exit handling
  reports it. (My call.)
- Dynamic-challenge (`CRV1`) servers: the user is asked at the first prompt
  and again at the challenge, exactly as a stored key is used twice today. A
  server that refuses a reused code needs the user to wait for the next code
  before answering the second prompt; the dialog says so. No new dialect
  option. (My call; known limitation.)

### B — paste a key or link

One server-side parser in `vpn.py` takes the pasted text and returns a list
of accounts (`label`, `issuer`, `secret`, `digits`, `period`, `algorithm`):

- bare base32 key → one account, defaults 6 digits / 30 s / SHA-1;
- `otpauth://totp/...` → one account, honouring `digits`, `period`,
  `algorithm`; `otpauth://hotp/` is rejected with a clear message;
- `otpauth-migration://offline?data=...` → Google's export: base64 of a small
  protobuf. Decode it with a hand-written varint/field reader in stdlib
  (no protobuf dependency). TOTP entries only.

`totp()` gains an `algorithm` argument (SHA-1 / SHA-256 / SHA-512). The vault
entry stores `totp_secret` plus `totp_digits`, `totp_period`,
`totp_algorithm` when they differ from the defaults.

`POST /api/vpns` accepts `totp_input` (the raw pasted text) and optional
`totp_account` (an index). If the input holds several accounts and no index
was given, it replies `409` with the list of **labels only**; the form shows
a picker and resubmits with the index. Secrets never travel back.

### C — QR code image

- Vendor **jsQR** (single file, Apache-2.0) into `static/vendor/`, with its
  licence noted next to xterm's.
- The form takes an image by file picker, drag-and-drop or clipboard paste,
  draws it to a canvas, decodes it, and puts the decoded text into the same
  `totp_input` field as flow B. From there the path is identical.
- The image is never uploaded or stored. An image with no readable QR shows
  "no QR code found in that image".

### Confirming it worked

- After a save that stored a key, the response includes the **current code**
  once, and the form shows "Current code: 123 456 — it should match your
  phone". A mismatch means the wrong account or a wrong clock. (Approved: a
  30-second code is not treated as a secret; the key still never leaves the
  server.)
- When a server rejects a login that used a generated code, the failure
  detail is "authentication rejected — if the password is right, check this
  computer's clock". No network check is made.

## Testing

- `test_p0.py`: parser vectors for a bare key, `otpauth://` with non-default
  digits/period/algorithm, a Google migration link with two accounts, HOTP
  rejection, garbage input; RFC 6238 SHA-256/512 vectors.
- `test_vpn.py`: `ask` mode against `testbin/openvpn` — `needs_code`, correct
  code connects, wrong code fails, deadline does not expire while waiting, and
  a re-auth prompt on a live tunnel (new fake mode) sets `pending_code` while
  staying `connected`.
- `test_live.py`: key, pasted link and labels-only `409` never put a secret in
  `config.json` or a response body.
- `test_ui.py`: the chooser, the code dialog, the account picker, and decoding
  a fixture QR PNG.

## Left to the builder

Exact wording and layout of the chooser and dialogs; how the driver waits for
the code (future/event); where the parser lives inside `vpn.py`; the jsQR
version to vendor.
