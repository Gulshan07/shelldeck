# Security policy

EazyConnector stores SSH keys, passwords, TOTP secrets and VPN credentials. A
bug here can expose all of them, so security reports get priority over
everything else.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead:

> **Security** tab → **Report a vulnerability**

That opens a private advisory only you and I can read. If it is not enabled or
you cannot reach it, email **071297gk@gmail.com** with `EazyConnector security`
in the subject.

Please include what an attacker gains, the steps to reproduce, and the version
or commit you tested. A proof of concept helps but is not required.

I am one person doing this outside work hours. Expect an acknowledgement within
a few days, and please give me a reasonable window to ship a fix before
disclosing publicly.

## What is in scope

The threat model assumes **a shared machine where other local users are
hostile**. These are all in scope:

- Recovering vault contents without the master password.
- Reaching the local server, or a session, from another user account, another
  browser tab, or another origin.
- Secrets reaching disk unencrypted, a command line, a log, an export bundle,
  or the browser.
- Weakening host-key verification, or a path that skips it.
- Files created outside `0600` in a `0700` directory.

## What is not

- Anything requiring you to already be root, or to already know the master
  password.
- Weaknesses in OpenVPN, AsyncSSH or the browser itself — report those upstream,
  though tell me if EazyConnector uses them unsafely.
- The master password being weak. It is stretched with scrypt (n=2^17), but a
  guessable password is still a guessable password.
- Missing hardening on a single-user machine that only matters on a shared one
  is still worth reporting, but is lower priority.

## Design decisions that are not bugs

These look like flaws and are deliberate. Reporting them is fine, but expect
this answer:

- **The vault is on disk, not in an OS keychain.** Chosen so a vault is portable
  and works identically on every platform.
- **The master key cannot be reliably zeroed from memory on lock.** CPython
  offers no way to do it; a process dump after unlocking may contain it.
- **The auth token is in the URL fragment.** Browsers never send fragments to
  the server, which keeps it out of request logs, and it avoids passing a secret
  on a command line where `/proc/<pid>/cmdline` is world-readable.
- **Ásbrú's saved passwords are never decrypted on import**, by choice, even
  though its cipher key is public. Structure is imported; passwords are not.
