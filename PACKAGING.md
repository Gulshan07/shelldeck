# Packaging & distribution

The app is a single Python codebase with a browser UI. All OS-specific behaviour
lives in `shelldeck/platform.py` (file permissions, elevation, openvpn path),
so the same source builds for all three platforms.

## What "install and go" means here

PyInstaller bundles Python + every dependency into one self-contained executable.
Your colleagues download one file — **no Python, no pip, nothing else** — except
OpenVPN, which stays a normal system install and is only needed for the VPN feature
(SSH/SFTP work without it).

## Build for the current OS

```bash
./build.sh
```

- **Ubuntu** → `dist/Shelldeck` (run it) and `dist/Shelldeck-x86_64.AppImage`
  (double-click, or `./Shelldeck-x86_64.AppImage`). ~18 MB.
- **macOS** → run `./build.sh` on a Mac → `dist/Shelldeck`. Everything works
  (macOS is POSIX). To avoid the Gatekeeper "unidentified developer" prompt, the
  binary must be code-signed + notarized (Apple Developer account).
- **Windows** → run `./build.sh` on Windows → `dist/Shelldeck.exe`. The core
  works; the VPN needs the app run as Administrator (Windows has no `sudo`), and
  file hardening uses ACLs — see the `ponytail:` notes in `platform.py`. To avoid
  the SmartScreen prompt, sign the .exe with a code-signing certificate.

## Giving it to a colleague (Ubuntu)

1. Send them `dist/Shelldeck-x86_64.AppImage`.
2. They run it (or `chmod +x` then double-click). It prints a URL and opens their
   browser. First launch asks them to create their own master password.
3. For the VPN feature: `sudo apt install openvpn`.

Each person's vault, config and keys live in their own `~/.shelldeck` — nothing
is shared, nothing is sent anywhere.

## Building all three from one push

`.github/workflows/build.yml` does this, started by hand from the Actions tab
("Run workflow"): the test suites run on Linux, then a matrix builds on
ubuntu / windows / macos runners. Each built
binary must pass `packaging/smoke.py` — it launches the artifact, waits for it to
bind, and asserts the index serves, the bundled `xterm.js` is present, an
unauthenticated API call gets 401 and an authenticated one gets 200. A build that
compiles but cannot run therefore fails the pipeline.

Artifacts are uploaded per platform. Dispatching the workflow against a `v*`
tag additionally creates a GitHub Release and attaches them, which is how the
download link in the README gets populated.

It is manual-dispatch only because the repository is private, where Actions
minutes are metered and macOS bills at 10x. Once the repository is public,
Actions is free on standard runners and the `push:` / `pull_request:` triggers
are worth restoring so incoming PRs get tested.

## Building and testing on Windows

From a clean Windows box with Python 3.10+ and Git installed:

```powershell
git clone https://github.com/Gulshan07/Shelldeck.git
cd Shelldeck
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[build,import,serial,test]"

.venv\Scripts\python test_p0.py          # start here; pure crypto and parsers
.venv\Scripts\pyinstaller --clean -y shelldeck.spec
.venv\Scripts\python packaging\smoke.py dist\Shelldeck.exe
```

`smoke.py` passing means the binary launches, serves, bundles its assets and
enforces its token. It does not exercise the Windows-specific paths, so check
these by hand — each maps to code that has never run on real Windows:

1. **The vault survives a restart.** Create it, add a connection, quit, relaunch,
   unlock. A failure here means the `O_BINARY` guard is wrong and CRLF
   translation corrupted the AES-GCM blob.
2. **File permissions.** `icacls %USERPROFILE%\.shelldeck\vault.enc` should
   list your user only, with inheritance broken.
3. **VPN without Administrator.** Starting a VPN unelevated must show the "run as
   Administrator" message, not an obscure openvpn failure.
4. **SSH, including through a jump host.** The core path, unchanged from Linux,
   but confirm host-key prompts and known_hosts write correctly.
5. **A serial connection** on a `COM3`-style device, if any hardware is to hand.

Report what breaks — none of the above has been verified by a human yet, which
is why the README calls Windows untested.

## Windows specifics

- File hardening uses `icacls` (break inheritance, grant the current user only)
  instead of chmod. Run without a shell, so a path cannot inject.
- `O_BINARY` is set explicitly when writing the vault and session logs. Without
  it the CRT can translate `\n` to `\r\n` and corrupt those AES-GCM blobs.
- There is no `sudo`. OpenVPN needs Administrator, so the app checks up front and
  tells the user to relaunch elevated rather than letting openvpn fail obscurely.
  Reading a root-owned key file via sudo is likewise unavailable and says so.
- Serial devices are `COM3`-style rather than `/dev/ttyUSB0`.

## OpenVPN

Not bundled (chosen: require-it-installed). The app finds the system `openvpn`
(`platform.find_openvpn()` also checks the standard Windows install path) and, if
missing, says exactly how to install it. Bundling it later is possible but adds
~30–50 MB per platform and GPL redistribution paperwork.
