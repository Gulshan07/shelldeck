# Packaging & distribution

The app is a single Python codebase with a browser UI. All OS-specific behaviour
lives in `eazyconnector/platform.py` (file permissions, elevation, openvpn path),
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

- **Ubuntu** → `dist/EazyConnector` (run it) and `dist/EazyConnector-x86_64.AppImage`
  (double-click, or `./EazyConnector-x86_64.AppImage`). ~18 MB.
- **macOS** → run `./build.sh` on a Mac → `dist/EazyConnector`. Everything works
  (macOS is POSIX). To avoid the Gatekeeper "unidentified developer" prompt, the
  binary must be code-signed + notarized (Apple Developer account).
- **Windows** → run `./build.sh` on Windows → `dist/EazyConnector.exe`. The core
  works; the VPN needs the app run as Administrator (Windows has no `sudo`), and
  file hardening uses ACLs — see the `ponytail:` notes in `platform.py`. To avoid
  the SmartScreen prompt, sign the .exe with a code-signing certificate.

## Giving it to a colleague (Ubuntu)

1. Send them `dist/EazyConnector-x86_64.AppImage`.
2. They run it (or `chmod +x` then double-click). It prints a URL and opens their
   browser. First launch asks them to create their own master password.
3. For the VPN feature: `sudo apt install openvpn`.

Each person's vault, config and keys live in their own `~/.eazyconnector` — nothing
is shared, nothing is sent anywhere.

## Building all three from one push (later)

A GitHub Actions matrix (ubuntu-latest / macos-latest / windows-latest) runs
`build.sh` on each runner and uploads the three artifacts. Add when the repo is on
GitHub; the build is already CI-ready (no interactive steps).

## OpenVPN

Not bundled (chosen: require-it-installed). The app finds the system `openvpn`
(`platform.find_openvpn()` also checks the standard Windows install path) and, if
missing, says exactly how to install it. Bundling it later is possible but adds
~30–50 MB per platform and GPL redistribution paperwork.
