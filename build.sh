#!/usr/bin/env bash
# Build a self-contained Shelldeck for the current OS.
#   Linux  -> dist/Shelldeck + dist/Shelldeck-x86_64.AppImage
#   macOS  -> dist/Shelldeck (run on a Mac)
#   Windows-> dist/Shelldeck.exe (run on Windows)
# Requires: python3, and for the AppImage step, appimagetool on PATH.
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv 2>/dev/null || true
.venv/bin/pip -q install -e . pyinstaller

.venv/bin/pyinstaller --clean -y shelldeck.spec
echo "built dist/Shelldeck"

# AppImage (Linux only, best-effort)
if [ "$(uname)" = "Linux" ] && command -v appimagetool >/dev/null 2>&1; then
  rm -rf build/AppDir && mkdir -p build/AppDir/usr/bin
  cp dist/Shelldeck build/AppDir/usr/bin/
  cp packaging/shelldeck.desktop build/AppDir/
  cp packaging/shelldeck.png build/AppDir/
  cp packaging/shelldeck.png build/AppDir/.DirIcon
  cp packaging/AppRun build/AppDir/AppRun && chmod +x build/AppDir/AppRun
  ARCH=x86_64 appimagetool --no-appstream build/AppDir dist/Shelldeck-x86_64.AppImage
  echo "built dist/Shelldeck-x86_64.AppImage"

  # Regenerate the run guide with THIS build's checksum. Written here rather than
  # kept as a static file, so it can never quote a stale hash after a rebuild.
  SUM=$(sha256sum dist/Shelldeck-x86_64.AppImage | cut -d' ' -f1)
  sed "s/__SHA256__/$SUM/" packaging/HOW-TO-RUN.txt.in > dist/HOW-TO-RUN.txt
  echo "wrote dist/HOW-TO-RUN.txt (sha256 $SUM)"
fi
