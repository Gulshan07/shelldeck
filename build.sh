#!/usr/bin/env bash
# Build a self-contained EazyConnector for the current OS.
#   Linux  -> dist/EazyConnector + dist/EazyConnector-x86_64.AppImage
#   macOS  -> dist/EazyConnector (run on a Mac)
#   Windows-> dist/EazyConnector.exe (run on Windows)
# Requires: python3, and for the AppImage step, appimagetool on PATH.
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv 2>/dev/null || true
.venv/bin/pip -q install -e . pyinstaller

.venv/bin/pyinstaller --clean -y eazyconnector.spec
echo "built dist/EazyConnector"

# AppImage (Linux only, best-effort)
if [ "$(uname)" = "Linux" ] && command -v appimagetool >/dev/null 2>&1; then
  rm -rf build/AppDir && mkdir -p build/AppDir/usr/bin
  cp dist/EazyConnector build/AppDir/usr/bin/
  cp packaging/eazyconnector.desktop build/AppDir/
  cp packaging/eazyconnector.png build/AppDir/
  cp packaging/eazyconnector.png build/AppDir/.DirIcon
  cp packaging/AppRun build/AppDir/AppRun && chmod +x build/AppDir/AppRun
  ARCH=x86_64 appimagetool --no-appstream build/AppDir dist/EazyConnector-x86_64.AppImage
  echo "built dist/EazyConnector-x86_64.AppImage"
fi
