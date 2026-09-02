# PyInstaller spec — one-file EazyConnector binary.
# Bundles the static UI (incl. vendored xterm.js). openvpn is NOT bundled;
# the app finds the system one (Require-it-installed choice).
from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=[],
    datas=[("eazyconnector/static", "eazyconnector/static")],
    # uvicorn/asyncssh load some deps lazily; pull them in explicitly.
    hiddenimports=(collect_submodules("uvicorn") + collect_submodules("asyncssh")
                   + ["websockets", "websockets.legacy", "yaml"]),
    hookspath=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="EazyConnector",
    console=True,             # prints the URL; users can also read ~/.eazyconnector/url
    onefile=True,
    strip=False, upx=False,
)
