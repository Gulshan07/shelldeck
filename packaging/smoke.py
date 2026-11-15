"""Launch a built Shelldeck and prove it actually serves.

Cross-platform (this is how the Windows and macOS builds are verified in CI,
where there is no browser and no display).

    python packaging/smoke.py dist/Shelldeck[.exe]
"""
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

exe = sys.argv[1]
home = tempfile.mkdtemp()
env = dict(os.environ, SHELLDECK_HOME=home, SHELLDECK_NO_BROWSER="1")

proc = subprocess.Popen([exe], env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True)


def die(msg):
    proc.kill()
    out, _ = proc.communicate(timeout=10)
    print(out or "(no output)")
    sys.exit(f"SMOKE FAILED: {msg}")


url_file = os.path.join(home, "url")
url = ""
for _ in range(120):                       # up to 60s: a cold onefile unpack is slow
    if proc.poll() is not None:
        die(f"exited early with code {proc.returncode}")
    if os.path.exists(url_file):
        url = open(url_file).read().strip()
        if url:
            break
    time.sleep(0.5)
if not url:
    die("never wrote its url file")

base, _, token = url.partition("/#")


def get(path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


try:
    # The url file is written before uvicorn binds, so wait for the socket too.
    code, body = 0, b""
    for _ in range(60):
        try:
            code, body = get("/")
            if code:
                break
        except Exception:
            pass
        if proc.poll() is not None:
            die(f"exited while starting (code {proc.returncode})")
        time.sleep(0.5)
    if code != 200 or b"Shelldeck" not in body:
        die(f"index returned {code}")
    if get("/static/vendor/xterm.js")[0] != 200:
        die("bundled xterm.js is missing from the build")
    if get("/static/vendor/fonts/jetbrains-mono-400.woff2")[0] != 200:
        die("bundled fonts are missing from the build")
    if get("/api/vault")[0] != 401:
        die("the API answered without a token")
    if get("/api/vault", {"Authorization": "Bearer " + token})[0] != 200:
        die("the API rejected its own token")
    print(f"SMOKE OK  {os.path.basename(exe)} served {base}, static bundled, auth enforced")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
