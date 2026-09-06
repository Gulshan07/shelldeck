"""Launch on an ephemeral loopback port. Token goes in the URL fragment only."""
import os
import socket
import threading
import webbrowser

import uvicorn

from . import store
from .server import TOKEN, app


def main():
    store.init_home()

    # Ephemeral port: no collision with other users on this machine, nothing guessable.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    url = f"http://127.0.0.1:{port}/#{TOKEN}"
    store.write_private(store.URL_FILE, url.encode())
    print(f"Shelldeck → {url}")
    print(f"(also saved to {store.URL_FILE}, mode 0600)")

    # Headless servers and CI have no browser to open; opening one there either
    # fails noisily or hangs.
    if not os.environ.get("SHELLDECK_NO_BROWSER"):
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
