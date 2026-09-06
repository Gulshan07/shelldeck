"""End-to-end VPN: spawns a fake openvpn that speaks the real management
protocol, so the whole auth conversation is exercised without root or a tunnel.
Run: .venv/bin/python test_vpn.py"""
import asyncio, os, tempfile, time

os.environ["SHELLDECK_HOME"] = tempfile.mkdtemp()
os.environ["SHELLDECK_OPENVPN_NO_SUDO"] = "1"
os.environ["PATH"] = os.path.abspath("testbin") + os.pathsep + os.environ["PATH"]

from shelldeck import store
from shelldeck.vpn import Vpn, VpnError, totp, RUN_DIR

PW = "corporate-secret"
SEED = "JBSWY3DPEHPK3PXP"
OVPN_SC = ('client\nremote vpn.example.com 1194 udp\nauth-user-pass\n'
           'static-challenge "Enter Authenticator Code" 1\n<key>\nPRIVATE-KEY-BYTES\n</key>\n')
OVPN_PLAIN = 'client\nremote vpn.example.com 1194 udp\nauth-user-pass\n'


async def run(mode, ovpn, profile_extra=None, timeout=25):
    os.environ["FAKE_VPN_MODE"] = mode
    os.environ["FAKE_VPN_PASSWORD"] = PW
    os.environ["FAKE_VPN_SEED"] = SEED
    v = Vpn()
    prof = {"id": "p1", "name": "Vitraya", "username": "gulshan", "dialect": "auto"}
    prof.update(profile_extra or {})
    await v.up(prof, {"ovpn": ovpn, "password": PW, "totp_secret": SEED})
    end = time.time() + timeout
    while time.time() < end and v.state == "connecting":
        await asyncio.sleep(0.2)
    return v


async def main():
    store.init_home()

    # 1. SCRV1 (the real Vitraya profile shape)
    v = await run("ok", OVPN_SC)
    assert v.state == "connected", (v.state, v.detail, v.log[-6:])
    assert v.ip == "10.8.0.7", v.ip
    print("ok  SCRV1 profile connected, ip", v.ip)

    # the profile with the private key must exist only while connected
    cfg = RUN_DIR / "p1.ovpn"
    assert cfg.exists(), "config should exist during the session"
    import stat as st
    assert st.S_IMODE(cfg.stat().st_mode) == 0o600, "config with a private key must be 0600"
    assert st.S_IMODE(RUN_DIR.stat().st_mode) == 0o700
    print("ok  runtime config is 0600 inside a 0700 dir")

    await v.down()
    assert v.state == "disconnected"
    assert not cfg.exists(), "config holding the private key must be deleted on disconnect"
    assert not (RUN_DIR / "p1.mgmt").exists(), "management password file must be deleted"
    print("ok  private key and mgmt password wiped from disk on disconnect")

    # 2. concatenated dialect
    v = await run("ok", OVPN_PLAIN)
    assert v.state == "connected", (v.state, v.detail, v.log[-6:])
    print("ok  concatenated-TOTP profile connected")
    await v.down()

    # 3. dynamic CRV1 challenge (code expired mid-handshake)
    v = await run("challenge", OVPN_SC)
    assert v.state == "connected", (v.state, v.detail, v.log[-6:])
    print("ok  answered a dynamic CRV1 challenge with a fresh code")
    await v.down()

    # 4. wrong password is reported, not hung
    os.environ["FAKE_VPN_MODE"] = "badpass"
    v = Vpn()
    await v.up({"id": "p1", "name": "Vitraya", "username": "u", "dialect": "auto"},
               {"ovpn": OVPN_SC, "password": "wrong", "totp_secret": SEED})
    end = time.time() + 25
    while time.time() < end and v.state == "connecting":
        await asyncio.sleep(0.2)
    assert v.state == "failed", (v.state, v.detail)
    assert "reject" in v.detail or "auth" in v.detail.lower(), v.detail
    print("ok  bad credentials reported as:", v.detail)
    await v.down()
    assert not (RUN_DIR / "p1.ovpn").exists(), "failed run must not leave the key on disk"
    print("ok  failed run also wipes the key from disk")

    # 5. a tunnel that comes up without any >STATE: notification is still detected,
    #    because openvpn's own log is authoritative
    v = await run("nostate", OVPN_SC)
    assert v.state == "connected", (v.state, v.detail, v.log[-6:])
    assert any("Initialization Sequence Completed" in l for l in v.log)
    print("ok  detected a live tunnel from the openvpn log with no >STATE: at all")
    await v.down()

    # 6. a stale 'failed' state with openvpn still alive must not start a second tunnel
    os.environ["FAKE_VPN_MODE"] = "ok"
    v = Vpn()
    prof = {"id": "p1", "name": "Vitraya", "username": "u", "dialect": "auto"}
    sec = {"ovpn": OVPN_SC, "password": PW, "totp_secret": SEED}
    await v.up(prof, sec)
    end = time.time() + 25
    while time.time() < end and v.state == "connecting":
        await asyncio.sleep(0.2)
    assert v.state == "connected"
    first_pid = v._proc.pid
    v.state = "failed"                    # what the missed-status bug looked like
    await v.up(prof, sec)                 # must tear the old one down, not stack another
    assert v._proc.pid != first_pid
    import subprocess as sp
    assert sp.run(["kill", "-0", str(first_pid)], capture_output=True).returncode != 0, \
        "the first openvpn was left running alongside the second"
    print("ok  a stale failed state tears the old tunnel down instead of duplicating it")
    await v.down()

    # 7. guard rails
    v = Vpn()
    try:
        await v.up({"id": "x", "name": "x", "dialect": "auto"}, {})
        raise AssertionError("missing .ovpn should be refused")
    except VpnError as e:
        print("ok  refuses a profile with no .ovpn:", e)

    print("\nvpn passed")

asyncio.run(main())
