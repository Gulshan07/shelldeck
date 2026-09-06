"""The only module that knows which OS it runs on.

POSIX behaviour is exactly what the code did before this module existed.
Windows uses ACLs instead of mode bits and UAC instead of sudo.
"""
import os
import shutil
import subprocess

IS_WINDOWS = os.name == "nt"

# Keep a console window from flashing up for each helper process we run.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0


def set_umask():
    """Deny group/other on everything we create. No-op on Windows (uses ACLs)."""
    if not IS_WINDOWS:
        os.umask(0o077)


def make_private_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    _restrict(path, 0o700)


def open_private(path, flags):
    """Open a file for writing, owner-only. Returns an fd."""
    if IS_WINDOWS:
        # O_BINARY is essential, not cosmetic: without it the CRT may translate
        # \n to \r\n on write, which would corrupt the encrypted vault and the
        # session logs (both are binary AES-GCM blobs, not text).
        fd = os.open(path, flags | getattr(os, "O_BINARY", 0))
        _win_owner_only(path)                # apply the ACL as soon as it exists
        return fd
    return os.open(path, flags, 0o600)


def lock_file(path):
    _restrict(path, 0o600)


def _restrict(path, posix_mode):
    if IS_WINDOWS:
        _win_owner_only(path)
    else:
        os.chmod(path, posix_mode)


def _win_owner_only(path):
    """Break inheritance and grant only the current user — the ACL equivalent of
    chmod 600/700. Run without a shell so a path with quotes cannot inject."""
    try:
        import getpass
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{getpass.getuser()}:F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=_NO_WINDOW, check=False, timeout=15)
    except Exception:
        pass          # a failed ACL must never stop the app from starting


def is_elevated() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def find_openvpn():
    """Path to the openvpn binary, or None. Windows keeps it off PATH by default."""
    name = "openvpn.exe" if IS_WINDOWS else "openvpn"
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS:
        for base in (r"C:\Program Files\OpenVPN\bin",
                     r"C:\Program Files (x86)\OpenVPN\bin"):
            cand = os.path.join(base, "openvpn.exe")
            if os.path.exists(cand):
                return cand
    return None


def elevation_prefix(sudo_pw):
    """Command prefix to run the next argv with root/admin, or [] if already
    elevated or elevation isn't available this way on the platform."""
    if is_elevated() or os.environ.get("SHELLDECK_OPENVPN_NO_SUDO"):
        return []
    if IS_WINDOWS:
        # Windows elevation is a UAC prompt, not a password we can pipe, so there
        # is no prefix that works. elevation_problem() explains this up front
        # instead of letting openvpn fail with a confusing access error.
        return []
    return ["sudo", "-S", "-p", ""] if sudo_pw else ["sudo", "-n"]


def elevation_problem():
    """Why we cannot get the privileges openvpn needs, or None if we can."""
    if is_elevated() or os.environ.get("SHELLDECK_OPENVPN_NO_SUDO"):
        return None
    if IS_WINDOWS:
        return ("OpenVPN needs Administrator rights on Windows, and Windows cannot be "
                "given a password the way sudo can. Close Shelldeck, right-click it "
                "and choose 'Run as administrator', then connect again.")
    return None      # POSIX: sudo handles it, with or without a stored password


def sudo_available() -> bool:
    """Whether a root-owned file can be read by escalating. Never on Windows."""
    return not IS_WINDOWS and shutil.which("sudo") is not None
