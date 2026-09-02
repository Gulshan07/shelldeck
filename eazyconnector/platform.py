"""The only module that knows which OS it runs on.

POSIX behaviour is exactly what the code did before this module existed. Windows
branches are best-effort today (private per-user profile) and marked where they
need finishing when Windows packaging happens; nothing here crashes on Windows.
"""
import os
import shutil

IS_WINDOWS = os.name == "nt"


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
        return os.open(path, flags)          # mode largely ignored; ACL applied on close
    return os.open(path, flags, 0o600)


def lock_file(path):
    _restrict(path, 0o600)


def _restrict(path, posix_mode):
    if IS_WINDOWS:
        _win_owner_only(path)
    else:
        os.chmod(path, posix_mode)


def _win_owner_only(path):
    # ponytail: best-effort until Windows packaging. Per-user %LOCALAPPDATA% is
    # already not world-readable; tighten to owner-only with icacls then.
    try:
        import getpass
        os.system(f'icacls "{path}" /inheritance:r /grant:r "{getpass.getuser()}":F >NUL 2>&1')
    except Exception:
        pass


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
    if is_elevated() or os.environ.get("EAZY_OPENVPN_NO_SUDO"):
        return []
    if IS_WINDOWS:
        # ponytail: Windows elevation is a UAC prompt, not a piped password.
        # Until the Windows build, run the app elevated so openvpn inherits it.
        return []
    return ["sudo", "-S", "-p", ""] if sudo_pw else ["sudo", "-n"]
