# MIT License
#
# Hardening helpers (pytr-hardened fork).
#
# Centralised filesystem-permission and redaction helpers used to fail closed
# when writing credential / cookie / log material. See P-1 and P-4 of the
# Denkeeper pytr-hardening spec.

import os
import stat
from pathlib import Path
from typing import Any

DIR_MODE = 0o700
FILE_MODE = 0o600


class InsecurePathError(RuntimeError):
    """Raised when a path cannot be used safely (symlink, unsafe mode, ...)."""


def secure_dir(path: Path) -> Path:
    """Create ``path`` (and parents) with ``0700`` perms, failing closed.

    Rejects the path if it already exists as a symlink. Tightens the mode of an
    existing directory to ``0700``.
    """
    path = Path(path)
    if path.is_symlink():
        raise InsecurePathError(f"Refusing to use symlinked directory: {path}")
    if path.parent and not path.parent.exists():
        secure_dir(path.parent)
    if not path.exists():
        # os.mkdir honours mode minus umask; chmod afterwards to be exact.
        os.mkdir(path)
    elif not path.is_dir():
        raise InsecurePathError(f"Expected a directory: {path}")
    os.chmod(path, DIR_MODE)
    return path


def _assert_not_symlink(path: Path) -> None:
    if path.is_symlink():
        raise InsecurePathError(f"Refusing to write through symlink: {path}")


def secure_write_text(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` with ``0600`` perms, refusing symlinks."""
    path = Path(path)
    secure_dir(path.parent)
    _assert_not_symlink(path)
    # O_NOFOLLOW so a symlink swapped in during the race is rejected by the OS.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, FILE_MODE)
    try:
        os.chmod(path, FILE_MODE)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def secure_prepare_file(path: Path) -> Path:
    """Ensure ``path``'s directory exists (0700) and pre-create ``path`` at 0600.

    Used before handing the path to a third-party writer (cookie jar, log
    handler) that does not set permissions itself.
    """
    path = Path(path)
    secure_dir(path.parent)
    _assert_not_symlink(path)
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), FILE_MODE)
        os.close(fd)
    _assert_not_symlink(path)
    os.chmod(path, FILE_MODE)
    return path


def assert_safe_to_read(path: Path) -> Path:
    """Fail closed before loading a sensitive file we did not just create.

    Rejects symlinks and group/other-readable modes.
    """
    path = Path(path)
    if path.is_symlink():
        raise InsecurePathError(f"Refusing to read symlinked file: {path}")
    st = path.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InsecurePathError(f"Refusing to read file with unsafe permissions: {path} (mode {oct(st.st_mode)})")
    return path


# --- P-4 redaction helpers -------------------------------------------------

# Fields that must never be emitted to any log, at any level.
_SECRET_KEYS = {
    "pin",
    "phonenumber",
    "phone_no",
    "phone",
    "password",
    "token",
    "aws-waf-token",
    "waf_token",
    "cookie",
    "cookies",
    "processid",
    "code",
    "authorization",
}

_REDACTED = "***redacted***"


def redact(value: Any) -> Any:
    """Recursively redact known-sensitive keys from a payload for logging.

    Only structural, allow-listed-shape data survives; anything under a secret
    key name is replaced. Strings/other scalars pass through unchanged (callers
    must not pass raw secrets as bare scalars; use :func:`safe_fields`).
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in _SECRET_KEYS:
                out[k] = _REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def safe_fields(payload: Any, allow: tuple[str, ...]) -> dict:
    """Return only allow-listed top-level keys from ``payload`` for logging."""
    if not isinstance(payload, dict):
        return {}
    return {k: payload[k] for k in allow if k in payload}
