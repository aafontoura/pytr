from pathlib import Path

import pytest

import pytr.utils as pytr_utils


def _pytr_home_state(path: Path):
    """None when the directory is absent, else its mode, mtime and every entry's mode, size and mtime."""
    try:
        top = path.lstat()
    except FileNotFoundError:
        return None
    entries = []
    for entry in sorted(path.rglob("*")):
        st = entry.lstat()
        entries.append((entry.relative_to(path).as_posix(), st.st_mode, st.st_size, st.st_mtime_ns))
    return top.st_mode, top.st_mtime_ns, entries


@pytest.fixture(autouse=True)
def real_pytr_home_unchanged():
    real = Path.home() / ".pytr"
    before = _pytr_home_state(real)
    yield
    assert _pytr_home_state(real) == before, "a test created or changed the real ~/.pytr"


@pytest.fixture(autouse=True)
def suppress_info_logs(monkeypatch):
    # pytr loggers call coloredlogs.install(level=log_level, ...) with propagate=False,
    # bypassing pytest's capture. Setting log_level to "warning" before tests run
    # makes all subsequently created loggers install at WARNING level.
    monkeypatch.setattr(pytr_utils, "log_level", "warning")
    # Also raise the level on handlers already installed on existing loggers.
    import logging

    for lg in logging.root.manager.loggerDict.values():
        if isinstance(lg, logging.Logger):
            for handler in lg.handlers:
                handler.setLevel(logging.WARNING)
    yield
