"""Regression tests for the pytr-hardened fork (patches P-1..P-6).

These cover the Denkeeper hardening spec acceptance criteria, notably:
  * AC-P2.1 - glm's two reproduced path-traversal payloads.
  * AC-P6.1 - every mutation method raises before any network I/O.
"""

import asyncio
import os
import stat
from datetime import datetime
from pathlib import Path

import pytest
from pathvalidate import sanitize_filepath

import pytr.api

# NB: pytr.api is referenced through the module, never imported by name:
# tests/test_api_urls.py importlib.reload()s it to re-evaluate its env-based
# constants, which replaces every class object in it. A name imported here
# before that reload would be a stale class and pytest.raises would not match
# the exceptions the live module raises.
from pytr.dl import (
    DL,
    PathTraversalError,
    UnexpectedDocumentHostError,
    _build_document_url,
    _sanitize_component,
)
from pytr.security import (
    InsecurePathError,
    assert_safe_to_read,
    redact,
    safe_fields,
    secure_dir,
    secure_write_text,
)

# --------------------------------------------------------------------------
# P-1 - file permissions
# --------------------------------------------------------------------------


def test_secure_dir_creates_0700(tmp_path):
    d = secure_dir(tmp_path / "vault")
    mode = stat.S_IMODE(os.stat(d).st_mode)
    assert mode == 0o700


def test_secure_write_text_is_0600_and_roundtrips(tmp_path):
    f = tmp_path / "vault" / "credentials"
    secure_write_text(f, "+49123\n1234\n")
    assert f.read_text() == "+49123\n1234\n"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    # parent tightened to 0700
    assert stat.S_IMODE(os.stat(f.parent).st_mode) == 0o700


def test_secure_write_text_rejects_symlink(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(InsecurePathError):
        secure_write_text(link / "creds", "x")


def test_assert_safe_to_read_rejects_group_readable(tmp_path):
    f = tmp_path / "cookies"
    f.write_text("x")
    os.chmod(f, 0o644)
    with pytest.raises(InsecurePathError):
        assert_safe_to_read(f)


def test_assert_safe_to_read_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.write_text("x")
    os.chmod(real, 0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(InsecurePathError):
        assert_safe_to_read(link)


# --------------------------------------------------------------------------
# P-2 - dl.py path containment (AC-P2.1)
# --------------------------------------------------------------------------


def _make_dl(output_path: Path) -> DL:
    """Build a DL instance without touching the network / Timeline / history."""
    dl = object.__new__(DL)
    dl.output_path = output_path
    dl.filename_fmt = "{iso_date}{time}{title}{subtitle}{doc_num}{id}"
    dl.flat = False
    dl.universal_filepath = False
    dl.dry_run = False
    dl.filepaths = []
    dl.doc_urls = []
    dl.futures = []

    class _Log:
        def __getattr__(self, _name):
            return lambda *a, **k: None

    dl.log = _Log()

    class _Future:
        pass

    class _Session:
        def get(self, *a, **k):
            # A contained (sanitized) payload legitimately reaches the queue;
            # return a stand-in future without performing real network I/O.
            return _Future()

    dl.session = _Session()
    return dl


def _assert_contained(paths, output: Path) -> None:
    root = output.resolve()
    for p in paths:
        resolved = Path(p).resolve()
        assert resolved.is_relative_to(root), f"{resolved} escaped {root}"
        assert all(part not in (".", "..") for part in resolved.relative_to(root).parts)


def test_base_behavior_is_vulnerable_title_dotdot(tmp_path):
    """Documents the base vulnerability: `..` in metadata escapes output."""
    output = tmp_path / "out"
    output.mkdir()
    # Reproduce the pre-patch path build: unsanitized title used as dir.
    escaping = sanitize_filepath(output / ".." / "2024-01-01 Doc.pdf", "_", "auto")
    assert not Path(escaping).resolve().is_relative_to(output.resolve())


def test_patch_contains_title_dotdot_payload(tmp_path):
    """glm payload #1: title `..` is neutralised and stays under output."""
    output = tmp_path / "out"
    output.mkdir()
    dl = _make_dl(output)
    doc = {
        "id": "doc-1",
        "title": "..",
        "detail": "",
        "action": {"payload": "https://api.traderepublic.com/api/v1/doc.pdf"},
    }
    dl.dl_doc(doc, "..", None, datetime(2024, 1, 1, 9, 0))
    assert dl.filepaths
    _assert_contained(dl.filepaths, output)


def test_patch_contains_docid_traversal_payload(tmp_path):
    """glm payload #2: doc id `../../../etc/evil` is neutralised."""
    output = tmp_path / "out"
    output.mkdir()
    doc = {
        "id": "../../../etc/evil",
        "title": "Kontoauszug",
        "detail": "",
        "action": {"payload": "https://api.traderepublic.com/api/v1/doc.pdf"},
    }
    dl = _make_dl(output)
    dl.dl_doc(doc, "Kontoauszug", None, datetime(2024, 1, 1, 9, 0))
    assert dl.filepaths
    _assert_contained(dl.filepaths, output)

    # Force the collision branch so the doc id enters the filename.
    dl2 = _make_dl(output)
    dl2.filepaths.append(dl.filepaths[0])
    doc2 = dict(doc)
    dl2.dl_doc(doc2, "Kontoauszug", None, datetime(2024, 1, 1, 9, 0))
    assert len(dl2.filepaths) == 2
    _assert_contained(dl2.filepaths, output)


def test_ensure_contained_raises_on_escape(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    dl = _make_dl(output)
    with pytest.raises(PathTraversalError):
        dl._ensure_contained(output / ".." / ".." / "etc" / "evil.pdf")


def test_sanitize_component_neutralises_traversal():
    assert _sanitize_component("..") == "_"
    assert _sanitize_component(".") == "_"
    assert "/" not in _sanitize_component("a/b/c")
    assert "\\" not in _sanitize_component("a\\b")


def test_build_document_url_rejects_foreign_host():
    with pytest.raises(UnexpectedDocumentHostError):
        _build_document_url("//evil.com/x.pdf")


def test_build_document_url_accepts_tr_host():
    assert _build_document_url("api/v1/doc.pdf") == "https://api.traderepublic.com/api/v1/doc.pdf"


# --------------------------------------------------------------------------
# P-4 - log redaction
# --------------------------------------------------------------------------


def test_redact_masks_secret_keys():
    payload = {
        "phoneNumber": "+49123",
        "pin": "1234",
        "processId": "abc",
        "token": "waf",
        "nested": {"cookie": "sess", "safe": "ok"},
        "list": [{"pin": "9"}],
    }
    red = redact(payload)
    assert red["phoneNumber"] == "***redacted***"
    assert red["pin"] == "***redacted***"
    assert red["processId"] == "***redacted***"
    assert red["token"] == "***redacted***"
    assert red["nested"]["cookie"] == "***redacted***"
    assert red["nested"]["safe"] == "ok"
    assert red["list"][0]["pin"] == "***redacted***"


def test_safe_fields_allowlist():
    assert safe_fields({"a": 1, "b": 2, "pin": "x"}, ("a",)) == {"a": 1}


# --------------------------------------------------------------------------
# P-5 - delta parser robustness
# --------------------------------------------------------------------------


def _api() -> pytr.api.TradeRepublicApi:
    return pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000")


def test_calculate_delta_skips_empty_segment():
    tr = _api()
    tr._previous_responses = {"1": "hello world"}
    assert tr._calculate_delta("1", "\t=5") == "hello"


def test_calculate_delta_raises_on_non_numeric_length():
    tr = _api()
    tr._previous_responses = {"1": "hello"}
    with pytest.raises(pytr.api.MalformedDeltaError):
        tr._calculate_delta("1", "=abc")


# --------------------------------------------------------------------------
# P-6 - read-only guard (AC-P6.1)
# --------------------------------------------------------------------------

ASYNC_MUTATIONS = [
    ("add_watchlist", ("isin",)),
    ("remove_watchlist", ("isin",)),
    ("limit_order", ("isin", "ex", "buy", 1, 10.0, "gfd")),
    ("market_order", ("isin", "ex", "buy", 1, "gfd", False)),
    ("stop_market_order", ("isin", "ex", "buy", 1, 10.0, "gfd")),
    ("cancel_order", ("order-1",)),
    ("create_savings_plan", ("isin", 25, "monthly", "2024-01-01", "t", "v")),
    ("change_savings_plan", ("sp-1", "isin", 25, "monthly", "2024-01-01", "t", "v")),
    ("cancel_savings_plan", ("sp-1",)),
    ("create_price_alarm", ("isin", 10.0)),
    ("cancel_price_alarm", ("alarm-1",)),
    ("subscribe_news", ("isin",)),
    ("unsubscribe_news", ("isin",)),
]

SYNC_MUTATIONS = [
    ("payout", (100,)),
    ("confirm_payout", ("proc", "1234")),
    # P-6 extension: session-state mutations of the #399 account switching.
    ("switch_account", (None,)),
    ("_post_session", ("subject-1",)),
]


@pytest.mark.parametrize("method,args", ASYNC_MUTATIONS)
def test_async_mutation_blocked_in_read_only(method, args):
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", read_only=True)
    with pytest.raises(pytr.api.ReadOnlyError):
        asyncio.run(getattr(tr, method)(*args))


@pytest.mark.parametrize("method,args", SYNC_MUTATIONS)
def test_sync_mutation_blocked_in_read_only(method, args):
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", read_only=True)
    with pytest.raises(pytr.api.ReadOnlyError):
        getattr(tr, method)(*args)


def test_read_only_defaults_false():
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000")
    assert tr._read_only is False
    # guard is a no-op when not read-only
    assert tr._guard_read_only() is None


# --------------------------------------------------------------------------
# P-7 - the PIN is single-use and released after the login POST (AC-P7.1)
# --------------------------------------------------------------------------

PIN = "4711"


class _FakeLoginResponse:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"processId": "proc-1", "countdownInSeconds": 30}


def _login_api(post):
    """Build an API with no WAF fetch and a stubbed login POST (no network I/O)."""
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin=PIN, waf_token=None, read_only=True)
    tr._websession.post = post
    return tr


def test_pin_is_sent_once_then_released():
    """AC-P7.1: the login POST carries the PIN, and the reference is dropped after."""
    sent = []

    def post(url, json=None, timeout=None, headers=None):
        sent.append(json)
        return _FakeLoginResponse()

    tr = _login_api(post)
    assert tr.pin == PIN  # held until consumed

    countdown = tr.initiate_weblogin()

    assert countdown == 31
    assert sent == [{"phoneNumber": "+490000000000", "pin": PIN}]  # actually delivered
    assert tr.pin is None  # released immediately after the POST


def test_pin_released_even_when_login_post_raises():
    """A network failure must not leave the PIN resident on the client."""

    def post(url, json=None, timeout=None, headers=None):
        raise ConnectionError("network down")

    tr = _login_api(post)
    with pytest.raises(ConnectionError):
        tr.initiate_weblogin()
    assert tr.pin is None


def test_no_attribute_retains_the_pin_after_login():
    """After login, no attribute of the client object holds the PIN value."""
    tr = _login_api(lambda url, json=None, timeout=None, headers=None: _FakeLoginResponse())
    tr.initiate_weblogin()

    leaks = [name for name, value in vars(tr).items() if value == PIN]
    assert leaks == [], f"PIN retained on attributes: {leaks}"


def test_second_initiate_weblogin_without_pin_raises():
    """Re-login on a consumed client fails loudly instead of POSTing a null pin."""
    calls = []

    def post(url, json=None, timeout=None, headers=None):
        calls.append(json)
        return _FakeLoginResponse()

    tr = _login_api(post)
    tr.initiate_weblogin()

    with pytest.raises(ValueError, match="PIN already consumed"):
        tr.initiate_weblogin()

    # The failed re-login must not have reached the network at all.
    assert len(calls) == 1


def test_resend_and_complete_weblogin_do_not_need_the_pin():
    """The rest of the login flow works off _process_id, not the PIN (P-7 safety)."""
    posted = []

    def post(url, json=None, timeout=None, headers=None):
        posted.append(url)
        return _FakeLoginResponse()

    tr = _login_api(post)
    tr.initiate_weblogin()
    assert tr.pin is None

    tr.resend_weblogin()  # must not raise
    tr.complete_weblogin("123456")  # must not raise
    assert any("/resend" in u for u in posted)
    assert any(u.endswith("/123456") for u in posted)
