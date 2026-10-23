"""Regression tests for the pytr-hardened fork (patches P-1..P-6).

These cover the Denkeeper hardening spec acceptance criteria, notably:
  * AC-P2.1 - glm's two reproduced path-traversal payloads.
  * AC-P6.1 - every mutation method raises before any network I/O.
"""

import asyncio
import base64
import contextlib
import json
import logging
import os
import re
import stat
import sys
import time
import types
from concurrent.futures import Future
from datetime import datetime
from pathlib import Path

import pytest
import requests
from pathvalidate import sanitize_filepath

import pytr.api

# NB: pytr.api is referenced through the module, never imported by name:
# tests/test_api_urls.py importlib.reload()s it to re-evaluate its env-based
# constants, which replaces every class object in it. A name imported here
# before that reload would be a stale class and pytest.raises would not match
# the exceptions the live module raises.
from pytr.dl import (
    DL,
    DOC_DOWNLOAD_TIMEOUT,
    PathTraversalError,
    _sanitize_component,
)
from pytr.security import (
    InsecurePathError,
    assert_safe_to_read,
    redact,
    safe_fields,
    secure_dir,
    secure_prepare_file,
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


@contextlib.contextmanager
def _capture_logger(caplog, name):
    """pytr loggers stop propagation, so caplog only sees them through a handler on the logger itself."""
    logger = logging.getLogger(name)
    logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.DEBUG, logger=name):
            yield
    finally:
        logger.removeHandler(caplog.handler)


@pytest.fixture
def pytr_home(tmp_path, monkeypatch):
    """Point every ~/.pytr path the api and account modules use at a temp dir, and return that dir."""
    from pytr import account as account_mod

    base = tmp_path / ".pytr"
    for module in (pytr.api, account_mod):
        monkeypatch.setattr(module, "BASE_DIR", base)
        monkeypatch.setattr(module, "CREDENTIALS_FILE", base / "credentials")
    monkeypatch.setattr(pytr.api, "COOKIES_FILE", base / "cookies.txt")
    return base


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


class _RecordingSession:
    def __init__(self):
        self.urls = []
        self.timeouts = []

    def get(self, url, timeout=None):
        self.urls.append(url)
        self.timeouts.append(timeout)
        return _RecordedFuture()


class _RecordedFuture:
    pass


def _document(payload):
    return {"id": "doc-1", "title": "Abrechnung", "detail": "", "action": {"payload": payload}}


@pytest.mark.parametrize(
    "payload",
    [
        "https://evil.example/x.pdf",
        "http://api.traderepublic.com/api/v1/doc.pdf",
        "https://api.traderepublic.com.evil.example/doc.pdf",
    ],
)
def test_document_string_url_off_host_is_skipped_without_request_or_file(tmp_path, payload):
    dl = _make_dl(tmp_path)
    dl.session = _RecordingSession()
    dl.dl_doc(_document(payload), "title", None, datetime(2024, 1, 1))
    assert dl.session.urls == []
    assert dl.futures == []
    assert not any(tmp_path.rglob("*.pdf"))


def test_document_string_url_on_tr_host_is_queued(tmp_path):
    dl = _make_dl(tmp_path)
    dl.session = _RecordingSession()
    dl.dl_doc(_document("https://api.traderepublic.com/api/v1/doc.pdf"), "title", None, datetime(2024, 1, 1))
    assert dl.session.urls == ["https://api.traderepublic.com/api/v1/doc.pdf"]
    assert len(dl.futures) == 1


def test_document_download_is_bounded_by_the_timeout(tmp_path):
    dl = _make_dl(tmp_path)
    dl.session = _RecordingSession()
    dl.dl_doc(_document("https://api.traderepublic.com/api/v1/doc.pdf"), "title", None, datetime(2024, 1, 1))
    assert dl.session.timeouts == [DOC_DOWNLOAD_TIMEOUT]


class _DocumentResponse:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content


def _finished_download(path, response):
    future = Future()
    future.set_result(response)
    future.filepath = path
    return future


def test_successful_document_response_is_persisted(tmp_path):
    dl = _make_dl(tmp_path)
    path = tmp_path / "Trades" / "doc.pdf"
    dl.futures = [_finished_download(path, _DocumentResponse(200, b"%PDF-1.4"))]
    dl.doc_urls = ["https://api.traderepublic.com/api/v1/doc.pdf"]
    dl.done = 0
    dl.work_responses()
    assert path.read_bytes() == b"%PDF-1.4"
    assert dl.done == 1


def test_non_200_document_response_is_not_persisted(tmp_path):
    dl = _make_dl(tmp_path)
    path = tmp_path / "Trades" / "doc.pdf"
    dl.futures = [_finished_download(path, _DocumentResponse(404, b"<html>not found</html>"))]
    dl.doc_urls = ["https://api.traderepublic.com/api/v1/doc.pdf"]
    dl.done = 0
    dl.work_responses()
    assert not path.exists()
    assert not any(tmp_path.rglob("*.pdf"))
    assert dl.done == 0


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


def test_calculate_delta_applies_in_range_segments():
    tr = _api()
    tr._previous_responses = {"1": "ABCDEFGHIJ"}
    assert tr._calculate_delta("1", "=4\t-2\t=4") == "ABCDGHIJ"
    assert tr._calculate_delta("1", "=10") == "ABCDEFGHIJ"


@pytest.mark.parametrize("delta", ["=-2", "=11", "-11", "=4\t-2\t=-1", "=4\t=-2\t=3"])
def test_calculate_delta_raises_on_out_of_range_length(delta):
    tr = _api()
    tr._previous_responses = {"1": "ABCDEFGHIJ"}
    with pytest.raises(pytr.api.MalformedDeltaError):
        tr._calculate_delta("1", delta)


def test_calculate_delta_skips_unknown_sign_without_advancing_the_offset():
    tr = _api()
    tr._previous_responses = {"1": "ABCDEFGHIJ"}
    assert tr._calculate_delta("1", "=4\tX3\t=2") == "ABCDEF"


def test_trade_republic_error_message_is_payload_free():
    err = pytr.api.TradeRepublicError("7", {"id": "7", "type": "portfolio"}, {"secret": "ACCOUNT-SECRET"})
    assert "ACCOUNT-SECRET" not in str(err)
    assert "7" in str(err) and "portfolio" in str(err)


def test_connect_error_does_not_echo_the_first_frame(monkeypatch):
    class _FakeSocket:
        close_code = None

        async def send(self, message):
            pass

        async def recv(self):
            return "FRAME-SECRET"

        async def close(self):
            pass

    async def connect(*args, **kwargs):
        return _FakeSocket()

    monkeypatch.setattr(pytr.api.websockets, "connect", connect)
    tr = _api()
    with pytest.raises(ValueError) as exc:
        asyncio.run(tr._get_ws())
    assert "FRAME-SECRET" not in str(exc.value)


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
    tr._get_ws = _socket_must_not_open
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


async def _socket_must_not_open():
    raise AssertionError("the read-only guard must run before any websocket I/O")


@pytest.mark.parametrize(
    "payload_type",
    [
        "addToWatchlist",
        "removeFromWatchlist",
        "simpleCreateOrder",
        "cancelOrder",
        "createSavingsPlan",
        "changeSavingsPlan",
        "cancelSavingsPlan",
        "createPriceAlarm",
        "cancelPriceAlarm",
        "subscribeNews",
        "unsubscribeNews",
    ],
)
def test_read_only_subscribe_blocks_mutation_types_before_any_io(payload_type):
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", read_only=True)
    tr._get_ws = _socket_must_not_open
    with pytest.raises(pytr.api.ReadOnlyError):
        asyncio.run(tr.subscribe({"type": payload_type}))
    with pytest.raises(pytr.api.ReadOnlyError):
        tr.blocking_subscribe({"type": payload_type})


def _read_only_api_with_recorded_socket():
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", read_only=True)
    sent = []

    class _FakeSocket:
        async def send(self, message):
            sent.append(message)

    async def get_ws():
        return _FakeSocket()

    tr._get_ws = get_ws
    return tr, sent


def test_read_only_subscribe_still_sends_read_subscriptions():
    tr, sent = _read_only_api_with_recorded_socket()
    subscription_id = asyncio.run(tr.subscribe({"type": "timeline", "after": None}))
    assert sent == [f"sub {subscription_id} " + json.dumps({"type": "timeline", "after": None})]


def test_read_only_savings_plan_parameters_is_still_a_read():
    tr, sent = _read_only_api_with_recorded_socket()
    subscription_id = asyncio.run(tr.savings_plan_parameters("DE000"))
    assert sent == [f"sub {subscription_id} " + json.dumps({"type": "cancelSavingsPlan", "instrumentId": "DE000"})]


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

    def post(url, json=None, timeout=None, headers=None, **kwargs):
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

    def post(url, json=None, timeout=None, headers=None, **kwargs):
        raise ConnectionError("network down")

    tr = _login_api(post)
    with pytest.raises(ConnectionError):
        tr.initiate_weblogin()
    assert tr.pin is None


def test_no_attribute_retains_the_pin_after_login():
    """After login, no attribute of the client object holds the PIN value."""
    tr = _login_api(lambda url, json=None, timeout=None, headers=None, **kwargs: _FakeLoginResponse())
    tr.initiate_weblogin()

    leaks = [name for name, value in vars(tr).items() if value == PIN]
    assert leaks == [], f"PIN retained on attributes: {leaks}"


def test_second_initiate_weblogin_without_pin_raises():
    """Re-login on a consumed client fails loudly instead of POSTing a null pin."""
    calls = []

    def post(url, json=None, timeout=None, headers=None, **kwargs):
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

    def post(url, json=None, timeout=None, headers=None, **kwargs):
        posted.append(url)
        return _FakeLoginResponse()

    tr = _login_api(post)
    tr.initiate_weblogin()
    assert tr.pin is None

    tr.resend_weblogin()  # must not raise
    tr.complete_weblogin("123456")  # must not raise
    assert any("/resend" in u for u in posted)
    assert any(u.endswith("/123456") for u in posted)


# --------------------------------------------------------------------------
# P-8' - v2 push-approval web login, hardened on upstream's v2 code
# --------------------------------------------------------------------------


class _FakeV2LoginResponse:
    """v2 login POST reply: a processId, and no countdown (there is no code)."""

    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"processId": "proc-v2"}


class _FakePollResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def raise_for_status(self):
        pass

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _v2_api(post=None, get=None, waf_token=None):
    """Build a v2 API with stubbed transport (no network, no WAF fetch).

    GET is always stubbed: initiate_weblogin() probes the process once after
    the POST (upstream's shape), and a real GET would leave the machine.
    """
    tr = pytr.api.TradeRepublicApi(
        phone_no="+490000000000",
        pin=PIN,
        waf_token=waf_token,
        read_only=True,
        use_v2_login=True,
    )
    tr._websession.post = post or (lambda url, json=None, timeout=None, headers=None, **kwargs: _FakeV2LoginResponse())
    tr._websession.get = get or (lambda url, headers=None, timeout=None: _FakePollResponse(payload={}))
    return tr


# --- headers, device identity, no ~/.pytr --------------------------------


def test_v2_headers_present_on_login_polls_and_account_reads():
    """Step 8: the required headers ride on the login calls and the account reads, not just the POST."""
    seen = []

    def post(url, json=None, timeout=None, headers=None, **kwargs):
        seen.append(headers or {})
        return _FakeV2LoginResponse()

    def get(url, headers=None, timeout=None):
        seen.append(headers or {})
        return _FakePollResponse(payload={"status": "CONFIRMED"})

    def request(method, url, data=None, headers=None, timeout=None):
        seen.append(headers or {})
        return _FakePollResponse(payload={})

    tr = _v2_api(post=post, get=get)
    tr._websession.request = request
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)
    tr.settings()

    assert len(seen) == 5  # POST, requiredAction probe, approval poll, session refresh, account read
    for h in seen:
        assert h.get("X-TR-Device-Info")
        assert h.get("X-TR-App-Version")
        assert h.get("X-Tr-Platform")


def test_v2_waf_token_travels_as_cookie_and_never_as_plain_header():
    """Upstream carries the solved WAF token as the aws-waf-token cookie."""
    tr = _v2_api(waf_token="waf-token-value")
    tr.initiate_weblogin()
    jar = {c.name: c.value for c in tr._websession.cookies}
    assert jar.get("aws-waf-token") == "waf-token-value"


def test_device_id_is_stable_and_never_persisted(pytr_home):
    """D-A option 1: upstream's stable, never-persisted device identity."""
    a, b = _v2_api(), _v2_api()
    assert a._stable_device_id() == b._stable_device_id()
    assert re.fullmatch(r"[0-9a-f]{128}", a._stable_device_id())

    device_info = a._login_headers()["X-TR-Device-Info"]
    decoded = json.loads(base64.b64decode(device_info))
    assert decoded["stableDeviceId"] == a._stable_device_id()
    assert not pytr_home.exists(), "device identity must not write to disk"


def test_v2_login_never_touches_the_pytr_home_directory(pytr_home):
    """R-104: no ~/.pytr is created or read on the v2 path."""
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "APPROVED"}))
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)

    assert not pytr_home.exists(), "the v2 path wrote under ~/.pytr"


# --- PIN release and the initiate/await split ----------------------------


def test_v2_pin_released_immediately_after_the_post_not_after_approval():
    """P-8.5: the PIN is gone before the up-to-180s approval poll begins."""
    tr = _v2_api()
    assert tr.pin == PIN
    tr.initiate_weblogin()
    assert tr.pin is None


def test_v2_pin_released_even_when_the_post_raises():
    def post(url, json=None, timeout=None, headers=None, **kwargs):
        raise ConnectionError("network down")

    tr = _v2_api(post=post)
    with pytest.raises(ConnectionError):
        tr.initiate_weblogin()
    assert tr.pin is None


def test_v2_second_initiate_weblogin_raises_without_posting():
    calls = []

    def post(url, json=None, timeout=None, headers=None, **kwargs):
        calls.append(url)
        return _FakeV2LoginResponse()

    tr = _v2_api(post=post)
    tr.initiate_weblogin()
    with pytest.raises(ValueError, match="PIN already consumed"):
        tr.initiate_weblogin()
    assert len(calls) == 1


def test_v2_initiate_returns_after_post_and_probe_without_polling():
    """P-8.1 split: initiate does POST + requiredAction probe only; the
    approval poll is a separate operation the caller drives."""
    polls = []

    def get(url, headers=None, timeout=None):
        polls.append(url)
        return _FakePollResponse(payload={"state": "APPROVED"})

    tr = _v2_api(get=get)
    countdown = tr.initiate_weblogin()

    assert countdown == 121  # upstream's countdown fallback (120) + 1
    assert len(polls) == 1, "initiate_weblogin() must not poll for approval"
    assert "/processes/proc-v2" in polls[0]

    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # independently callable
    assert len(polls) == 2


# --- approval outcomes ---------------------------------------------------


@pytest.mark.parametrize("state", ["CONFIRMED", "APPROVED", "COMPLETED", "SUCCESS", "OK", "DONE"])
def test_approval_succeeds_on_each_recognized_state(state):
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": state}))
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


@pytest.mark.parametrize("state", ["CONFIRMED", "COMPLETED"])
def test_approval_accepts_the_states_upstream_reports_under_status(state):
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"status": state}))
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


def test_approval_falls_back_to_state_when_status_is_null():
    tr = _v2_api(
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"status": None, "state": "CONFIRMED"})
    )
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


def test_approval_succeeds_via_the_tr_session_cookie_fallback():
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "PENDING"}))
    tr.initiate_weblogin()
    tr._websession.cookies.set("tr_session", "session-value")
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


def test_approval_ignores_a_tr_session_cookie_that_predates_initiate():
    polls = []

    def get(url, headers=None, timeout=None):
        polls.append(url)
        return _FakePollResponse(payload={"state": "PENDING"})

    tr = _v2_api(get=get)
    tr._websession.cookies.set("tr_session", "stale-session")
    tr.initiate_weblogin()
    polls_before_await = len(polls)
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=0.05, interval_s=0)
    assert len(polls) > polls_before_await, "the poll must run and still not report the login complete"


def test_approval_accepts_a_tr_session_cookie_reissued_after_initiate():
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "PENDING"}))
    tr._websession.cookies.set("tr_session", "stale-session")
    tr.initiate_weblogin()
    tr._websession.cookies.set("tr_session", "fresh-session")
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


@pytest.mark.parametrize("state", ["REJECTED", "DECLINED", "FAILED", "EXPIRED"])
def test_approval_rejection_raises_without_leaking_the_payload(state):
    secret = "session-material-that-must-not-leak"
    tr = _v2_api(
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": state, "token": secret})
    )
    tr.initiate_weblogin()
    with pytest.raises(ValueError) as excinfo:
        tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert state.lower() in str(excinfo.value)
    assert secret not in str(excinfo.value)


@pytest.mark.parametrize("status", [401, 403, 404, 410])
def test_expired_process_status_raises_without_leaking_the_body(status):
    secret = "body-material-that-must-not-leak"
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(status_code=status, text=secret))
    tr.initiate_weblogin()
    with pytest.raises(ValueError) as excinfo:
        tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert str(status) in str(excinfo.value)
    assert secret not in str(excinfo.value)


def test_approval_deadline_raises_timeout_error():
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "PENDING"}))
    tr.initiate_weblogin()
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=0, interval_s=0)


def test_await_approval_before_initiate_raises():
    with pytest.raises(ValueError, match="Initiate web login first"):
        _v2_api().await_web_login_approval(timeout_s=5, interval_s=0)


# --- TOTP accounts are a distinct stage error (D-C) ----------------------


def test_totp_account_raises_distinct_stage_error_before_any_wait():
    secret = "totp-process-material"
    tr = _v2_api(
        get=lambda url, headers=None, timeout=None: _FakePollResponse(
            payload={"requiredAction": "AUTHENTICATOR_VERIFICATION", "token": secret}
        )
    )
    tr.initiate_weblogin()
    assert tr.weblogin_needs_authenticator is True

    with pytest.raises(pytr.api.AuthenticatorRequiredError) as excinfo:
        tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert "authenticator app" in str(excinfo.value)
    assert "not supported" in str(excinfo.value)
    assert secret not in str(excinfo.value)


def test_totp_account_raises_from_complete_weblogin_too():
    tr = _v2_api()
    tr._process_id = "proc-v2"
    tr._required_action = "AUTHENTICATOR_VERIFICATION"
    with pytest.raises(pytr.api.AuthenticatorRequiredError):
        tr.complete_weblogin("")


# --- timeouts and the 180s soft-deadline semantics -----------------------


def test_v2_post_probe_and_poll_all_pass_an_explicit_timeout():
    """D2: no `requests` call on the v2 path may use the infinite default."""
    timeouts = []

    def post(url, json=None, timeout=None, headers=None, **kwargs):
        timeouts.append(timeout)
        return _FakeV2LoginResponse()

    def get(url, headers=None, timeout=None):
        timeouts.append(timeout)
        return _FakePollResponse(payload={"state": "APPROVED"})

    tr = _v2_api(post=post, get=get)
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)

    assert len(timeouts) == 3  # POST + requiredAction probe + approval poll
    assert all(t == pytr.api.DEFAULT_NETWORK_TIMEOUT for t in timeouts)


def test_poll_deadline_is_monotonic_and_gates_the_start_of_each_request(monkeypatch):
    """P-8.3 soft-deadline semantics: a GET started just before the deadline is
    the last one; the *next* deadline check raises. Also proves the loop reads
    the monotonic clock, not the NTP-jumpable wall clock."""
    # Three reads, and no more: deadline, one in-window check, one past it. The
    # loop driving off this iterator to exhaustion IS the proof it reads
    # monotonic; on wall-clock time these ticks would go untouched and the test
    # would hang.
    ticks = iter([0.0, 179.0, 181.0])  # start, last poll start (in), then out
    monkeypatch.setattr("pytr.api.time.monotonic", lambda: next(ticks))

    polls = []

    def get(url, headers=None, timeout=None):
        polls.append(url)
        return _FakePollResponse(payload={"state": "PENDING"})

    tr = _v2_api(get=get)
    tr.initiate_weblogin()  # the requiredAction probe (wall clock only)
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=180, interval_s=0)

    # probe + exactly one in-window approval poll: the GET that started before
    # the deadline is allowed to finish, and nothing starts after it.
    assert len(polls) == 2
    assert next(ticks, None) is None, "the loop must read the monotonic clock exactly as expected"


def test_server_expiry_only_shortens_the_poll_window(monkeypatch):
    """D-B: the 180s cap is min-ed with the server's expiresAt, never extended."""
    monkeypatch.setattr("pytr.api.time.time", lambda: 1_000_000.0)

    def get(url, headers=None, timeout=None):
        # Server says the process expires in 30s; the caller asks for 180s.
        return _FakePollResponse(payload={"state": "PENDING", "expiresAt": 1_000_030.0})

    sleeps = []
    monkeypatch.setattr("pytr.api.time.sleep", lambda s: sleeps.append(s))

    tr = _v2_api(get=get)
    tr.initiate_weblogin()  # probe captures expiresAt

    ticks = iter([0.0, 29.0, 31.0])
    monkeypatch.setattr("pytr.api.time.monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=180, interval_s=0)
    assert next(ticks, None) is None


# --- redaction across a full v2 login (P-8.4/P-8.7) ----------------------


def test_no_secret_material_is_logged_across_a_full_v2_login(caplog, monkeypatch, pytr_home):
    """P-8.4: at DEBUG, across a full account.login(v2=True), no WAF token, session cookie,
    process JSON, device info, PIN, phone or account settings appears in any log record."""
    from pytr import account as account_mod

    waf = "waf-token-secret"
    cookie_value = "tr-session-secret"
    settings_pii = "settings-pii-secret"
    process_payload = {"state": "CONFIRMED", "token": "process-json-secret"}
    device_info = _v2_api()._login_headers()["X-TR-Device-Info"]

    def stubbed_client(**kwargs):
        tr = pytr.api.TradeRepublicApi(**kwargs)
        tr._websession.cookies.set("tr_session", cookie_value)
        tr._websession.post = lambda url, json=None, timeout=None, headers=None, **kwargs: _FakeV2LoginResponse()
        tr._websession.get = lambda url, headers=None, timeout=None: _FakePollResponse(payload=process_payload)
        tr._websession.request = lambda method, url, data=None, headers=None, timeout=None: _FakePollResponse(
            payload={"name": settings_pii}
        )
        return tr

    monkeypatch.setattr(account_mod, "TradeRepublicApi", stubbed_client)
    with _capture_logger(caplog, "api"), _capture_logger(caplog, "account"):
        account_mod.login(phone_no="+490000000000", pin=PIN, waf_token=waf, v2=True)

    assert any(r.name == "api" for r in caplog.records), "DEBUG records of the api logger must be captured"
    assert any(r.name == "account" for r in caplog.records), "records of the account logger must be captured"
    logged = "\n".join(r.getMessage() for r in caplog.records)
    for secret in (waf, cookie_value, "process-json-secret", device_info, PIN, "+490000000000", settings_pii):
        assert secret not in logged, f"secret leaked into logs: {secret!r}"


def test_v2_login_does_not_print_to_stdout(capsys):
    """P-8.7: library code logs; a bare print would corrupt a caller that owns
    stdout as a protocol channel."""
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "APPROVED"}))
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert capsys.readouterr().out == ""


# --- the account.login(v2=True) regression for the P-8.1 split -----------


def test_account_login_v2_drives_initiate_then_await_then_complete(monkeypatch, pytr_home):
    """Without the explicit await_web_login_approval() call, account.login(v2=True)
    would report "Logged in." with no session (P-8.1)."""
    from pytr import account as account_mod

    calls = []

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            calls.append("initiate")
            return 121

        def await_web_login_approval(self):
            calls.append("await")

        def complete_weblogin(self, code):
            calls.append(f"complete:{code!r}")

        def settings(self):
            return {}

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FakeTr())
    account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)

    assert calls == ["initiate", "await", "complete:''"]
    assert not pytr_home.exists()


def test_account_login_v2_exits_when_approval_never_granted(monkeypatch, pytr_home):
    from pytr import account as account_mod

    completed = []

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            return 121

        def await_web_login_approval(self):
            raise TimeoutError("Push approval not received within timeout.")

        def complete_weblogin(self, code):
            completed.append(code)

        def settings(self):
            return {}

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FakeTr())
    with pytest.raises(SystemExit):
        account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    assert completed == [], "login must not report success without an approval"
    assert not pytr_home.exists()


def test_account_login_v2_exits_with_the_totp_stage_error(monkeypatch, pytr_home):
    """D-C: a TOTP account dies at the approval stage with its own message."""
    from pytr import account as account_mod

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            return 121

        def await_web_login_approval(self):
            raise pytr.api.AuthenticatorRequiredError(
                "This account requires an authenticator app; not supported by the sync."
            )

        def complete_weblogin(self, code):
            raise AssertionError("must not finalize a TOTP account")

        def settings(self):
            return {}

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FakeTr())
    with pytest.raises(SystemExit):
        account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    assert not pytr_home.exists()


def test_account_login_explicit_pin_without_store_leaves_pytr_home_untouched(monkeypatch, pytr_home):
    """R-104: explicit phone and PIN without store_credentials neither create ~/.pytr nor save cookies."""
    from pytr import account as account_mod

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            return 121

        def await_web_login_approval(self):
            pass

        def complete_weblogin(self, code):
            pass

        def settings(self):
            return {}

    constructed = []

    def factory(**kwargs):
        constructed.append(kwargs)
        return _FakeTr()

    monkeypatch.setattr(account_mod, "TradeRepublicApi", factory)
    account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)

    assert constructed[0]["save_cookies"] is False
    assert not pytr_home.exists()


class _FrameProbeTr:
    """Stands in for the client; records whether the caller's login frame still holds the PIN."""

    def __init__(self, held):
        self._held = held

    def resume_websession(self):
        return False

    def initiate_weblogin(self):
        caller = sys._getframe(1)
        self._held.append(any(PIN in str(value) for value in caller.f_locals.values()))
        return 121

    def await_web_login_approval(self):
        pass

    def complete_weblogin(self, code):
        pass

    def settings(self):
        return {}


def test_login_frame_drops_the_pin_once_the_client_is_built(monkeypatch, pytr_home):
    from pytr import account as account_mod

    held = []
    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FrameProbeTr(held))
    account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    assert held == [False]
    assert not pytr_home.exists()


def test_login_frame_drops_the_credentials_file_pin_once_the_client_is_built(monkeypatch, pytr_home):
    from pytr import account as account_mod

    secure_write_text(pytr_home / "credentials", f"+490000000000\n{PIN}\n")
    held = []
    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FrameProbeTr(held))
    account_mod.login(v2=True)
    assert held == [False]
    assert sorted(p.name for p in pytr_home.iterdir()) == ["credentials"]


@pytest.mark.parametrize("stage", ["initiate", "await"])
def test_account_login_v2_keeps_the_process_id_out_of_transport_errors(monkeypatch, caplog, pytr_home, stage):
    from pytr import account as account_mod

    transport_error = requests.exceptions.ConnectionError(
        "Max retries exceeded with url: /api/v2/auth/web/login/processes/PROCESS-SECRET"
    )

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            if stage == "initiate":
                raise transport_error
            return 121

        def await_web_login_approval(self):
            raise transport_error

        def complete_weblogin(self, code):
            raise AssertionError("must not finalize after a transport failure")

        def settings(self):
            return {}

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FakeTr())
    with _capture_logger(caplog, "account"):
        with pytest.raises(SystemExit):
            account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "PROCESS-SECRET" not in logged
    assert "ConnectionError" in logged
    assert not pytr_home.exists()


# --------------------------------------------------------------------------
# P-5 - explicit timeouts on every network call outside the streaming recv
# --------------------------------------------------------------------------


class _WafResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _WafSession:
    def __init__(self):
        self.headers = {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(kwargs)
        return _WafResponse({"challenge_type": "unknown"})

    def post(self, url, **kwargs):
        self.calls.append(kwargs)
        return _WafResponse({"token": "waf-token"})


def test_awswaf_requests_all_carry_an_explicit_timeout(monkeypatch):
    from pytr.awswaf.aws import AwsWaf

    session = _WafSession()
    waf = AwsWaf("waf.example", "app.traderepublic.com", "")
    waf.session = session
    waf.get_inputs()
    waf.verify({"solution": "s"}, "unknown")

    multipart_calls = []

    def multipart_post(url, **kwargs):
        multipart_calls.append(kwargs)
        return _WafResponse({"token": "multipart-token"})

    waf._js_config["challenge_types"] = {"mp-hash": "mp_verify"}
    monkeypatch.setattr(requests, "post", multipart_post)
    waf.verify({"solution": "s"}, "mp-hash")

    timeouts = [kwargs.get("timeout") for kwargs in session.calls + multipart_calls]
    assert len(timeouts) == 3
    assert all(timeout == pytr.api.DEFAULT_NETWORK_TIMEOUT for timeout in timeouts)


class _HandshakeSocket:
    close_code = None

    def __init__(self, answer, closed):
        self._answer = answer
        self._closed = closed

    async def send(self, message):
        pass

    async def recv(self):
        if self._answer is None:
            await asyncio.sleep(3600)
        return self._answer

    async def close(self):
        self._closed.append(True)


def _stub_connect(monkeypatch, answer, closed, seen=None):
    async def connect(uri, **kwargs):
        if seen is not None:
            seen.update(kwargs)
        return _HandshakeSocket(answer, closed)

    monkeypatch.setattr(pytr.api.websockets, "connect", connect)


def test_websocket_connect_passes_an_explicit_open_timeout(monkeypatch):
    seen, closed = {}, []
    _stub_connect(monkeypatch, "connected", closed, seen)
    tr = _api()
    asyncio.run(tr._get_ws())
    assert seen["open_timeout"] == pytr.api.DEFAULT_NETWORK_TIMEOUT
    assert closed == []
    assert tr._ws is not None


def test_silent_handshake_is_bounded_closed_and_not_kept(monkeypatch):
    closed = []
    _stub_connect(monkeypatch, None, closed)
    monkeypatch.setattr(pytr.api, "DEFAULT_NETWORK_TIMEOUT", 0.01)
    tr = _api()

    async def bounded_by_the_test():
        return await asyncio.wait_for(tr._get_ws(), 5)

    started = time.monotonic()
    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        asyncio.run(bounded_by_the_test())
    assert time.monotonic() - started < 2, "only the inner network timeout may end the handshake"
    assert closed == [True]
    assert tr._ws is None


def test_unconfirmed_handshake_is_closed_and_not_kept(monkeypatch):
    closed = []
    _stub_connect(monkeypatch, "not-connected", closed)
    tr = _api()
    with pytest.raises(ValueError):
        asyncio.run(tr._get_ws())
    assert closed == [True]
    assert tr._ws is None


# --------------------------------------------------------------------------
# P-3 - Chromium sandbox on by default, off only behind the explicit opt-in
# --------------------------------------------------------------------------


def _fake_playwright(monkeypatch, launches, launch_error=None):
    class _Page:
        def goto(self, url, **kwargs):
            pass

    class _Context:
        def new_page(self):
            return _Page()

        def cookies(self):
            return [{"name": "aws-waf-token", "value": "token-value"}]

    class _Browser:
        def new_context(self):
            return _Context()

        def close(self):
            pass

    class _Chromium:
        def launch(self, **kwargs):
            launches.append(kwargs)
            if launch_error is not None:
                raise launch_error
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _Playwright
    package = types.ModuleType("playwright")
    package.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)


def test_playwright_launch_keeps_the_chromium_sandbox_by_default(monkeypatch):
    launches = []
    _fake_playwright(monkeypatch, launches)
    monkeypatch.delenv("PYTR_ALLOW_NO_SANDBOX", raising=False)
    assert _api()._fetch_waf_token_playwright() == "token-value"
    assert launches[0]["chromium_sandbox"] is True
    assert "--no-sandbox" not in launches[0]["args"]


def test_playwright_launch_drops_the_sandbox_only_behind_the_opt_in(monkeypatch):
    launches = []
    _fake_playwright(monkeypatch, launches)
    monkeypatch.setenv("PYTR_ALLOW_NO_SANDBOX", "1")
    assert _api()._fetch_waf_token_playwright() == "token-value"
    assert launches[0]["chromium_sandbox"] is False
    assert "--no-sandbox" in launches[0]["args"]


# --------------------------------------------------------------------------
# P-8' - login POST errors are mapped and unknown process states fail fast
# --------------------------------------------------------------------------

OUTDATED_APP_VERSION = {"errors": [{"errorCode": "CLIENT_VERSION_OUTDATED", "detail": "BODY-SECRET"}]}


def test_v2_login_post_error_is_mapped_and_keeps_the_status():
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None, **kwargs: _FakePollResponse(426, OUTDATED_APP_VERSION)
    )
    with pytest.raises(ValueError) as excinfo:
        tr.initiate_weblogin()
    message = str(excinfo.value)
    assert message.startswith(pytr.api.LOGIN_ERRORS["CLIENT_VERSION_OUTDATED"])
    assert "HTTP status 426" in message
    assert "BODY-SECRET" not in message


def test_account_login_v2_logs_the_mapped_login_error_and_exits(monkeypatch, caplog, pytr_home):
    from pytr import account as account_mod

    def post(url, json=None, timeout=None, headers=None, **kwargs):
        return _FakePollResponse(426, OUTDATED_APP_VERSION)

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _v2_api(post=post))
    with _capture_logger(caplog, "account"):
        with pytest.raises(SystemExit):
            account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert pytr.api.LOGIN_ERRORS["CLIENT_VERSION_OUTDATED"] in logged
    assert "HTTP status 426" in logged
    assert "BODY-SECRET" not in logged
    assert "Login request failed" not in logged
    assert not pytr_home.exists()


def test_approval_fails_fast_on_an_unrecognised_process_status():
    polls = []

    def get(url, headers=None, timeout=None):
        polls.append(url)
        return _FakePollResponse(payload={"status": "SERVER-INVENTED-STATE"})

    tr = _v2_api(get=get)
    tr.initiate_weblogin()
    polls_before_await = len(polls)
    with pytest.raises(ValueError) as excinfo:
        tr.await_web_login_approval(timeout_s=1, interval_s=0)
    assert len(polls) == polls_before_await + 1, "an unrecognised status must end the wait on its first poll"
    assert "SERVER-INVENTED-STATE" not in str(excinfo.value)


def test_approval_reads_the_status_key_before_the_state_key():
    def get(url, headers=None, timeout=None):
        return _FakePollResponse(payload={"status": "PENDING", "state": "CONFIRMED"})

    tr = _v2_api(get=get)
    tr.initiate_weblogin()
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=0.05, interval_s=0)


def test_playwright_sandbox_start_up_failure_names_the_opt_in(monkeypatch, caplog):
    sandbox_error = RuntimeError("Running as root without --no-sandbox is not supported.")
    _fake_playwright(monkeypatch, [], launch_error=sandbox_error)
    monkeypatch.delenv("PYTR_ALLOW_NO_SANDBOX", raising=False)
    with _capture_logger(caplog, "api"):
        with pytest.raises(RuntimeError):
            _api()._fetch_waf_token_playwright()
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "PYTR_ALLOW_NO_SANDBOX=1" in logged


def test_playwright_other_failures_get_no_sandbox_hint(monkeypatch, caplog):
    _fake_playwright(monkeypatch, [], launch_error=RuntimeError("Target page, context or browser has been closed."))
    monkeypatch.delenv("PYTR_ALLOW_NO_SANDBOX", raising=False)
    with _capture_logger(caplog, "api"):
        with pytest.raises(RuntimeError):
            _api()._fetch_waf_token_playwright()
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "Failed to get AWS WAF token." in logged
    assert "PYTR_ALLOW_NO_SANDBOX" not in logged


def test_v2_login_with_the_default_waf_setting_never_fetches_a_playwright_token(monkeypatch, pytr_home):
    from pytr import account as account_mod

    fetched = []
    monkeypatch.setattr(
        pytr.api.TradeRepublicApi,
        "_fetch_waf_token_playwright",
        lambda self, timeout_ms=30000: fetched.append(timeout_ms),
    )

    def stubbed_client(**kwargs):
        tr = pytr.api.TradeRepublicApi(**kwargs)
        tr._websession.post = lambda url, json=None, timeout=None, headers=None, **kwargs: _FakeV2LoginResponse()
        tr._websession.get = lambda url, headers=None, timeout=None: _FakePollResponse(payload={"status": "CONFIRMED"})
        tr._websession.request = lambda method, url, data=None, headers=None, timeout=None: _FakePollResponse(
            payload={}
        )
        return tr

    monkeypatch.setattr(account_mod, "TradeRepublicApi", stubbed_client)
    tr = account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    assert isinstance(tr, pytr.api.TradeRepublicApi)
    assert fetched == []
    assert not pytr_home.exists()


class _ReplayWebsocket:
    close_code = None

    def __init__(self, frames):
        self._frames = list(frames)

    async def recv(self):
        return self._frames.pop(0)


def test_unmatched_websocket_frame_is_dropped_without_logging_its_content(caplog):
    unmatched = '{"type":"x","secret":"FRAME-SECRET"}'
    ws = _ReplayWebsocket([unmatched, '1 A {"ok":true}'])

    async def get_ws():
        return ws

    tr = _api()
    tr.subscriptions = {"1": {"type": "timeline"}}
    tr._previous_responses = {}
    tr._get_ws = get_ws
    with _capture_logger(caplog, "api"):
        subscription_id, _, payload = asyncio.run(tr._recv_ws())
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert (subscription_id, payload) == ("1", {"ok": True})
    assert "FRAME-SECRET" not in logged
    assert any(r.getMessage().startswith("Dropping websocket message") for r in caplog.records)


def test_unparseable_expires_at_keeps_the_full_poll_window():
    payload = {"state": "PENDING", "expiresAt": "not-a-timestamp"}
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload=payload))
    tr.initiate_weblogin()
    assert tr._clamp_approval_timeout(180) == 180
    assert not tr._weblogin_expired(payload)


def _client_with_saved_session(pytr_home):
    path = pytr_home / "cookies.txt"
    secure_write_text(
        path,
        "# Netscape HTTP Cookie File\n"
        "api.traderepublic.com\tFALSE\t/\tFALSE\t4102444800\ttr_session\tsaved-session\n",
    )
    return pytr.api.TradeRepublicApi(
        phone_no="+490000000000", pin=PIN, waf_token=None, save_cookies=True, cookies_file=path
    )


def _session_cookies(tr):
    return [c.value for c in tr._websession.cookies if c.name == "tr_session"]


@pytest.mark.parametrize(
    "transport_error",
    [
        requests.exceptions.Timeout("the session probe timed out"),
        requests.exceptions.ConnectionError("connection reset"),
    ],
)
def test_resume_keeps_the_saved_session_when_trade_republic_cannot_be_reached(pytr_home, transport_error):
    tr = _client_with_saved_session(pytr_home)

    def failing(url, headers=None, timeout=None):
        raise transport_error

    tr._websession.get = failing
    with pytest.raises(ConnectionError):
        tr.resume_websession()
    assert _session_cookies(tr) == ["saved-session"]


def _response(status, content=b""):
    response = requests.Response()
    response.status_code = status
    response._content = content
    return response


def test_resume_falls_back_to_a_fresh_login_when_the_probe_body_is_not_json(pytr_home):
    tr = _client_with_saved_session(pytr_home)
    tr._websession.get = lambda url, headers=None, timeout=None: _response(200)
    tr._websession.request = lambda method, url, data=None, headers=None, timeout=None: _response(
        200, b"<html>maintenance</html>"
    )
    assert tr.resume_websession() is False
    assert _session_cookies(tr) == []


def test_resume_falls_back_to_a_fresh_login_when_the_session_is_rejected(pytr_home):
    tr = _client_with_saved_session(pytr_home)

    def rejected(url, headers=None, timeout=None):
        raise requests.exceptions.HTTPError("403 Client Error")

    tr._websession.get = rejected
    assert tr.resume_websession() is False
    assert _session_cookies(tr) == []


def test_account_login_stops_when_the_saved_session_cannot_be_verified(monkeypatch, caplog, pytr_home):
    from pytr import account as account_mod

    initiated = []

    class _FakeTr:
        def resume_websession(self):
            raise ConnectionError("Could not reach Trade Republic to verify the saved session.")

        def initiate_weblogin(self):
            initiated.append(True)
            return 121

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FakeTr())
    with _capture_logger(caplog, "account"):
        with pytest.raises(SystemExit):
            account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "Could not reach Trade Republic to verify the saved session." in logged
    assert initiated == [], "an unverifiable session must not start a fresh login"


def test_assert_safe_to_read_skips_mode_bits_where_posix_modes_do_not_apply(tmp_path, monkeypatch):
    f = tmp_path / "cookies"
    f.write_text("x")
    os.chmod(f, 0o644)
    link = tmp_path / "link"
    link.symlink_to(f)
    monkeypatch.setattr("pytr.security._POSIX_MODE_BITS", False)
    assert assert_safe_to_read(f) == f
    with pytest.raises(InsecurePathError):
        assert_safe_to_read(link)


def test_secure_prepare_file_leaves_an_existing_parent_directory_alone(tmp_path):
    parent = tmp_path / "project"
    parent.mkdir()
    os.chmod(parent, 0o755)
    f = secure_prepare_file(parent / "debug.log")
    assert stat.S_IMODE(os.stat(parent).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


def test_secure_prepare_file_does_not_refuse_a_symlinked_parent(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    os.chmod(target, 0o755)
    link = tmp_path / "link"
    link.symlink_to(target)
    f = secure_prepare_file(link / "debug.log")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


def test_secure_prepare_file_creates_a_missing_parent_0700(tmp_path):
    f = secure_prepare_file(tmp_path / "new" / "cookies.txt")
    assert stat.S_IMODE(os.stat(f.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


def test_resume_returns_false_when_the_saved_jar_is_rejected(pytr_home):
    tr = pytr.api.TradeRepublicApi(
        phone_no="+490000000000",
        pin=PIN,
        waf_token=None,
        save_cookies=True,
        cookies_file=pytr_home / "cookies.txt",
    )
    os.chmod(pytr_home / "cookies.txt", 0o644)
    assert tr.resume_websession() is False


def _redirecting_post(seen, status=302):
    def post(url, json=None, timeout=None, headers=None, **kwargs):
        seen.append(kwargs)
        return _FakePollResponse(status)

    return post


def test_login_post_is_not_followed_on_a_redirect():
    seen = []
    tr = _v2_api(post=_redirecting_post(seen))
    with pytest.raises(requests.exceptions.HTTPError):
        tr.initiate_weblogin()
    assert seen[0]["allow_redirects"] is False


def test_session_post_is_not_followed_on_a_redirect():
    seen = []
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", waf_token=None)
    tr._websession.post = _redirecting_post(seen)
    with pytest.raises(requests.exceptions.HTTPError):
        tr._post_session("subject-1")
    assert seen[0]["allow_redirects"] is False


def test_v1_verification_post_is_not_followed_on_a_redirect():
    seen = []
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", waf_token=None)
    tr._process_id = "proc-1"
    tr._websession.post = _redirecting_post(seen)
    with pytest.raises(requests.exceptions.HTTPError):
        tr.complete_weblogin("1234")
    assert seen[0]["allow_redirects"] is False


def test_payout_confirmation_is_not_followed_on_a_redirect(monkeypatch):
    seen = []

    def request(method, url, data=None, headers=None, timeout=None, **kwargs):
        seen.append(kwargs)
        return _FakePollResponse(302)

    monkeypatch.setattr(requests, "request", request)
    tr = pytr.api.TradeRepublicApi(phone_no="+490000000000", pin="0000", waf_token=None)
    with pytest.raises(ValueError):
        tr.confirm_payout("proc-1", "1234")
    assert seen[0]["allow_redirects"] is False
