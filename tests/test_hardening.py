"""Regression tests for the pytr-hardened fork (patches P-1..P-6).

These cover the Denkeeper hardening spec acceptance criteria, notably:
  * AC-P2.1 - glm's two reproduced path-traversal payloads.
  * AC-P6.1 - every mutation method raises before any network I/O.
"""

import asyncio
import base64
import json
import os
import stat
from pathlib import Path

import pytest
from pathvalidate import sanitize_filepath

from pytr.api import (
    DEFAULT_NETWORK_TIMEOUT,
    TR_WEB_APP_VERSION,
    MalformedDeltaError,
    ReadOnlyError,
    TradeRepublicApi,
)
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
    dl.filepaths = []
    dl.doc_urls = []
    dl.doc_urls_history = []
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


def test_base_behavior_is_vulnerable_title_dotdot(tmp_path):
    """Documents the base 24163dc vulnerability: `..` title escapes output."""
    output = tmp_path / "out"
    output.mkdir()
    # Reproduce the base (pre-patch) path build: unsanitized title used as dir.
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
    from datetime import datetime

    dl.dl_doc(doc, "..", None, datetime(2024, 1, 1, 9, 0))
    for p in dl.filepaths:
        assert Path(p).resolve().is_relative_to(output.resolve())


def test_patch_contains_docid_traversal_payload(tmp_path):
    """glm payload #2: doc id `../../../etc/evil` is neutralised."""
    output = tmp_path / "out"
    output.mkdir()
    dl = _make_dl(output)
    doc = {
        "id": "../../../etc/evil",
        "title": "Kontoauszug",
        "detail": "",
        "action": {"payload": "https://api.traderepublic.com/api/v1/doc.pdf"},
    }
    from datetime import datetime

    # Force the collision path branch so the doc id enters the filename.
    dl.filepaths.append(str(sanitize_filepath(output / "Abschlüsse" / "20240101" / "Kontoauszug.pdf", "_", "auto")))
    dl.dl_doc(doc, "Kontoauszug", None, datetime(2024, 1, 1, 9, 0))
    for p in dl.filepaths:
        assert Path(p).resolve().is_relative_to(output.resolve())


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


def _api() -> TradeRepublicApi:
    return TradeRepublicApi(phone_no="+490000000000", pin="0000")


def test_calculate_delta_skips_empty_segment():
    tr = _api()
    tr._previous_responses = {"1": "hello world"}
    assert tr._calculate_delta("1", "\t=5") == "hello"


def test_calculate_delta_raises_on_non_numeric_length():
    tr = _api()
    tr._previous_responses = {"1": "hello"}
    with pytest.raises(MalformedDeltaError):
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
]


@pytest.mark.parametrize("method,args", ASYNC_MUTATIONS)
def test_async_mutation_blocked_in_read_only(method, args):
    tr = TradeRepublicApi(phone_no="+490000000000", pin="0000", read_only=True)
    with pytest.raises(ReadOnlyError):
        asyncio.run(getattr(tr, method)(*args))


@pytest.mark.parametrize("method,args", SYNC_MUTATIONS)
def test_sync_mutation_blocked_in_read_only(method, args):
    tr = TradeRepublicApi(phone_no="+490000000000", pin="0000", read_only=True)
    with pytest.raises(ReadOnlyError):
        getattr(tr, method)(*args)


def test_read_only_defaults_false():
    tr = TradeRepublicApi(phone_no="+490000000000", pin="0000")
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
    tr = TradeRepublicApi(phone_no="+490000000000", pin=PIN, waf_token=None, read_only=True)
    tr._websession.post = post
    return tr


def test_pin_is_sent_once_then_released(tmp_path):
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


# --------------------------------------------------------------------------
# P-8 - v2 push-approval web login (absorbed upstream #355 + D1/D2/D3 fixes)
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

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _v2_api(post=None, get=None, waf_token=None):
    """Build a v2 API with stubbed transport (no network, no WAF fetch)."""
    tr = TradeRepublicApi(
        phone_no="+490000000000",
        pin=PIN,
        waf_token=waf_token,
        read_only=True,
        use_v2_login=True,
    )
    if post is not None:
        tr._websession.post = post
    if get is not None:
        tr._websession.get = get
    return tr


# --- §4.1 / §4.2: headers, endpoint, device info, no ~/.pytr ---------------


def test_v2_login_posts_to_v2_path_with_required_headers():
    seen = {}

    def post(url, json=None, timeout=None, headers=None):
        seen["url"] = url
        seen["headers"] = headers or {}
        return _FakeV2LoginResponse()

    tr = _v2_api(post=post, waf_token="waf-token-value")
    tr.initiate_weblogin()

    assert seen["url"].endswith("/api/v2/auth/web/login")
    assert "/api/v1/" not in seen["url"]
    h = seen["headers"]
    assert h["x-tr-platform"] == "web"
    assert h["x-tr-app-version"] == TR_WEB_APP_VERSION
    assert h["x-tr-device-info"]
    assert h["x-aws-waf-token"] == "waf-token-value"
    assert h["Origin"] == "https://app.traderepublic.com"
    assert h["Referer"] == "https://app.traderepublic.com/"


def test_v2_waf_header_absent_when_no_token():
    seen = {}

    def post(url, json=None, timeout=None, headers=None):
        seen["headers"] = headers or {}
        return _FakeV2LoginResponse()

    _v2_api(post=post, waf_token=None).initiate_weblogin()
    assert "x-aws-waf-token" not in seen["headers"]


def test_v1_login_still_uses_the_v1_path_and_no_v2_headers():
    """Regression: the opt-in flag off means byte-identical v1 behavior."""
    seen = {}

    def post(url, json=None, timeout=None, headers=None):
        seen["url"] = url
        seen["headers"] = headers
        return _FakeLoginResponse()

    tr = _login_api(post)
    assert tr.initiate_weblogin() == 31  # v1 still returns the countdown
    assert seen["url"].endswith("/api/v1/auth/web/login")
    assert seen["headers"] is None


def test_device_info_decodes_and_carries_the_in_memory_device_id():
    tr = _v2_api()
    decoded = json.loads(base64.b64decode(tr._build_device_info_header()))
    assert decoded["stableDeviceId"] == tr._device_id
    assert len(tr._device_id) == 64
    assert all(c in "0123456789abcdef" for c in tr._device_id)
    assert decoded["model"] and decoded["browser"] and decoded["os"]


def test_device_id_is_per_instance_and_not_a_doubled_half():
    a, b = _v2_api(), _v2_api()
    assert a._device_id != b._device_id  # D1: not a stable per-install value
    # A doubled 32-hex half would be a fork-specific fingerprint.
    assert a._device_id[:32] != a._device_id[32:]


def test_v2_login_never_touches_the_pytr_home_directory(tmp_path, monkeypatch):
    """D1 / R-104: no ~/.pytr is created or read on the v2 path."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "APPROVED"}),
    )
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)

    assert list(fake_home.iterdir()) == [], "the v2 path wrote under HOME"
    assert not (fake_home / ".pytr").exists()


# --- §4.3 / §4.5: PIN release, split, approval outcomes --------------------


def test_v2_pin_released_immediately_after_the_post_not_after_approval():
    """P-8.5: the PIN is gone before the up-to-180s approval poll begins."""
    tr = _v2_api(post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse())
    assert tr.pin == PIN
    tr.initiate_weblogin()
    assert tr.pin is None


def test_v2_pin_released_even_when_the_post_raises():
    def post(url, json=None, timeout=None, headers=None):
        raise ConnectionError("network down")

    tr = _v2_api(post=post)
    with pytest.raises(ConnectionError):
        tr.initiate_weblogin()
    assert tr.pin is None


def test_v2_second_initiate_weblogin_raises_without_posting():
    calls = []

    def post(url, json=None, timeout=None, headers=None):
        calls.append(url)
        return _FakeV2LoginResponse()

    tr = _v2_api(post=post)
    tr.initiate_weblogin()
    with pytest.raises(ValueError, match="PIN already consumed"):
        tr.initiate_weblogin()
    assert len(calls) == 1


def test_v2_initiate_returns_after_the_post_without_polling():
    """P-8.1: the split — initiate does NOT drive the approval poll."""
    polls = []

    def get(url, headers=None, timeout=None):
        polls.append(url)
        return _FakePollResponse(payload={"state": "APPROVED"})

    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=get,
    )
    assert tr.initiate_weblogin() == 0  # no countdown on the v2 path
    assert polls == [], "initiate_weblogin() must not poll for approval"

    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # independently callable
    assert len(polls) == 1
    assert "/processes/proc-v2" in polls[0]


@pytest.mark.parametrize("state", ["APPROVED", "COMPLETED", "SUCCESS", "OK", "DONE"])
def test_approval_succeeds_on_each_recognized_state(state):
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": state}),
    )
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


def test_approval_succeeds_via_the_tr_session_cookie_fallback():
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "PENDING"}),
    )
    tr.initiate_weblogin()
    tr._websession.cookies.set("tr_session", "session-value")
    tr.await_web_login_approval(timeout_s=5, interval_s=0)  # must not raise


@pytest.mark.parametrize("state", ["REJECTED", "DECLINED", "FAILED", "EXPIRED"])
def test_approval_rejection_raises_without_leaking_the_payload(state):
    secret = "session-material-that-must-not-leak"
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": state, "token": secret}),
    )
    tr.initiate_weblogin()
    with pytest.raises(ValueError) as excinfo:
        tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert state.lower() in str(excinfo.value)
    assert secret not in str(excinfo.value)


@pytest.mark.parametrize("status", [401, 403, 404, 410])
def test_expired_process_status_raises_without_leaking_the_body(status):
    secret = "body-material-that-must-not-leak"
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(status_code=status, text=secret),
    )
    tr.initiate_weblogin()
    with pytest.raises(ValueError) as excinfo:
        tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert str(status) in str(excinfo.value)
    assert secret not in str(excinfo.value)


def test_approval_deadline_raises_timeout_error():
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "PENDING"}),
    )
    tr.initiate_weblogin()
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=0, interval_s=0)


def test_await_approval_before_initiate_raises():
    with pytest.raises(ValueError, match="Initiate web login first"):
        _v2_api().await_web_login_approval(timeout_s=5, interval_s=0)


# --- §4.4: explicit timeouts and a monotonic, poll-start deadline ----------


def test_v2_login_post_and_poll_get_pass_an_explicit_timeout():
    """D2: no `requests` call on the v2 path may use the infinite default."""
    timeouts = []

    def post(url, json=None, timeout=None, headers=None):
        timeouts.append(timeout)
        return _FakeV2LoginResponse()

    def get(url, headers=None, timeout=None):
        timeouts.append(timeout)
        return _FakePollResponse(payload={"state": "APPROVED"})

    tr = _v2_api(post=post, get=get)
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)

    assert len(timeouts) == 2
    assert all(t == DEFAULT_NETWORK_TIMEOUT for t in timeouts)


def test_poll_deadline_is_monotonic_and_gates_the_start_of_each_request(monkeypatch):
    """P-8.3 soft-deadline semantics: a GET started just before the deadline is
    the last one; the *next* deadline check raises. Also proves the loop reads
    the monotonic clock, not the NTP-jumpable wall clock."""
    # Three reads, and no more: deadline, one in-window check, one past it. The
    # loop driving off this iterator to exhaustion IS the proof it reads
    # monotonic — on wall-clock time these ticks would go untouched and the
    # deadline (now + 180s real seconds) would never be reached, hanging the test.
    ticks = iter([0.0, 179.0, 181.0])  # start, last poll start (in), then out
    monkeypatch.setattr("pytr.api.time.monotonic", lambda: next(ticks))

    polls = []

    def get(url, headers=None, timeout=None):
        polls.append(url)
        return _FakePollResponse(payload={"state": "PENDING"})

    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=get,
    )
    tr.initiate_weblogin()
    with pytest.raises(TimeoutError):
        tr.await_web_login_approval(timeout_s=180, interval_s=0)

    assert len(polls) == 1, "the GET started before the deadline must be allowed to finish"
    assert next(ticks, None) is None, "the loop must read the monotonic clock exactly as expected"


# --- §4.7: redaction across a full v2 login --------------------------------


def test_no_secret_material_is_logged_across_a_full_v2_login(caplog):
    """P-8.4: at DEBUG, no process JSON, device-info, WAF token, or session
    cookie value appears in any log record."""
    waf = "waf-token-secret"
    cookie_value = "tr-session-secret"
    process_payload = {"state": "PENDING", "token": "process-json-secret"}

    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload=process_payload),
        waf_token=waf,
    )
    device_info = tr._build_device_info_header()

    with caplog.at_level("DEBUG"):
        tr.initiate_weblogin()
        tr._websession.cookies.set("tr_session", cookie_value)
        tr.await_web_login_approval(timeout_s=5, interval_s=0)

    logged = "\n".join(r.getMessage() for r in caplog.records)
    for secret in (waf, cookie_value, "process-json-secret", device_info, PIN):
        assert secret not in logged, f"secret leaked into logs: {secret!r}"


def test_v2_login_does_not_print_to_stdout(capsys):
    """P-8.7: library code logs; a bare print would corrupt a caller that owns
    stdout as a protocol channel."""
    tr = _v2_api(
        post=lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse(),
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "APPROVED"}),
    )
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert capsys.readouterr().out == ""


# --- §4.9: the CLI/account-helper regression for the P-8.1 split -----------


def test_account_login_v2_drives_initiate_then_await_then_complete(monkeypatch):
    """Without the explicit await_web_login_approval() call, account.login(v2=True)
    would report "Logged in." with no session (P-8.1)."""
    from pytr import account as account_mod

    calls = []

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            calls.append("initiate")
            return 0

        def await_web_login_approval(self):
            calls.append("await")

        def complete_weblogin(self, code):
            calls.append(f"complete:{code!r}")

        def settings(self):
            return {}

    monkeypatch.setattr(account_mod, "TradeRepublicApi", lambda **kw: _FakeTr())
    account_mod.login(phone_no="+490000000000", pin=PIN, v2=True)

    assert calls == ["initiate", "await", "complete:''"]


def test_account_login_v2_exits_when_approval_never_granted(monkeypatch):
    from pytr import account as account_mod

    completed = []

    class _FakeTr:
        def resume_websession(self):
            return False

        def initiate_weblogin(self):
            return 0

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
