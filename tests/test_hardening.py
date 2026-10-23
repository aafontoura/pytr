"""Regression tests for the pytr-hardened fork (patches P-1..P-6).

These cover the Denkeeper hardening spec acceptance criteria, notably:
  * AC-P2.1 - glm's two reproduced path-traversal payloads.
  * AC-P6.1 - every mutation method raises before any network I/O.
"""

import asyncio
import base64
import json
import os
import re
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
    tr._websession.post = post or (lambda url, json=None, timeout=None, headers=None: _FakeV2LoginResponse())
    tr._websession.get = get or (lambda url, headers=None, timeout=None: _FakePollResponse(payload={}))
    return tr


# --- headers, device identity, no ~/.pytr --------------------------------


def test_v2_headers_present_on_post_and_every_poll():
    """Step 8: the required headers ride on every v2 call, not just the POST."""
    seen = []

    def post(url, json=None, timeout=None, headers=None):
        seen.append(headers or {})
        return _FakeV2LoginResponse()

    def get(url, headers=None, timeout=None):
        seen.append(headers or {})
        return _FakePollResponse(payload={"status": "CONFIRMED"})

    tr = _v2_api(post=post, get=get)
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)

    assert len(seen) == 3  # POST + requiredAction probe + approval poll
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


def test_device_id_is_stable_and_never_persisted(tmp_path, monkeypatch):
    """D-A option 1: upstream's stable, never-persisted device identity."""
    a, b = _v2_api(), _v2_api()
    assert a._stable_device_id() == b._stable_device_id()
    assert re.fullmatch(r"[0-9a-f]{128}", a._stable_device_id())

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    device_info = a._login_headers()["X-TR-Device-Info"]
    decoded = json.loads(base64.b64decode(device_info))
    assert decoded["stableDeviceId"] == a._stable_device_id()
    assert list(fake_home.iterdir()) == [], "device identity must not write to disk"


def test_v2_login_never_touches_the_pytr_home_directory(tmp_path, monkeypatch):
    """R-104: no ~/.pytr is created or read on the v2 path."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "APPROVED"}))
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)

    assert list(fake_home.iterdir()) == [], "the v2 path wrote under HOME"
    assert not (fake_home / ".pytr").exists()


# --- PIN release and the initiate/await split ----------------------------


def test_v2_pin_released_immediately_after_the_post_not_after_approval():
    """P-8.5: the PIN is gone before the up-to-180s approval poll begins."""
    tr = _v2_api()
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


def test_approval_succeeds_via_the_tr_session_cookie_fallback():
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "PENDING"}))
    tr.initiate_weblogin()
    tr._websession.cookies.set("tr_session", "session-value")
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

    def post(url, json=None, timeout=None, headers=None):
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


def test_no_secret_material_is_logged_across_a_full_v2_login(caplog):
    """P-8.4: at DEBUG, no WAF token, session cookie, process JSON, device
    info or PIN appears in any log record."""
    waf = "waf-token-secret"
    cookie_value = "tr-session-secret"
    process_payload = {"state": "PENDING", "token": "process-json-secret"}

    tr = _v2_api(
        get=lambda url, headers=None, timeout=None: _FakePollResponse(payload=process_payload),
        waf_token=waf,
    )
    device_info = tr._login_headers()["X-TR-Device-Info"]

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
    tr = _v2_api(get=lambda url, headers=None, timeout=None: _FakePollResponse(payload={"state": "APPROVED"}))
    tr.initiate_weblogin()
    tr.await_web_login_approval(timeout_s=5, interval_s=0)
    assert capsys.readouterr().out == ""


# --- the account.login(v2=True) regression for the P-8.1 split -----------


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


def test_account_login_v2_exits_when_approval_never_granted(monkeypatch):
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


def test_account_login_v2_exits_with_the_totp_stage_error(monkeypatch):
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
