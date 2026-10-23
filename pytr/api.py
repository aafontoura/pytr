# MIT License

# Copyright (c) 2020 nborrmann

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import base64
import hashlib
import json
import os
import pathlib
import platform
import re
import ssl
import time
import urllib.parse
import uuid
from collections import deque
from datetime import datetime
from http.cookiejar import Cookie, MozillaCookieJar
from typing import Any, Dict

import certifi
import requests
import websockets
from curl_cffi import requests as cffi_requests

from pytr.security import assert_safe_to_read, secure_dir, secure_prepare_file
from pytr.utils import get_logger

# `playwright` and `pytr.awswaf` are imported lazily inside the two
# `_fetch_waf_token_*` methods, not here. Both are only reachable when the
# caller asks for that specific WAF strategy, and importing them at module
# level made every consumer pay for them unconditionally:
#   - `playwright` is an optional extra (see pyproject). A module-level import
#     makes `import pytr.api` fail outright when it is not installed, which
#     would defeat the point of making it optional.
#   - `pytr.awswaf` reaches the network and reads `webgl.json` from disk at
#     import time (`awswaf/fingerprint.py`). Deferring the import means a
#     deployment that never selects `waf_token="awswaf"` neither performs that
#     file IO nor carries the code in a hot import path.

home = pathlib.Path.home()
BASE_DIR = home / ".pytr"
CREDENTIALS_FILE = BASE_DIR / "credentials"
COOKIES_FILE = BASE_DIR / "cookies.txt"

# P-5: bound WAF / document / login network operations so a hung or hostile
# endpoint cannot pin a worker indefinitely.
DEFAULT_NETWORK_TIMEOUT = 30

# Hosts that `_fetch_waf_token_awswaf` is allowed to talk to. The challenge
# endpoint is scraped out of the login page with a regular expression, so
# whatever `app.traderepublic.com` serves decides where the follow-up requests
# for `/inputs` and `/verify` go — that is a server-side request forgery
# primitive if left unchecked. AWS serves WAF challenge tokens exclusively from
# `*.token.awswaf.com`, so pinning the suffix costs nothing and removes the
# primitive. Comparison is on the parsed host, never on the raw URL string.
_AWSWAF_ALLOWED_HOST_SUFFIX = ".token.awswaf.com"

# errorCodes the v2 login process can answer with, mapped to readable messages.
LOGIN_ERRORS = {
    "PROCESS_GONE": "The login request expired. Please start again.",
    "ALREADY_PROCESSED": "The login request was rejected or has already been used.",
    "NOT_FOUND": "Trade Republic does not know this login request.",
    "TOO_MANY_REQUESTS": "Too many attempts. Please wait before trying again.",
    "VALIDATION_CODE_INVALID": "That authenticator code is not correct.",
    "VALIDATION_CODE_ALREADY_USED": "That authenticator code was already used.",
    "CLIENT_VERSION_OUTDATED": "Trade Republic rejected this app version as outdated. Set PYTR_TR_APP_VERSION.",
}

# Build version of the web frontend. Sent on every api/v2 login call.
# Moves with each frontend deployment; bump when TR starts rejecting stale versions.
APP_VERSION = "2.2631.13"

# The web frontend's API client identifies itself with this platform on all v2 login calls.
WEB_PLATFORM = "web-pro"

# Sent on every request. Trade Republic can start rejecting a stale one as bot traffic.
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

# Trade Republic can invalidate any of the three values above at any time, and none of
# those failures needs a code change to fix, only a different string. Overriding them
# from the environment turns "wait for a pytr release" into "export a variable" for a
# user who is locked out today. See the README for when to reach for which. An unset or
# empty variable keeps the built-in default, so an empty assignment sends no empty header.
ENV_APP_VERSION = "PYTR_TR_APP_VERSION"
ENV_PLATFORM = "PYTR_TR_PLATFORM"
ENV_USER_AGENT = "PYTR_TR_USER_AGENT"

# P-8.3: how long await_web_login_approval() keeps polling, and how long it
# sleeps between polls. This is a poll-*start* deadline (deliberately soft): a
# GET issued just before it may still consume up to 2 x DEFAULT_NETWORK_TIMEOUT
# (requests applies a scalar timeout to connect and read separately), so the
# worst case is deadline + one full request. Callers that need a hard wall-clock
# bound must impose it out of process. Denkeeper derives its parent timeout
# (255s = 180 + 2x30 + 15) from this constant; changing it breaks that derivation.
V2_APPROVAL_TIMEOUT = 180
V2_APPROVAL_POLL_INTERVAL = 2.0

#: Process states that mean the user approved the push in the TR app.
_V2_APPROVED_STATES = ("CONFIRMED", "APPROVED", "COMPLETED", "SUCCESS", "OK", "DONE")
#: Process states that are terminal failures.
_V2_REJECTED_STATES = ("REJECTED", "DECLINED", "FAILED", "EXPIRED")
#: Process state while the push is still waiting for the user.
_V2_PENDING_STATE = "PENDING"

#: D-C: the contract is fixed at push approval with no second secret, so an
#: authenticator (TOTP) account cannot complete this flow. It must fail as its
#: own stage instead of waiting for a code that can never arrive.
_AUTHENTICATOR_REQUIRED_MESSAGE = "This account requires an authenticator app; not supported by the sync."


class AuthenticatorRequiredError(ValueError):
    """Raised when the login needs an authenticator-app code this flow cannot supply (D-C)."""


# Seconds after which the web session is refreshed.
SESSION_REFRESH_INTERVAL = 290


class ReadOnlyError(RuntimeError):
    """Raised when a mutation method is called on a read-only API instance (P-6)."""


class MalformedDeltaError(ValueError):
    """Raised on a malformed websocket delta segment (P-5).

    It aborts the stream with a typed, payload-free error and the caller fails the run.
    """


_MUTATION_SUBSCRIPTION_TYPES = frozenset(
    {
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
    }
)


def account_kind(relationship):
    """The kind of account behind an entry of `relationships()`, e.g. `ADULT` or `LEGAL_ENTITY`."""
    return str(relationship.get("accountType") or relationship.get("relationshipType") or "UNKNOWN")


def account_name(relationship):
    """The name of the account behind an entry of `relationships()`: the account's, else the person's."""
    person = [str(part) for part in (relationship.get("firstName"), relationship.get("lastName")) if part]
    return str(relationship.get("accountName") or " ".join(person))


def _account_selectors(relationship):
    """Everything an entry of `relationships()` can be selected by, lower-cased."""
    selectors = [
        relationship.get("customerId"),
        relationship.get("relationshipType"),
        relationship.get("accountType"),
        relationship.get("firstName"),
        account_name(relationship),
    ]
    return {str(selector).strip().casefold() for selector in selectors if selector and str(selector).strip()}


def _describe_account(relationship):
    name = account_name(relationship)
    return f"{account_kind(relationship)} ({name})" if name else account_kind(relationship)


class TradeRepublicApi:
    _default_headers = {"User-Agent": os.environ.get(ENV_USER_AGENT) or USER_AGENT}
    _host = "https://api.traderepublic.com"
    _waf_login_url = "https://app.traderepublic.com/login"

    _process_id = None
    _required_action = None
    _device_info = None
    _process_expires_at = 0
    _tr_session_at_initiate = None
    _session_expires_at = 0

    _ws = None
    _lock = asyncio.Lock()
    _subscription_id_counter = 1
    _previous_responses: Dict[str, str] = {}
    subscriptions: Dict[str, Dict[str, Any]] = {}

    _credentials_file = CREDENTIALS_FILE
    _cookies_file = COOKIES_FILE

    def __init__(
        self,
        phone_no=None,
        pin=None,
        locale="de",
        save_cookies=False,
        credentials_file=None,
        cookies_file=None,
        use_v2_login=False,
        waf_token="default",
        read_only=False,
    ):
        self.log = get_logger(__name__)
        self._locale = locale
        self._save_cookies = save_cookies
        self._use_v2_login = use_v2_login
        self._waf_token = waf_token
        if self._waf_token == "default":
            self._waf_token = None if self._use_v2_login else "playwright"
        # P-6: when True, every mutation method raises before any network I/O.
        # This reduces accidental exposure only; the server-side TR session
        # remains write-capable (see ADR-0006 / audit H3).
        self._read_only = read_only

        self._credentials_file = pathlib.Path(credentials_file) if credentials_file else CREDENTIALS_FILE

        # P-7: the PIN is consumed exactly once (by the login POST in
        # initiate_weblogin) and the reference is released right after. It is
        # therefore Optional for the whole life of the object after login.
        # NOTE: releasing the reference ends *our* retention; CPython cannot
        # securely erase an immutable str, so the value may still live in freed
        # heap, swap, or a core dump until the process exits.
        self.pin: str | None
        if not (phone_no and pin):
            try:
                # P-1: fail closed on a symlinked or group/other-readable file.
                assert_safe_to_read(self._credentials_file)
                with open(self._credentials_file, "r") as f:
                    lines = f.readlines()
                self.phone_no = lines[0].strip()
                self.pin = lines[1].strip()
            except FileNotFoundError:
                raise ValueError(f"phone_no and pin must be specified explicitly or via {self._credentials_file}")
        else:
            self.phone_no = phone_no
            self.pin = pin

        self._cookies_file = pathlib.Path(cookies_file) if cookies_file else BASE_DIR / f"cookies.{self.phone_no}.txt"

        self._websession = requests.Session()
        self._websession.headers = self._default_headers
        if self._save_cookies:
            # P-1: ensure the cookie jar's directory (0700) and file (0600)
            # exist with safe perms before MozillaCookieJar touches them.
            secure_dir(BASE_DIR)
            secure_prepare_file(self._cookies_file)
            self._websession.cookies = MozillaCookieJar(self._cookies_file)
        self._sec_acc_no: str | None = None
        # Customer id of the account the session acts for, once it is not the login's own.
        self._subject_id: str | None = None
        # Messages read off the websocket on behalf of a caller that has not asked for them yet.
        self._held_back: deque = deque()

    def _guard_read_only(self) -> None:
        """P-6: block mutations on read-only instances before any network I/O."""
        if getattr(self, "_read_only", False):
            raise ReadOnlyError("This TradeRepublicApi instance is read-only; mutation methods are disabled.")

    def _fetch_waf_token_awswaf(self):
        """
        Get the AWS WAF token, using the awswaf library.
        """

        from pytr.awswaf.aws import AwsWaf

        self.log.info("Retrieving AWS WAF token using awswaf...")
        try:
            session = cffi_requests.Session(impersonate="chrome")
            # P-5: bound WAF network operations with explicit timeouts.
            response = session.get(self._waf_login_url, timeout=DEFAULT_NETWORK_TIMEOUT)
            m = re.search(r'src="(https://[^"]+/challenge\.js)"', response.text)
            if not m:
                self.log.warning("AWS WAF token not acquired. challenge.js URL not found in login page.")
                return None
            challenge_js_url = m.group(1)
            # The URL above came out of a regular expression over whatever the
            # login page returned, and everything below turns it into outbound
            # requests. Check the host before the first of them, not after.
            host = urllib.parse.urlparse(challenge_js_url).hostname or ""
            if not host.lower().endswith(_AWSWAF_ALLOWED_HOST_SUFFIX):
                self.log.warning(
                    "AWS WAF token not acquired. challenge.js host is not an AWS WAF endpoint (expected *%s).",
                    _AWSWAF_ALLOWED_HOST_SUFFIX,
                )
                return None
            waf_endpoint = challenge_js_url.split("https://", 1)[1].rsplit("/challenge.js", 1)[0]
            challenge_js = session.get(challenge_js_url, timeout=DEFAULT_NETWORK_TIMEOUT).text
            token = AwsWaf(waf_endpoint, "app.traderepublic.com", challenge_js)()
        except Exception:
            self.log.error("Failed to get AWS WAF token.")
            raise

        if not token:
            self.log.warning("AWS WAF token not acquired. Value is None.")
        return token

    def _fetch_waf_token_playwright(self, timeout_ms: int = 30000):
        """
        Get the AWS WAF token, using a Playwright browser session.

        Requires the optional `playwright` extra plus its browser binary:
            pip install 'pytr[playwright]' && playwright install chromium

        Neither is installed automatically. An earlier version of this method
        caught *every* exception — a network blip, a WAF change, a timeout —
        and answered it by shelling out to `playwright install chromium`, i.e.
        by downloading and executing a browser at runtime, in the process that
        is holding the user's PIN and Trade Republic cookies. That download
        bypasses whatever pinning the installing environment applied to its
        dependencies, and it only ever helped for one of the many failures it
        was triggered by. A missing browser is now reported like any other
        failure and left to the operator to fix deliberately.
        """
        try:
            from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
        except ImportError:
            raise ValueError(
                "playwright is not installed. "
                "Install the optional extra with `pip install 'pytr[playwright]'` "
                "and then run `playwright install chromium`. "
                "Alternatively, use --v2 which does not require a WAF token."
            ) from None

        self.log.info("Retrieving AWS WAF token using Playwright...")

        # P-3: keep Chromium's sandbox ON by default. Disabling it is only
        # allowed via an explicit opt-in env var (e.g. for constrained CI),
        # never silently.
        no_sandbox = os.environ.get("PYTR_ALLOW_NO_SANDBOX") == "1"
        launch_args: list[str] = []
        if no_sandbox:
            self.log.warning("PYTR_ALLOW_NO_SANDBOX=1 set; launching Chromium WITHOUT its sandbox.")
            launch_args = ["--no-sandbox", "--disable-setuid-sandbox"]

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    chromium_sandbox=not no_sandbox,
                    args=launch_args,
                )
                context = browser.new_context()
                page = context.new_page()
                page.goto(
                    "https://app.traderepublic.com/login",
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )
                deadline = time.time() + timeout_ms / 1000
                token = None
                while time.time() < deadline:
                    for c in context.cookies():
                        if c["name"] == "aws-waf-token":
                            token = c["value"]
                            break
                    if token:
                        break
                    time.sleep(0.5)
                browser.close()
        except Exception as e:
            if "Executable doesn't exist" in str(e):
                raise ValueError(
                    "Chromium is not installed. "
                    "Run `playwright install chromium` to download it. "
                    "Alternatively, use --v2 which does not require a WAF token."
                ) from None
            if "sandbox" in str(e).lower():
                self.log.error(
                    "Failed to get AWS WAF token. Chromium could not start its sandbox "
                    "(for example as root in a container); set PYTR_ALLOW_NO_SANDBOX=1 "
                    "to launch it without the sandbox."
                )
            else:
                self.log.error("Failed to get AWS WAF token.")
            raise

        if not token:
            self.log.warning("AWS WAF token not acquired. Value is None.")
        return token

    def _set_waf_cookie(self, token: str):
        """Set the aws-waf-token cookie on the web session."""
        cookie = Cookie(
            version=0,
            name="aws-waf-token",
            value=token,
            port=None,
            port_specified=False,
            domain=".traderepublic.com",
            domain_specified=True,
            domain_initial_dot=True,
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 3600,
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": ""},
        )
        self._websession.cookies.set_cookie(cookie)

    def _stable_device_id(self):
        """An id that stays the same for this installation.

        The web frontend derives it from a canvas fingerprint hashed with SHA-512.
        There is no canvas here, so the hash covers what identifies this machine
        instead. Same length, same alphabet, no state on disk and no request to anyone.
        """
        seed = "|".join([str(uuid.getnode()), platform.node(), platform.machine(), platform.system()])
        return hashlib.sha512(seed.encode()).hexdigest()

    def _timezone_name(self):
        """The IANA name of the local timezone, with the frontend's own fallback."""
        try:
            return str(pathlib.Path("/etc/localtime").resolve()).split("zoneinfo/")[1]
        except (OSError, IndexError):
            return "Etc/UTC"

    def _login_headers(self):
        """The headers Trade Republic requires on the api/v2 login calls.

        Without them the endpoints answer 400 MISSING_REQUIRED_HEADER. The web
        frontend sends the same set on all three of them: a base64-encoded JSON
        description of the device, its build version, the platform its API client is
        configured with, and the language it wants to be answered in.

        Fields the frontend can only fill from a browser are left out rather than
        invented. It omits them itself when the browser doesn't provide them
        (`model` on desktop, `deviceMemory` outside Chromium), so their absence
        is accepted by the server. `screen` is the one value with no counterpart here.
        """
        if self._device_info is None:
            chrome = re.search(r"Chrome/([\d.]+)", self._websession.headers.get("User-Agent", ""))
            offset = datetime.now().astimezone().utcoffset()
            device = {
                "stableDeviceId": self._stable_device_id(),
                "browser": "Chrome",
                "browserVersion": chrome.group(1) if chrome else "",
                "os": platform.system(),
                "osVersion": platform.release(),
                "timezone": self._timezone_name(),
                # JavaScript counts the offset the other way round than Python does.
                "timezoneOffset": -int(offset.total_seconds() // 60) if offset else 0,
                "screen": "1920x1080x24",
                "preferredLanguages": [self._locale],
                "numberOfCores": os.cpu_count() or 1,
            }
            self._device_info = base64.b64encode(json.dumps(device).encode()).decode()
        return {
            "X-TR-Device-Info": self._device_info,
            "X-TR-App-Version": os.environ.get(ENV_APP_VERSION) or APP_VERSION,
            "X-Tr-Platform": os.environ.get(ENV_PLATFORM) or WEB_PLATFORM,
            "Accept-Language": self._locale,
        }

    def initiate_weblogin(self):
        # P-7: the PIN is single-use. It is released as soon as the login POST
        # has been attempted, so a second initiate_weblogin() on the same client
        # has nothing to send and must fail loudly rather than POST a null pin.
        # Re-login requires a NEW client constructed with the PIN again.
        # (resend_weblogin / complete_weblogin / resume_websession never need
        # the PIN: they work off _process_id and the web session cookies.)
        if self.pin is None:
            raise ValueError(
                "PIN already consumed: this TradeRepublicApi client can initiate a web login "
                "only once. Construct a new client with phone_no and pin to log in again."
            )

        self.log.info("Initiating web login...")

        if self._waf_token == "awswaf":
            self._waf_token = self._fetch_waf_token_awswaf()
            if not self._waf_token:
                self.log.warning("No WAF token available.")
        elif self._waf_token == "playwright":
            self._waf_token = self._fetch_waf_token_playwright()
            if not self._waf_token:
                self.log.warning("No WAF token available.")
        elif self._waf_token:
            self.log.info("Using WAF token from arguments.")
        else:
            self.log.info("WAF token skipped.")

        if self._waf_token:
            # P-4: never log the WAF token value.
            self.log.debug("WAF token acquired.")
            self._set_waf_cookie(self._waf_token)

        extra_headers = self._login_headers() if self._use_v2_login else None
        login_path = "/api/v2/auth/web/login" if self._use_v2_login else "/api/v1/auth/web/login"
        try:
            r = self._websession.post(
                f"{self._host}{login_path}",
                json={"phoneNumber": self.phone_no, "pin": self.pin},
                headers=extra_headers,
                # P-5: bound the login POST with an explicit timeout.
                timeout=DEFAULT_NETWORK_TIMEOUT,
            )
        finally:
            # P-7: release the PIN reference as soon as the POST has been
            # attempted (including on a network error, where the PIN may
            # already be on the wire. Retaining it would only widen the window;
            # a retry must build a new client. This does NOT securely erase the
            # string from memory (see __init__).
            self.pin = None

        self.log.debug(f"Web login returned: {r.status_code}")
        if r.status_code == 405 and "awselb" in r.headers.get("server", "").lower():
            hint = (
                f"The request was blocked by the AWS load balancer before reaching Trade Republic "
                f"(server: {r.headers.get('server')}, empty body). "
                "This means the AWS WAF token is missing or was rejected. "
                "Try using --waf-token playwright to obtain a valid token, or switch to --v2 which does not require a WAF token."
            )
            raise ValueError(hint)
        if self._use_v2_login:
            self._raise_for_login_error(r)
        else:
            r.raise_for_status()
        j = r.json()
        # P-4: never log the raw login response (contains processId + PII).
        self.log.debug("Web login response received.")
        try:
            self._process_id = j["processId"]
        except KeyError:
            # P-8.4: surface the machine-readable errorCode only, never the
            # response payload (it carries PII and session material).
            code = None
            try:
                code = j["errors"][0]["errorCode"]
            except (KeyError, IndexError, TypeError):
                pass
            if code:
                raise ValueError(LOGIN_ERRORS.get(str(code), f"Login failed: {code}.")) from None
            raise ValueError("processId not in response.") from None
        if not self._use_v2_login:
            return int(j["countdownInSeconds"]) + 1
        if self._process_id is None:
            raise ValueError("Trade Republic completed the login without a confirmation step.")
        # The second factor is on the login process, not in the login response.
        process = self._get_weblogin_process(quiet=True)
        self._required_action = process.get("requiredAction")
        # D-B: remember the server-side expiry so it can only shorten the
        # approval poll window, never extend it (0 = the server did not say).
        self._process_expires_at = self._weblogin_deadline(process) if process.get("expiresAt") else 0
        self._tr_session_at_initiate = self._tr_session_cookie()
        # v2 does not always send countdownInSeconds; the web frontend falls back to 120s.
        return int(j.get("countdownInSeconds", 120)) + 1

    @property
    def weblogin_needs_authenticator(self):
        """Whether the account needs a code from the user's authenticator app."""
        return self._required_action == "AUTHENTICATOR_VERIFICATION"

    def await_web_login_approval(
        self,
        timeout_s: int = V2_APPROVAL_TIMEOUT,
        interval_s: float = V2_APPROVAL_POLL_INTERVAL,
    ):
        """Block until the TR mobile-app push for this login process is approved.

        Raises :class:`AuthenticatorRequiredError` when the account needs a
        second secret (D-C), ``ValueError`` if the process was rejected or
        expired, and ``TimeoutError`` if no verdict arrived before the poll
        deadline.

        P-8.1: the approval wait is a separate operation from
        :meth:`initiate_weblogin`, so the PIN release (P-7) is strictly before
        the up-to-180s poll and callers get the stage boundary they drive.
        """
        if self.weblogin_needs_authenticator:
            raise AuthenticatorRequiredError(_AUTHENTICATOR_REQUIRED_MESSAGE)
        if not self._process_id:
            raise ValueError("Initiate web login first.")
        self._await_weblogin_confirmation(interval=interval_s, timeout_s=timeout_s)

    def resend_weblogin(self):
        if self._use_v2_login:
            self.log.warning(
                "Trade Republic removed the SMS resend endpoint along with the v1 web login. "
                "Confirm the login in the Trade Republic mobile app instead."
            )
            return
        r = self._websession.post(
            f"{self._host}/api/v1/auth/web/login/{self._process_id}/resend",
            headers=self._default_headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        )
        r.raise_for_status()

    def complete_weblogin(self, verify_code=None):
        if not self._process_id and not self._websession:
            raise ValueError("Initiate web login first.")

        if not self._use_v2_login:
            r = self._websession.post(
                f"{self._host}/api/v1/auth/web/login/{self._process_id}/{verify_code}",
                timeout=DEFAULT_NETWORK_TIMEOUT,
            )
            r.raise_for_status()
            self.save_websession()
            return

        # D-C: an authenticator (TOTP) account cannot complete this flow; there
        # is no channel to deliver the second secret. Fail at the stage that
        # would otherwise wait for a code that can never arrive.
        if self.weblogin_needs_authenticator:
            raise AuthenticatorRequiredError(_AUTHENTICATOR_REQUIRED_MESSAGE)
        if verify_code:
            raise ValueError("v2 web login uses push approval; no verify code is expected.")
        # P-8.1: the approval already happened in await_web_login_approval();
        # this is the post-poll session save and issues no request.
        self.save_websession()

    def _raise_for_login_error(self, r):
        """Raise a readable error, keeping the process id out of the message."""
        if r.status_code < 400:
            return
        try:
            code = r.json()["errors"][0]["errorCode"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ValueError(f"Login failed with status {r.status_code}.") from None
        message = LOGIN_ERRORS.get(code, f"Login failed: {code}.")
        raise ValueError(f"{message} HTTP status {r.status_code}.")

    def _get_weblogin_process(self, quiet=False):
        """Read the state of the current login process."""
        r = self._websession.get(
            f"{self._host}/api/v2/auth/web/login/processes/{self._process_id}",
            headers=self._login_headers(),
            # P-5: bound every login-process poll with an explicit timeout.
            timeout=DEFAULT_NETWORK_TIMEOUT,
        )
        if quiet and r.status_code >= 400:
            return {}
        self._raise_for_login_error(r)
        return r.json()

    def _weblogin_deadline(self, process, fallback=120):
        """Return deadline as a Unix timestamp; fall back to a fixed window."""
        expires_at = process.get("expiresAt")
        try:
            if isinstance(expires_at, (int, float)):
                return expires_at / 1000 if expires_at > 1e11 else float(expires_at)
            return datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            return time.time() + fallback

    def _clamp_approval_timeout(self, timeout_s):
        """D-B: the server's expiresAt may only shorten the poll window, never extend it."""
        if not self._process_expires_at:
            return timeout_s
        return max(0.0, min(float(timeout_s), self._process_expires_at - time.time()))

    def _weblogin_expired(self, process):
        """Whether the server-side expiry of this process has passed (D-B)."""
        if not process.get("expiresAt"):
            return False
        # Unparseable expiry means unknown, not expired.
        return self._weblogin_deadline(process, fallback=float("inf")) <= time.time()

    def _await_weblogin_confirmation(self, interval=2, timeout_s=V2_APPROVAL_TIMEOUT):
        """Poll the login process until confirmed in the Trade Republic mobile app.

        P-8.3: the deadline is a poll-*start* deadline (deliberately soft): a GET
        issued just before it may still run to completion afterwards. It is
        measured on the monotonic clock (the wall clock jumps under NTP
        adjustments) and clamped by the server's expiresAt, which may only
        shorten the window, never extend it (D-B).
        P-8.4: no response payload is ever interpolated into an exception or a
        log record, only the state name and the HTTP status.
        """
        deadline = time.monotonic() + self._clamp_approval_timeout(timeout_s)
        self.log.info("Approve the login in your Trade Republic mobile app (waiting up to %ss)...", timeout_s)
        while time.monotonic() < deadline:
            process = self._get_weblogin_process()
            status = process["status"] if "status" in process else process.get("state")
            state = str(status or "").upper()
            self.log.debug("Login process state: %s", state or "unknown")
            if state in _V2_APPROVED_STATES:
                self.save_websession()
                self.log.info("Login confirmed.")
                return
            if state in _V2_REJECTED_STATES:
                raise ValueError(f"Login process {state.lower()}.")
            if state and state != _V2_PENDING_STATE:
                raise ValueError("Unexpected login process status.")
            if self._weblogin_expired(process):
                raise TimeoutError("The login request expired before approval.")
            # State unknown: a tr_session cookie issued after initiate means the session was granted.
            tr_session = self._tr_session_cookie()
            if tr_session is not None and tr_session != self._tr_session_at_initiate:
                self.save_websession()
                self.log.info("Session cookie detected, login complete.")
                return
            time.sleep(interval)
        raise TimeoutError("Push approval not received within timeout.")

    def _tr_session_cookie(self):
        for c in self._websession.cookies or ():
            if c.name == "tr_session" and c.value:
                return c.value
        return None

    def save_websession(self):
        if self._save_cookies:
            # P-1: (re)assert 0600 perms around the plaintext jar write.
            secure_prepare_file(self._cookies_file)
            # Saves session cookies too (expirydate=0).
            self._websession.cookies.save(ignore_discard=True)
            secure_prepare_file(self._cookies_file)

    def resume_websession(self):
        """
        Use saved cookie file to resume web session
        return success
        """
        self.log.debug("Called resume_websession.")

        # Only attempt to resume if cookies are used and a cookie file exists.
        if self._save_cookies is False or not self._cookies_file.exists():
            return False

        self.log.info("Trying to resume websession...")

        # P-1: fail closed if the jar is a symlink or group/other-readable.
        try:
            assert_safe_to_read(self._cookies_file)
        except OSError:
            return False

        # Loads session cookies too (expirydate=0).
        # P-5/L3: guard the disk-resume path against races / OS errors.
        try:
            self._websession.cookies.load(ignore_discard=True)
        except (FileNotFoundError, OSError):
            self.log.info("Cookie file unavailable; starting fresh session.")
            return False

        try:
            self.log.debug("Calling settings...")
            self.settings()
        except requests.exceptions.HTTPError:
            self.log.info("Resuming websession failed.")
            self.log.debug("Error calling tr.settings().", exc_info=True)
            # in case the websession can not be resumed, start with a fresh set of cookies
            self._websession.cookies.clear()
            return False

        self.log.info("Websession resumed.")
        return True

    def _web_request(self, url_path, payload=None, method="GET"):
        headers = self._login_headers() if self._use_v2_login else None
        if self._session_expires_at < time.time():
            if self._subject_id is None:
                # Refreshing without a subject returns the session to the login's own account.
                # A new process starts here, so it never inherits the account an earlier run chose.
                r = self._websession.get(
                    f"{self._host}/api/v1/auth/web/session", headers=headers, timeout=DEFAULT_NETWORK_TIMEOUT
                )
            else:
                r = self._post_session(self._subject_id)
            r.raise_for_status()
            self._session_expires_at = time.time() + SESSION_REFRESH_INTERVAL
        return self._websession.request(
            method=method, url=f"{self._host}{url_path}", data=payload, headers=headers, timeout=DEFAULT_NETWORK_TIMEOUT
        )

    def _post_session(self, subject_id):
        """Ask for session cookies that act for `subject_id`, the way the web frontend does.

        The frontend uses this call both to switch the account and to refresh the session.
        """
        # P-6: swapping the session's acting account is a session-state mutation.
        self._guard_read_only()
        return self._websession.post(
            f"{self._host}/api/v2/auth/web/session",
            json={"subjectId": subject_id},
            headers=self._login_headers(),
            timeout=DEFAULT_NETWORK_TIMEOUT,
        )

    def relationships(self):
        """List the accounts this login can act for.

        Besides the login's own account (`relationshipType` `SELF`) this is e.g. a
        company account (`LEGAL_ENTITY_ACTOR`).
        """
        r = self._web_request("/api/v1/customer/relationships/detailed")
        r.raise_for_status()
        return r.json().get("relationships") or []

    def _find_relationship(self, account):
        """Pick one relationship by customer id, type or name. `None` picks the login's own account."""
        relationships = self.relationships()
        if account is None:
            matches = [r for r in relationships if r.get("relationshipType") == "SELF"]
            wanted = "Your own account"
        else:
            matches = [r for r in relationships if account.strip().casefold() in _account_selectors(r)]
            wanted = repr(account)
        if len(matches) == 1 and matches[0].get("customerId"):
            return matches[0]
        known = ", ".join(_describe_account(r) for r in relationships) or "none"
        if len(matches) > 1:
            raise ValueError(f"{wanted} matches more than one account, use its customer id. Accounts: {known}.")
        raise ValueError(f"{wanted} was not found among the accounts of this login. Accounts: {known}.")

    def switch_account(self, account=None):
        """Let the session act for another account of this login, e.g. a company account.

        `account` is the account's type (`LEGAL_ENTITY`), its name or its customer id, as listed
        by `relationships()`. `None` switches back to the login's own account. Returns the chosen
        relationship.

        Trade Republic does not address these accounts by a second account number. It hands
        out new session cookies that act for the other customer, so every call made afterwards,
        the websocket included, sees that account only.
        """
        # P-6: swapping the session's acting account is a session-state mutation.
        self._guard_read_only()
        if self._ws is not None and self._ws.close_code is None:
            raise ValueError("Close the websocket connection before switching the account.")

        relationship = self._find_relationship(account)
        r = self._post_session(relationship["customerId"])
        r.raise_for_status()

        is_self = relationship.get("relationshipType") == "SELF"
        self._subject_id = None if is_self else relationship["customerId"]
        self._session_expires_at = time.time() + SESSION_REFRESH_INTERVAL
        # The securities account belongs to the previous account.
        self._sec_acc_no = None
        # The switch replaced the session cookies; keep the saved ones usable for the next run.
        self.save_websession()
        self.log.info(f"Using account: {_describe_account(relationship)}")
        return relationship

    async def _get_ws(self):
        if self._ws and self._ws.close_code is None:
            return self._ws

        self.log.info("Connecting to websocket...")
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        extra_headers = None
        connection_message = {"locale": self._locale}
        connect_id = 21

        # authenticate with cookies, set different connection message and connect ID
        cookie_str = ""
        for cookie in self._websession.cookies:
            # P-5/L2: exact-or-subdomain match so "evil-traderepublic.com" is
            # not treated as a TR cookie.
            if cookie.domain == "traderepublic.com" or cookie.domain.endswith(".traderepublic.com"):
                cookie_str += f"{cookie.name}={cookie.value}; "
        extra_headers = {"Cookie": cookie_str.rstrip("; ")}

        connection_message = {
            "locale": self._locale,
            "platformId": "webtrading",
            "platformVersion": "chrome - 94.0.4606",
            "clientId": "app.traderepublic.com",
            "clientVersion": "5582",
        }
        connect_id = 31

        ws = await websockets.connect(
            "wss://api.traderepublic.com",
            ssl=ssl_context,
            additional_headers=extra_headers,
            open_timeout=DEFAULT_NETWORK_TIMEOUT,
        )
        try:
            await ws.send(f"connect {connect_id} {json.dumps(connection_message)}")
            response = await asyncio.wait_for(ws.recv(), DEFAULT_NETWORK_TIMEOUT)
            if not response == "connected":
                raise ValueError("Connection Error: the websocket did not confirm the connection.")
        except BaseException:
            await ws.close()
            raise

        self._ws = ws
        self.log.info("Connected.")

        return self._ws

    async def close(self):
        """Close the websocket connection gracefully."""
        if self._ws is not None:
            self.log.info("Closing websocket connection...")
            await self._ws.close()
            self._ws = None

    async def _next_subscription_id(self):
        async with self._lock:
            subscription_id = self._subscription_id_counter
            self._subscription_id_counter += 1
            return str(subscription_id)

    async def subscribe(self, payload):
        if isinstance(payload, dict) and payload.get("type") in _MUTATION_SUBSCRIPTION_TYPES:
            self._guard_read_only()
        return await self._send_subscription(payload)

    async def _send_subscription(self, payload):
        subscription_id = await self._next_subscription_id()
        ws = await self._get_ws()
        # P-4: log only the subscription type, not the full payload.
        self.log.debug(
            f"Subscribing id={subscription_id} type={payload.get('type', '?') if isinstance(payload, dict) else '?'}"
        )
        self.subscriptions[subscription_id] = payload
        await ws.send(f"sub {subscription_id} {json.dumps(payload)}")
        return subscription_id

    async def unsubscribe(self, subscription_id):
        ws = await self._get_ws()

        self.log.debug(f"Unsubscribing: {subscription_id}")
        await ws.send(f"unsub {subscription_id}")

        self.subscriptions.pop(subscription_id, None)
        self._previous_responses.pop(subscription_id, None)

    async def recv(self):
        if self._held_back:
            return self._held_back.popleft()
        return await self._recv_ws()

    async def _recv_ws(self):
        ws = await self._get_ws()
        while True:
            response = await ws.recv()
            # P-4: do not log raw websocket messages (financial payloads).
            self.log.debug("Received websocket message (%d bytes).", len(response))

            subscription_id = response[: response.find(" ")]
            code = response[response.find(" ") + 1 : response.find(" ") + 2]
            payload_str = response[response.find(" ") + 2 :].lstrip()

            if subscription_id not in self.subscriptions:
                if code != "C":
                    self.log.debug(f"No active subscription for id {subscription_id}, dropping message")
                continue
            subscription = self.subscriptions[subscription_id]

            if code == "A":
                self._previous_responses[subscription_id] = payload_str
                payload = json.loads(payload_str) if payload_str else {}
                return subscription_id, subscription, payload

            elif code == "D":
                response = self._calculate_delta(subscription_id, payload_str)
                # P-4: do not log the reconstructed financial payload.
                self.log.debug("Reconstructed delta payload (%d bytes).", len(response))

                self._previous_responses[subscription_id] = response
                return subscription_id, subscription, json.loads(response)

            if code == "C":
                self.subscriptions.pop(subscription_id, None)
                self._previous_responses.pop(subscription_id, None)
                continue

            elif code == "E":
                self.log.error("Received error message for subscription %s (%s).", subscription_id, subscription.get("type"))

                await self.unsubscribe(subscription_id)

                payload = json.loads(payload_str) if payload_str else {}
                raise TradeRepublicError(subscription_id, subscription, payload)

    def _calculate_delta(self, subscription_id, delta_payload):
        previous_response = self._previous_responses[subscription_id]
        i, result = 0, []
        for diff in delta_payload.split("\t"):
            # P-5/L1: a malformed length (non-numeric, negative, or past the previous response) from a
            # hostile/buggy backend raises a typed error instead of an arbitrary one. Empty and unknown-sign
            # segments are skipped without advancing the offset.
            if not diff:
                continue
            sign = diff[0]
            if sign == "+":
                result.append(urllib.parse.unquote_plus(diff).strip())
            elif sign == "-" or sign == "=":
                try:
                    length = int(diff[1:])
                except ValueError as e:
                    raise MalformedDeltaError("Malformed delta segment") from None
                if length < 0 or i + length > len(previous_response):
                    raise MalformedDeltaError("Malformed delta segment")
                if sign == "=":
                    result.append(previous_response[i : i + length])
                i += length
        return "".join(result)

    async def _recv_subscription(self, subscription_id):
        while True:
            response_subscription_id, _, response = await self.recv()
            if response_subscription_id == subscription_id:
                return response

    async def _receive_one(self, fut, timeout):
        subscription_id = await fut

        try:
            return await asyncio.wait_for(self._recv_subscription(subscription_id), timeout)
        finally:
            await self.unsubscribe(subscription_id)

    def run_blocking(self, fut, timeout=5.0):
        return asyncio.run(self._receive_one(fut, timeout=timeout))

    async def portfolio(self):
        return await self.subscribe({"type": "portfolio"})

    async def portfolio_status(self):
        return await self.subscribe({"type": "portfolioStatus"})

    async def compact_portfolio(self):
        if self._sec_acc_no is None:
            if self._subject_id is None:
                self.settings()
            else:
                # /api/v2/auth/account answers 400 INVALID_AUTH_ACCOUNT_STATE for any account but
                # the login's own, so the number has to come from the websocket instead.
                self._sec_acc_no = await self._sec_acc_no_from_account_pairs()
        if self._sec_acc_no is None:
            source = "account settings" if self._subject_id is None else "account pairs"
            raise ValueError(f"Could not retrieve securities account number from {source}.")
        return await self.subscribe({"type": "compactPortfolioByType", "secAccNo": self._sec_acc_no})

    async def account_pairs(self):
        return await self.subscribe({"type": "accountPairs"})

    async def _sec_acc_no_from_account_pairs(self, timeout=5.0):
        """Read the securities account number of the account the session acts for."""
        subscription_id = await self.account_pairs()
        try:
            response = await asyncio.wait_for(self._recv_holding_back_others(subscription_id), timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            await self.unsubscribe(subscription_id)
        accounts = [a for a in response.get("accounts") or [] if a.get("securitiesAccountNumber")]
        # Prefer the pair of the default product if the account has more than one.
        accounts.sort(key=lambda a: a.get("productType") != "DEFAULT")
        return accounts[0]["securitiesAccountNumber"] if accounts else None

    async def _recv_holding_back_others(self, subscription_id):
        """Wait for one subscription's answer; keep the answers to others for the next `recv()`."""
        while True:
            message = await self._recv_ws()
            if message[0] == subscription_id:
                return message[2]
            self._held_back.append(message)

    async def watchlist(self):
        return await self.subscribe({"type": "watchlist"})

    async def cash(self):
        return await self.subscribe({"type": "cash"})

    async def available_cash_for_payout(self):
        return await self.subscribe({"type": "availableCashForPayout"})

    async def portfolio_history(self, timeframe):
        return await self.subscribe({"type": "portfolioAggregateHistory", "range": timeframe})

    async def instrument_details(self, isin):
        return await self.subscribe({"type": "instrument", "id": isin})

    async def instrument_suitability(self, isin):
        return await self.subscribe({"type": "instrumentSuitability", "instrumentId": isin})

    async def stock_details(self, isin):
        return await self.subscribe({"type": "stockDetails", "id": isin})

    async def add_watchlist(self, isin):
        return await self.subscribe({"type": "addToWatchlist", "instrumentId": isin})

    async def remove_watchlist(self, isin):
        return await self.subscribe({"type": "removeFromWatchlist", "instrumentId": isin})

    async def ticker(self, isin, exchange="LSX"):
        return await self.subscribe({"type": "ticker", "id": f"{isin}.{exchange}"})

    async def performance(self, isin, exchange="LSX"):
        return await self.subscribe({"type": "performance", "id": f"{isin}.{exchange}"})

    async def performance_history(self, isin, timeframe, exchange="LSX", resolution=None):
        parameters = {
            "type": "aggregateHistory",
            "id": f"{isin}.{exchange}",
            "range": timeframe,
        }
        if resolution:
            parameters["resolution"] = resolution
        return await self.subscribe(parameters)

    async def experience(self):
        return await self.subscribe({"type": "experience"})

    async def motd(self):
        return await self.subscribe({"type": "messageOfTheDay"})

    async def neon_cards(self):
        return await self.subscribe({"type": "neonCards"})

    async def timeline(self, after=None):
        return await self.subscribe({"type": "timeline", "after": after})

    async def timeline_detail(self, timeline_id):
        return await self.subscribe({"type": "timelineDetail", "id": timeline_id})

    async def timeline_detail_order(self, order_id):
        return await self.subscribe({"type": "timelineDetail", "orderId": order_id})

    async def timeline_detail_savings_plan(self, savings_plan_id):
        return await self.subscribe({"type": "timelineDetail", "savingsPlanId": savings_plan_id})

    async def timeline_transactions(self, after=None):
        return await self.subscribe({"type": "timelineTransactions", "after": after})

    async def timeline_activity_log(self, after=None):
        return await self.subscribe({"type": "timelineActivityLog", "after": after})

    async def timeline_detail_v2(self, timeline_id):
        return await self.subscribe({"type": "timelineDetailV2", "id": timeline_id})

    async def search_tags(self):
        return await self.subscribe({"type": "neonSearchTags"})

    async def search_suggested_tags(self, query):
        return await self.subscribe({"type": "neonSearchSuggestedTags", "data": {"q": query}})

    async def search(
        self,
        query,
        asset_type="stock",
        page=1,
        page_size=20,
        aggregate=False,
        only_savable=False,
        filter_index=None,
        filter_country=None,
        filter_sector=None,
        filter_region=None,
    ):
        search_parameters = {
            "q": query,
            "filter": [{"key": "type", "value": asset_type}],
            "page": page,
            "pageSize": page_size,
        }
        if only_savable:
            search_parameters["filter"].append({"key": "attribute", "value": "savable"})
        if filter_index:
            search_parameters["filter"].append({"key": "index", "value": filter_index})
        if filter_country:
            search_parameters["filter"].append({"key": "country", "value": filter_country})
        if filter_region:
            search_parameters["filter"].append({"key": "region", "value": filter_region})
        if filter_sector:
            search_parameters["filter"].append({"key": "sector", "value": filter_sector})

        search_type = "neonSearch" if not aggregate else "neonSearchAggregations"
        return await self.subscribe({"type": search_type, "data": search_parameters})

    async def search_derivative(self, underlying_isin, product_type):
        return await self.subscribe(
            {
                "type": "derivatives",
                "underlying": underlying_isin,
                "productCategory": product_type,
            }
        )

    async def order_overview(self):
        return await self.subscribe({"type": "orders"})

    async def price_for_order(self, isin, exchange, order_type):
        return await self.subscribe(
            {
                "type": "priceForOrder",
                "parameters": {
                    "exchangeId": exchange,
                    "instrumentId": isin,
                    "type": order_type,
                },
            }
        )

    async def cash_available_for_order(self):
        return await self.subscribe({"type": "availableCash"})

    async def size_available_for_order(self, isin, exchange):
        return await self.subscribe(
            {
                "type": "availableSize",
                "parameters": {"exchangeId": exchange, "instrumentId": isin},
            }
        )

    async def limit_order(
        self,
        isin,
        exchange,
        order_type,
        size,
        limit,
        expiry,
        expiry_date=None,
        warnings_shown=None,
    ):
        parameters = {
            "type": "simpleCreateOrder",
            "clientProcessId": str(uuid.uuid4()),
            "warningsShown": warnings_shown if warnings_shown else [],
            "parameters": {
                "instrumentId": isin,
                "exchangeId": exchange,
                "expiry": {"type": expiry},
                "limit": limit,
                "mode": "limit",
                "size": size,
                "type": order_type,
            },
        }
        if expiry == "gtd" and expiry_date:
            parameters["parameters"]["expiry"]["value"] = expiry_date

        return await self.subscribe(parameters)

    async def market_order(
        self,
        isin,
        exchange,
        order_type,
        size,
        expiry,
        sell_fractions,
        expiry_date=None,
        warnings_shown=None,
    ):
        parameters = {
            "type": "simpleCreateOrder",
            "clientProcessId": str(uuid.uuid4()),
            "warningsShown": warnings_shown if warnings_shown else [],
            "parameters": {
                "instrumentId": isin,
                "exchangeId": exchange,
                "expiry": {"type": expiry},
                "mode": "market",
                "sellFractions": sell_fractions,
                "size": size,
                "type": order_type,
            },
        }
        if expiry == "gtd" and expiry_date:
            parameters["parameters"]["expiry"]["value"] = expiry_date

        return await self.subscribe(parameters)

    async def stop_market_order(
        self,
        isin,
        exchange,
        order_type,
        size,
        stop,
        expiry,
        expiry_date=None,
        warnings_shown=None,
    ):
        parameters = {
            "type": "simpleCreateOrder",
            "clientProcessId": str(uuid.uuid4()),
            "warningsShown": warnings_shown if warnings_shown else [],
            "parameters": {
                "instrumentId": isin,
                "exchangeId": exchange,
                "expiry": {"type": expiry},
                "mode": "stopMarket",
                "size": size,
                "stop": stop,
                "type": order_type,
            },
        }
        if expiry == "gtd" and expiry_date:
            parameters["parameters"]["expiry"]["value"] = expiry_date

        return await self.subscribe(parameters)

    async def cancel_order(self, order_id):
        return await self.subscribe({"type": "cancelOrder", "orderId": order_id})

    async def savings_plan_overview(self):
        return await self.subscribe({"type": "savingsPlans"})

    async def savings_plan_parameters(self, isin):
        return await self._send_subscription({"type": "cancelSavingsPlan", "instrumentId": isin})

    async def create_savings_plan(
        self,
        isin,
        amount,
        interval,
        start_date,
        start_date_type,
        start_date_value,
        warnings_shown=None,
    ):
        parameters = {
            "type": "createSavingsPlan",
            "warningsShown": warnings_shown if warnings_shown else [],
            "parameters": {
                "amount": amount,
                "instrumentId": isin,
                "interval": interval,
                "startDate": {
                    "nextExecutionDate": start_date,
                    "type": start_date_type,
                    "value": start_date_value,
                },
            },
        }
        return await self.subscribe(parameters)

    async def change_savings_plan(
        self,
        savings_plan_id,
        isin,
        amount,
        interval,
        start_date,
        start_date_type,
        start_date_value,
        warnings_shown=None,
    ):
        parameters = {
            "id": savings_plan_id,
            "type": "changeSavingsPlan",
            "warningsShown": warnings_shown if warnings_shown else [],
            "parameters": {
                "amount": amount,
                "instrumentId": isin,
                "interval": interval,
                "startDate": {
                    "nextExecutionDate": start_date,
                    "type": start_date_type,
                    "value": start_date_value,
                },
            },
        }
        return await self.subscribe(parameters)

    async def cancel_savings_plan(self, savings_plan_id):
        return await self.subscribe({"type": "cancelSavingsPlan", "id": savings_plan_id})

    async def price_alarm_overview(self):
        return await self.subscribe({"type": "priceAlarms"})

    async def create_price_alarm(self, isin, price):
        return await self.subscribe({"type": "createPriceAlarm", "instrumentId": isin, "targetPrice": price})

    async def cancel_price_alarm(self, price_alarm_id):
        return await self.subscribe({"type": "cancelPriceAlarm", "id": price_alarm_id})

    async def news(self, isin):
        return await self.subscribe({"type": "neonNews", "isin": isin})

    async def news_subscriptions(self):
        return await self.subscribe({"type": "newsSubscriptions"})

    async def subscribe_news(self, isin):
        return await self.subscribe({"type": "subscribeNews", "instrumentId": isin})

    async def unsubscribe_news(self, isin):
        return await self.subscribe({"type": "unsubscribeNews", "instrumentId": isin})

    def payout(self, amount):
        self._guard_read_only()
        return requests.request(
            method="POST",
            url=f"{self._host}/api/v1/payout",
            data={"amount": amount},
            headers=self._default_headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        ).json()

    def confirm_payout(self, process_id, code):
        self._guard_read_only()
        r = requests.request(
            method="POST",
            url=f"{self._host}/api/v1/payout/{process_id}/code",
            data={"code": code},
            headers=self._default_headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        )

        if r.status_code != 200:
            # P-4/H3: do not echo the raw server error body.
            raise ValueError(f"Payout failed with status {r.status_code}")

    def settings(self):
        r = self._web_request("/api/v2/auth/account")
        r.raise_for_status()
        data = r.json()
        if self._sec_acc_no is None and "securitiesAccountNumber" in data:
            self._sec_acc_no = data["securitiesAccountNumber"]
        return data

    def order_cost(self, isin, exchange, order_mode, order_type, size, sell_fractions):
        return requests.request(
            method="GET",
            url=f"{self._host}/api/v1/user/costtransparency?instrumentId={isin}&exchangeId={exchange}&mode={order_mode}&type={order_type}&size={size}&sellFractions={sell_fractions}",
            data=None,
            headers=self._default_headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        ).text

    def savings_plan_cost(self, isin, amount, interval):
        return requests.request(
            method="GET",
            url=f"{self._host}/api/v1/user/savingsplancosttransparency?instrumentId={isin}&amount={amount}&interval={interval}",
            data=None,
            headers=self._default_headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        ).text

    def __getattr__(self, name):
        if name[:9] == "blocking_":
            attr = object.__getattribute__(self, name[9:])
            if hasattr(attr, "__call__"):
                return lambda *args, **kwargs: self.run_blocking(
                    timeout=kwargs.pop("timeout", 5), fut=attr(*args, **kwargs)
                )
        return object.__getattribute__(self, name)


class TradeRepublicError(ValueError):
    def __init__(self, subscription_id, subscription, error_message):
        super().__init__(
            f"Trade Republic returned an error for subscription {subscription_id} ({subscription.get('type')})."
        )
        self.subscription_id = subscription_id
        self.subscription = subscription
        self.error = error_message
