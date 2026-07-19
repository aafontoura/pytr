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
import json
import os
import pathlib
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.parse
import uuid
from http.cookiejar import Cookie, MozillaCookieJar
from typing import Any, Dict

import certifi
import requests
import websockets
from curl_cffi import requests as cffi_requests
from playwright.sync_api import sync_playwright

from pytr.awswaf.aws import AwsWaf
from pytr.security import (
    assert_safe_to_read,
    secure_dir,
    secure_prepare_file,
)
from pytr.utils import get_logger

home = pathlib.Path.home()
BASE_DIR = home / ".pytr"
CREDENTIALS_FILE = BASE_DIR / "credentials"
COOKIES_FILE = BASE_DIR / "cookies.txt"

# P-5: bound WAF / document / login network operations so a hung or hostile
# endpoint cannot pin a worker indefinitely.
DEFAULT_NETWORK_TIMEOUT = 30

# --- v2 web login (P-8, absorbed from upstream PR #355) ---------------------
# Values captured from app.traderepublic.com on 2026-05-29. Used only when the
# caller opts into the v2 push-approval flow. Overridable via env vars because a
# TR bump to the web app version re-breaks login with HTTP 426 until the
# constant is updated; the override is the documented hotfix, and the constant
# is re-pinned at the next absorb.
TR_WEB_APP_VERSION = os.environ.get("PYTR_TR_APP_VERSION", "15.7.0")
TR_WEB_USER_AGENT_V2 = os.environ.get(
    "PYTR_TR_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
)
TR_V1_LOGIN_PATH = "/api/v1/auth/web/login"
TR_V2_LOGIN_PATH = "/api/v2/auth/web/login"

# P-8.3: how long await_web_login_approval() keeps polling, and how long it
# sleeps between polls. This is a poll-*start* deadline (deliberately soft): a
# GET issued just before it may still consume a full DEFAULT_NETWORK_TIMEOUT, so
# the worst case is deadline + one network timeout. Callers that need a hard
# wall-clock bound must impose it out of process.
V2_APPROVAL_TIMEOUT = 180
V2_APPROVAL_POLL_INTERVAL = 2.0

#: Process states that mean the user approved the push in the TR app.
_V2_APPROVED_STATES = ("APPROVED", "COMPLETED", "SUCCESS", "OK", "DONE")
#: Process states that are terminal failures.
_V2_REJECTED_STATES = ("REJECTED", "DECLINED", "FAILED", "EXPIRED")


class ReadOnlyError(RuntimeError):
    """Raised when a mutation method is called on a read-only API instance (P-6)."""


class MalformedDeltaError(ValueError):
    """Raised on a malformed websocket delta segment so the recv loop can reconnect (P-5)."""


class TradeRepublicApi:
    _default_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    }
    _host = "https://api.traderepublic.com"
    _waf_login_url = "https://app.traderepublic.com/login"

    _process_id = None
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
        waf_token="playwright",
        read_only=False,
        use_v2_login=False,
    ):
        self.log = get_logger(__name__)
        self._locale = locale
        self._save_cookies = save_cookies
        self._waf_token = waf_token
        self._use_v2_login = use_v2_login
        # P-8.2 (D1): the v2 flow needs a 64-hex device id. Upstream persists it
        # to ~/.pytr/device_id; we generate it per instance and hold it in memory
        # only, so nothing is ever written under ~/.pytr on the v2 path (R-104).
        # 64 hex chars of CSPRNG output, matching the web app's shape — not a
        # doubled 32-hex half, whose repeated halves would be a fingerprint.
        self._device_id = secrets.token_hex(32)
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

    def _guard_read_only(self) -> None:
        """P-6: block mutations on read-only instances before any network I/O."""
        if getattr(self, "_read_only", False):
            raise ReadOnlyError("This TradeRepublicApi instance is read-only; mutation methods are disabled.")

    def _fetch_waf_token_awswaf(self):
        """
        Get the AWS WAF token, using the awswaf library.
        """

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

        One-time setup needed:
            playwright install chromium
        """

        self.log.info("Retrieving AWS WAF token using Playwright...")

        # P-3: keep Chromium's sandbox ON by default. Disabling it is only
        # allowed via an explicit opt-in env var (e.g. for constrained CI),
        # never silently.
        launch_args: list[str] = []
        if os.environ.get("PYTR_ALLOW_NO_SANDBOX") == "1":
            self.log.warning("PYTR_ALLOW_NO_SANDBOX=1 set; launching Chromium WITHOUT its sandbox.")
            launch_args = ["--no-sandbox", "--disable-setuid-sandbox"]

        called_playwright_install = False
        while True:
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(
                        headless=True,
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
                done = True
            except Exception as e:
                if called_playwright_install:
                    self.log.error("Failed to get AWS WAF token.")
                    raise
                else:
                    self.log.warning("%s", e)
                    self.log.info('Running "playwright install chromium"...')
                    called_playwright_install = True
                    done = False
                    # P-3: invoke playwright via the current interpreter, never a
                    # PATH-resolved binary.
                    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
                    self.log.info("Calling Playwright once more...")
            if done:
                break

        if not token:
            self.log.warning("AWS WAF token not acquired. Value is None.")
        return token

    def _build_device_info_header(self) -> str:
        """Build the base64(JSON) x-tr-device-info payload the web app sends.

        P-8.2: ``stableDeviceId`` is this instance's in-memory id — nothing is
        read from or written to ``~/.pytr``.
        """
        payload = {
            "stableDeviceId": self._device_id,
            "model": "Apple Macintosh",
            "browser": "Chrome",
            "browserVersion": "148.0.0.0",
            "os": "Mac OS",
            "osVersion": "10.15.7",
            "timezone": "Europe/Amsterdam",
            "timezoneOffset": -120,
            "screen": "1800x1169x30",
            "preferredLanguages": ["en", "en-US"],
            "numberOfCores": 12,
            "deviceMemory": 16,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _auth_headers(self) -> Dict[str, str]:
        """Headers required by /api/v2/auth/web/login (v2 push-approval flow)."""
        headers = {
            "User-Agent": TR_WEB_USER_AGENT_V2,
            "Origin": "https://app.traderepublic.com",
            "Referer": "https://app.traderepublic.com/",
            "x-tr-platform": "web",
            "x-tr-app-version": TR_WEB_APP_VERSION,
            "x-tr-device-info": self._build_device_info_header(),
        }
        if self._waf_token:
            headers["x-aws-waf-token"] = self._waf_token
        return headers

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

    def initiate_weblogin(self):
        # P-7: the PIN is single-use. It is released as soon as the login POST
        # has been attempted, so a second initiate_weblogin() on the same client
        # has nothing to send and must fail loudly rather than POST a null pin.
        # Re-login requires a NEW client constructed with the PIN again.
        # (resend_weblogin / complete_weblogin / resume_websession never need
        # the PIN — they work off _process_id and the web session cookies.)
        if self.pin is None:
            raise ValueError(
                "PIN already consumed: this TradeRepublicApi client can initiate a web login "
                "only once. Construct a new client with phone_no and pin to log in again."
            )

        self.log.info("Initiating web login...")

        if self._waf_token == "awswaf":
            self._waf_token = self._fetch_waf_token_awswaf()
        elif self._waf_token == "playwright":
            self._waf_token = self._fetch_waf_token_playwright()
        elif self._waf_token:
            self.log.info("Using WAF token from arguments.")

        if self._waf_token:
            # P-4: never log the WAF token value.
            self.log.debug("WAF token acquired.")
            self._set_waf_cookie(self._waf_token)
        else:
            self.log.warning("No WAF token available.")

        login_path = TR_V2_LOGIN_PATH if self._use_v2_login else TR_V1_LOGIN_PATH
        extra_headers = self._auth_headers() if self._use_v2_login else None

        try:
            r = self._websession.post(
                f"{self._host}{login_path}",
                json={"phoneNumber": self.phone_no, "pin": self.pin},
                headers=extra_headers,
                timeout=DEFAULT_NETWORK_TIMEOUT,
            )
        finally:
            # P-7: release the PIN reference as soon as the POST has been
            # attempted — including on a network error, where the PIN may
            # already be on the wire. Retaining it would only widen the window;
            # a retry must build a new client. This does NOT securely erase the
            # string from memory (see __init__).
            self.pin = None

        self.log.debug(f"Web login returned: {r.status_code}")
        r.raise_for_status()
        j = r.json()
        # P-4: never log the raw login response (contains processId + PII).
        self.log.debug("Web login response received.")
        try:
            self._process_id = j["processId"]
        except KeyError:
            err = j.get("errors")
            if err:
                raise ValueError(str(err))
            else:
                raise ValueError("processId not in reponse")

        if not self._use_v2_login:
            return int(j["countdownInSeconds"]) + 1

        # P-8.1: v2 uses push-to-approve in the TR mobile app — there is no code
        # and no countdown. Unlike upstream, this method does NOT poll for the
        # approval: it returns as soon as the POST has succeeded, and the caller
        # drives await_web_login_approval() as a separate step. That split keeps
        # the approval wait a distinct operation (the downstream child protocol
        # needs the boundary) and puts the P-7 PIN release strictly before the
        # up-to-180s poll rather than after it.
        return 0

    def await_web_login_approval(
        self,
        timeout_s: int = V2_APPROVAL_TIMEOUT,
        interval_s: float = V2_APPROVAL_POLL_INTERVAL,
    ):
        """Block until the TR mobile-app push for this login process is approved.

        Raises ``ValueError`` if the process was rejected/expired and
        ``TimeoutError`` if no verdict arrived before the poll deadline.

        P-8.3: the deadline is monotonic (upstream uses wall-clock ``time.time()``,
        which jumps under NTP adjustment) and gates the *start* of each poll, so a
        GET issued just before it may still run for one DEFAULT_NETWORK_TIMEOUT.
        P-8.4: no response payload is ever interpolated into an exception or a log
        record — only the state name and the HTTP status.
        """
        if not self._process_id:
            raise ValueError("Initiate web login first.")
        url = f"{self._host}{TR_V2_LOGIN_PATH}/processes/{self._process_id}"
        deadline = time.monotonic() + timeout_s
        # P-8.7: library code logs, it does not print (a bare print would also
        # corrupt a caller that owns stdout as a protocol channel).
        self.log.info("Approve the login in your Trade Republic mobile app (waiting up to %ss)...", timeout_s)
        while time.monotonic() < deadline:
            r = self._websession.get(
                url,
                headers=self._auth_headers(),
                timeout=DEFAULT_NETWORK_TIMEOUT,
            )
            if r.status_code == 200:
                try:
                    j = r.json()
                except ValueError:
                    j = {}
                state = str(j.get("state") or j.get("status") or "").upper()
                if state in _V2_APPROVED_STATES:
                    self.save_websession()
                    self.log.info("Push approved.")
                    return
                if state in _V2_REJECTED_STATES:
                    raise ValueError(f"Login process {state.lower()}.")
                # State unknown but session cookie present? Treat as approved.
                # Safe only because the jar starts empty for a fresh client
                # (save_cookies=False and resume_websession() never called).
                for c in self._websession.cookies:
                    if c.name == "tr_session" and c.value:
                        self.save_websession()
                        self.log.info("Session cookie detected, login complete.")
                        return
            elif r.status_code in (401, 403, 404, 410):
                raise ValueError(f"Login process rejected or expired (HTTP {r.status_code}).")
            else:
                self.log.warning("Login poll returned HTTP %s.", r.status_code)
            time.sleep(interval_s)
        raise TimeoutError("Push approval not received within timeout.")

    def resend_weblogin(self):
        path = TR_V2_LOGIN_PATH if self._use_v2_login else TR_V1_LOGIN_PATH
        headers = self._auth_headers() if self._use_v2_login else self._default_headers
        r = self._websession.post(
            f"{self._host}{path}/{self._process_id}/resend",
            headers=headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        )
        r.raise_for_status()

    def complete_weblogin(self, verify_code):
        if not self._process_id and not self._websession:
            raise ValueError("Initiate web login first.")

        # v2 push flow: approval already happened in await_web_login_approval().
        # An empty verify_code signals nothing left to do.
        if self._use_v2_login and not verify_code:
            self.save_websession()
            return

        path = TR_V2_LOGIN_PATH if self._use_v2_login else TR_V1_LOGIN_PATH
        headers = self._auth_headers() if self._use_v2_login else None
        r = self._websession.post(
            f"{self._host}{path}/{self._process_id}/{verify_code}",
            headers=headers,
            timeout=DEFAULT_NETWORK_TIMEOUT,
        )
        r.raise_for_status()
        self.save_websession()

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
        if self._session_expires_at < time.time():
            r = self._websession.get(f"{self._host}/api/v1/auth/web/session")
            r.raise_for_status()
            self._session_expires_at = time.time() + 290
        return self._websession.request(method=method, url=f"{self._host}{url_path}", data=payload)

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

        self._ws = await websockets.connect(
            "wss://api.traderepublic.com", ssl=ssl_context, additional_headers=extra_headers
        )
        await self._ws.send(f"connect {connect_id} {json.dumps(connection_message)}")
        response = await self._ws.recv()

        if not response == "connected":
            raise ValueError(f"Connection Error: {response}")

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
                self.log.error(f"Received error message: {response!r}")

                await self.unsubscribe(subscription_id)

                payload = json.loads(payload_str) if payload_str else {}
                raise TradeRepublicError(subscription_id, subscription, payload)

    def _calculate_delta(self, subscription_id, delta_payload):
        previous_response = self._previous_responses[subscription_id]
        i, result = 0, []
        for diff in delta_payload.split("\t"):
            # P-5/L1: a malformed segment (empty, or non-numeric length) from a
            # hostile/buggy backend must not crash the recv loop.
            if not diff:
                continue
            sign = diff[0]
            if sign == "+":
                result.append(urllib.parse.unquote_plus(diff).strip())
            elif sign == "-" or sign == "=":
                try:
                    length = int(diff[1:])
                except ValueError as e:
                    raise MalformedDeltaError(f"Malformed delta segment: {diff!r}") from e
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
            self.settings()
        if self._sec_acc_no is None:
            raise ValueError("Could not retrieve securities account number from account settings.")
        return await self.subscribe({"type": "compactPortfolioByType", "secAccNo": self._sec_acc_no})

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
        self._guard_read_only()
        return await self.subscribe({"type": "addToWatchlist", "instrumentId": isin})

    async def remove_watchlist(self, isin):
        self._guard_read_only()
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
        self._guard_read_only()
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
        self._guard_read_only()
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
        self._guard_read_only()
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
        self._guard_read_only()
        return await self.subscribe({"type": "cancelOrder", "orderId": order_id})

    async def savings_plan_overview(self):
        return await self.subscribe({"type": "savingsPlans"})

    async def savings_plan_parameters(self, isin):
        return await self.subscribe({"type": "cancelSavingsPlan", "instrumentId": isin})

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
        self._guard_read_only()
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
        self._guard_read_only()
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
        self._guard_read_only()
        return await self.subscribe({"type": "cancelSavingsPlan", "id": savings_plan_id})

    async def price_alarm_overview(self):
        return await self.subscribe({"type": "priceAlarms"})

    async def create_price_alarm(self, isin, price):
        self._guard_read_only()
        return await self.subscribe({"type": "createPriceAlarm", "instrumentId": isin, "targetPrice": price})

    async def cancel_price_alarm(self, price_alarm_id):
        self._guard_read_only()
        return await self.subscribe({"type": "cancelPriceAlarm", "id": price_alarm_id})

    async def news(self, isin):
        return await self.subscribe({"type": "neonNews", "isin": isin})

    async def news_subscriptions(self):
        return await self.subscribe({"type": "newsSubscriptions"})

    async def subscribe_news(self, isin):
        self._guard_read_only()
        return await self.subscribe({"type": "subscribeNews", "instrumentId": isin})

    async def unsubscribe_news(self, isin):
        self._guard_read_only()
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
        ).text

    def savings_plan_cost(self, isin, amount, interval):
        return requests.request(
            method="GET",
            url=f"{self._host}/api/v1/user/savingsplancosttransparency?instrumentId={isin}&amount={amount}&interval={interval}",
            data=None,
            headers=self._default_headers,
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
        self.subscription_id = subscription_id
        self.subscription = subscription
        self.error = error_message
