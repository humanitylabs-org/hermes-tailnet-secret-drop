#!/usr/bin/env python3
"""Tailnet-only, one-time, write-only secret entry for Hermes.

The browser can submit a new value but no HTTP or CLI surface can retrieve one.
The random capability that authorizes one intake lives only in the URL fragment,
so it never reaches the server in a request line; the browser replays it in a
fixed custom header. Only its SHA-256 digest is ever written to disk.
Secrets are validated before an atomic update of the configured Hermes .env.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import html
import json
import math
import os
import re
import secrets
import socket
import socketserver
import ssl
import stat
import tempfile
import threading
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener, urlopen

APP_VERSION = "1.1.0"
USER_AGENT = f"Hermes-Tailnet-Secret-Drop/{APP_VERSION}"
DEFAULT_TTL_MINUTES = 15
MAX_TTL_MINUTES = 15
CLEANUP_INTERVAL_SECONDS = 30
TOMBSTONE_KEEP_HOURS = 24
MAX_SECRET_BYTES = 64 * 1024
MAX_BODY_BYTES = MAX_SECRET_BYTES + 4096
MAX_ENV_BYTES = 10 * 1024 * 1024
MAX_CALENDAR_BYTES = 16 * 1024 * 1024
TOKEN_HEADER = "X-Secret-Drop-Token"
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")
REQUEST_ID_RE = re.compile(r"[0-9a-f]{64}")
ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{2,127}")
LIFECYCLE_LOCK_NAME = "lifecycle.lock"
SECRET_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASS",
    "_URL",
    "_URI",
    "_CREDENTIAL",
)
DANGEROUS_KEYS = {
    "BASH_ENV",
    "ENV",
    "HOME",
    "IFS",
    "PATH",
    "PROMPT_COMMAND",
    "PYTHONHOME",
    "PYTHONPATH",
    "SHELL",
    "SHELLOPTS",
}
DANGEROUS_PREFIXES = ("LD_", "SUDO_", "SYSTEMD_", "XDG_")
CLIENT_SCRIPT = """(() => {
  const TOKEN_HEADER = 'X-Secret-Drop-Token';
  const found = /^#token=([A-Za-z0-9_-]{32,128})$/.exec(window.location.hash || '');
  const capability = found ? found[1] : '';
  if (found && window.history && window.history.replaceState) {
    window.history.replaceState(null, '', window.location.pathname);
  }

  const heading = document.getElementById('heading');
  const feedback = document.getElementById('feedback');
  const form = document.getElementById('secret-form');
  const input = document.getElementById('secret');
  const label = document.getElementById('secret-label');
  const submit = document.getElementById('submit');
  const countdown = document.getElementById('countdown');
  const reveal = document.getElementById('reveal-secret');
  const slash = document.getElementById('eye-slash');
  let finished = false;
  let progressLabel = 'Saving\\u2026';

  const setFeedback = (message) => {
    feedback.textContent = message || '';
    feedback.hidden = !message;
  };

  const finish = (title, message) => {
    finished = true;
    form.hidden = true;
    countdown.hidden = true;
    heading.textContent = title;
    setFeedback(message);
  };

  reveal.addEventListener('click', () => {
    const showing = input.type === 'password';
    input.type = showing ? 'text' : 'password';
    reveal.setAttribute('aria-label', showing ? 'Hide value' : 'Show value');
    reveal.setAttribute('title', showing ? 'Hide value' : 'Show value');
    slash.hidden = !showing;
    input.focus({preventScroll: true});
  });

  const startCountdown = (seconds) => {
    const deadline = performance.now() + Math.max(0, seconds) * 1000;
    countdown.hidden = false;
    const tick = () => {
      if (finished) return;
      const remaining = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
      const minutes = Math.floor(remaining / 60);
      countdown.textContent = `${minutes}:${String(remaining % 60).padStart(2, '0')}`;
      if (remaining <= 0) {
        input.value = '';
        finish('Expired', 'This Secret Drop link is no longer valid. Ask for a new one.');
        return;
      }
      window.setTimeout(tick, 250);
    };
    tick();
  };

  const api = (path, options) => {
    const settings = Object.assign({cache: 'no-store', credentials: 'omit', redirect: 'error'}, options || {});
    settings.headers = Object.assign({}, settings.headers || {}, {[TOKEN_HEADER]: capability});
    return window.fetch(path, settings).then((response) =>
      response.json().catch(() => ({})).then((data) => ({ok: response.ok, data: data || {}}))
    );
  };

  if (!capability) {
    finish('Not found', 'Open the whole Secret Drop link, including the part after the # symbol.');
    return;
  }

  api('/api/request', {method: 'GET'}).then(({ok, data}) => {
    if (!ok) {
      finish(data.title || 'Not found', data.error || '');
      return;
    }
    const name = data.label || 'Secret';
    heading.textContent = name;
    label.textContent = name;
    input.setAttribute('aria-label', name);
    document.title = name + ' \\u00b7 Hermes Secret Drop';
    submit.textContent = data.submit_label || 'Save';
    progressLabel = data.progress_label || 'Saving\\u2026';
    form.hidden = false;
    input.focus({preventScroll: true});
    startCountdown(Number(data.expires_in_seconds || 0));
  }).catch(() => finish('Unavailable', 'The Secret Drop service could not be reached.'));

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (finished) return;
    const value = input.value;
    if (!value) {
      setFeedback('Enter the value to save.');
      return;
    }
    submit.disabled = true;
    setFeedback(progressLabel);
    api('/api/secret', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({secret: value})
    }).then(({ok, data}) => {
      input.value = '';
      if (ok) {
        finish(data.result === 'discarded' ? 'Done' : 'Saved', data.note || '');
        return;
      }
      submit.disabled = false;
      if (data.retry) {
        setFeedback(data.error || 'That value was not accepted. Try again.');
        input.focus({preventScroll: true});
        return;
      }
      finish(data.title || 'Not saved', data.error || '');
    }).catch(() => {
      input.value = '';
      submit.disabled = false;
      setFeedback('The value could not be sent. Try again.');
    });
  });
})();"""
CLIENT_SCRIPT_SHA256 = base64.b64encode(hashlib.sha256(CLIENT_SCRIPT.encode("utf-8")).digest()).decode("ascii")
SECURITY_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src 'sha256-{CLIENT_SCRIPT_SHA256}'; connect-src 'self'; form-action 'none'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
}


class SecretDropError(Exception):
    """A safe user-facing failure with no secret material."""

    def __init__(self, message: str, status: int = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.message = message
        self.status = int(status)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def default_state_dir() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "hermes-tailnet-secret-drop"


def default_config_path() -> Path:
    return default_state_dir() / "config.json"


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise SecretDropError("Secret Drop state path is not a private directory.", HTTPStatus.INTERNAL_SERVER_ERROR)
    os.chmod(path, 0o700)


def fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_private_dir(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
        fsync_directory(path.parent)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError as exc:
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretDropError("Secret Drop state could not be read.", HTTPStatus.INTERNAL_SERVER_ERROR) from exc
    if not isinstance(payload, dict):
        raise SecretDropError("Secret Drop state is invalid.", HTTPStatus.INTERNAL_SERVER_ERROR)
    return payload


def load_config(path: Path) -> dict[str, Any]:
    config = load_json(path)
    required = ("state_dir", "env_path", "socket_path", "public_base_url")
    if any(not isinstance(config.get(key), str) or not config[key] for key in required):
        raise SecretDropError("Secret Drop is not configured correctly.", HTTPStatus.INTERNAL_SERVER_ERROR)
    base = config["public_base_url"].rstrip("/")
    parsed = urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".ts.net")
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise SecretDropError("Secret Drop must use a private Tailscale HTTPS URL.", HTTPStatus.INTERNAL_SERVER_ERROR)
    config["public_base_url"] = base
    return config


def request_origin(config: dict[str, Any]) -> str:
    """Return the scheme + authority of the configured public base URL."""
    parsed = urlsplit(str(config["public_base_url"]).rstrip("/"))
    if not parsed.scheme or not parsed.netloc:
        raise SecretDropError("Secret Drop is not configured correctly.", HTTPStatus.INTERNAL_SERVER_ERROR)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def origin_matches(config: dict[str, Any], header_value: str | None) -> bool:
    """Accept only an Origin header exactly equal to the configured origin."""
    if not header_value:
        return False
    candidate = header_value.strip()
    if not candidate or candidate.lower() == "null" or any(character.isspace() for character in candidate):
        return False
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        return False
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}" == request_origin(config)


def validate_env_key(key: str) -> str:
    key = key.strip()
    if not ENV_KEY_RE.fullmatch(key):
        raise SecretDropError("The requested environment key is not allowed.")
    if key in DANGEROUS_KEYS or key.startswith(DANGEROUS_PREFIXES):
        raise SecretDropError("The requested environment key is not allowed.")
    if not key.endswith(SECRET_SUFFIXES):
        raise SecretDropError("The environment key must clearly represent a secret, token, password, or private URL.")
    return key


def validate_label(label: str) -> str:
    label = " ".join(label.strip().split())
    if not label or len(label) > 160 or any(ord(char) < 32 for char in label):
        raise SecretDropError("The request label is invalid.")
    return label


def quote_dotenv_value(value: str) -> str:
    """Return a literal python-dotenv value with interpolation disabled by quoting."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def normalize_secret(value: str) -> str:
    value = value.strip()
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise SecretDropError("Enter a valid UTF-8 value.") from exc
    if not value or len(encoded) > MAX_SECRET_BYTES or any(char in value for char in "\r\n\x00"):
        raise SecretDropError("Enter one non-empty value without line breaks.")
    if "${" in value:
        raise SecretDropError("This value contains a dotenv interpolation sequence and cannot be stored safely.")
    return value


def validate_opaque(value: str) -> str:
    """Check syntax only: one non-empty single-line value that is safe to store."""
    return normalize_secret(value)


def validate_google_calendar_ics(value: str) -> str:
    value = normalize_secret(value)
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower()
    except ValueError as exc:
        raise SecretDropError("Enter a valid private Google Calendar ICS URL.") from exc
    if (
        parsed.scheme != "https"
        or hostname != "calendar.google.com"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or not parsed.path.endswith("/basic.ics")
        or "/calendar/ical/" not in parsed.path
    ):
        raise SecretDropError("Enter a private Google Calendar ICS URL ending in /basic.ics.")

    try:
        request = Request(value, headers={"User-Agent": USER_AGENT})
        with urlopen(request, timeout=20) as response:
            status_code = getattr(response, "status", response.getcode())
            final_url = urlsplit(response.geturl())
            final_hostname = (final_url.hostname or "").lower()
            content_type = response.headers.get("Content-Type", "").lower()
            body = response.read(MAX_CALENDAR_BYTES + 1)
    except Exception:
        raise SecretDropError("The calendar URL could not be fetched. Check it and try again.") from None

    if status_code != HTTPStatus.OK:
        raise SecretDropError("The calendar URL did not return a usable calendar.")
    if final_url.scheme != "https" or final_hostname != "calendar.google.com":
        raise SecretDropError("The calendar URL redirected outside Google Calendar.")
    if len(body) > MAX_CALENDAR_BYTES:
        raise SecretDropError("The calendar is too large for this Secret Drop validator.")
    if "text/calendar" not in content_type:
        raise SecretDropError("The URL did not return calendar content.")
    if b"BEGIN:VCALENDAR" not in body or b"END:VCALENDAR" not in body:
        raise SecretDropError("The URL did not return a complete calendar.")
    return value


OPENROUTER_KEY_URL = "https://openrouter.ai/api/v1/key"
OPENROUTER_TIMEOUT_SECONDS = 15
OPENROUTER_MAX_RESPONSE_BYTES = 64 * 1024
OPENROUTER_KEY_RE = re.compile(r"sk-or-v1-[A-Za-z0-9._-]{20,512}")
OPENROUTER_UNEXPECTED = "OpenRouter returned an unexpected response while verifying this key."


class RejectRedirects(HTTPRedirectHandler):
    """Keep bearer credentials pinned to the configured provider endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Provider checks bypass ambient proxy variables and never follow redirects with
# the submitted bearer credential. The endpoint itself is fixed in source.
OPENROUTER_OPENER = build_opener(ProxyHandler({}), RejectRedirects())


def open_openrouter(request: Request, timeout: int):
    return OPENROUTER_OPENER.open(request, timeout=timeout)


def openrouter_status_message(status_code: int) -> str:
    """Return a fixed message per upstream status; never include the upstream body."""
    if status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
        return "OpenRouter rejected this key. Check it in your OpenRouter dashboard and paste it again."
    if status_code == HTTPStatus.TOO_MANY_REQUESTS:
        return "OpenRouter is rate limiting this check. Wait a moment and submit the key again."
    return "OpenRouter could not verify this key right now. Try again."


def validate_openrouter_api_key(value: str) -> str:
    """Verify an OpenRouter key with a bounded, read-only call to the official key endpoint.

    GET /api/v1/key only reads the calling key's own metadata, so validation never
    mutates the account. Nothing from the request or the upstream response is
    reflected into the raised message.
    """
    value = normalize_secret(value)
    if not OPENROUTER_KEY_RE.fullmatch(value):
        raise SecretDropError(
            "That does not look like an OpenRouter API key. Copy the whole key from your OpenRouter dashboard."
        )

    request = Request(
        OPENROUTER_KEY_URL,
        headers={
            "Authorization": f"Bearer {value}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with open_openrouter(request, timeout=OPENROUTER_TIMEOUT_SECONDS) as response:
            status_code = int(getattr(response, "status", 0) or response.getcode())
            body = response.read(OPENROUTER_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise SecretDropError(openrouter_status_message(int(getattr(exc, "code", 0) or 0))) from None
    except Exception:
        raise SecretDropError("OpenRouter could not be reached to verify this key. Try again.") from None

    if status_code != HTTPStatus.OK:
        raise SecretDropError(openrouter_status_message(status_code))
    if len(body) > OPENROUTER_MAX_RESPONSE_BYTES:
        raise SecretDropError(OPENROUTER_UNEXPECTED)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SecretDropError(OPENROUTER_UNEXPECTED) from None
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise SecretDropError(OPENROUTER_UNEXPECTED)
    return value


VALIDATORS: dict[str, tuple[Callable[[str], str], str]] = {
    "opaque": (validate_opaque, "Saved"),
    "google-calendar-ics": (validate_google_calendar_ics, "Saved and verified as a Google Calendar ICS feed"),
    "openrouter-api-key": (validate_openrouter_api_key, "Saved and verified with OpenRouter"),
}
PROVIDER_VALIDATORS = frozenset({"openrouter-api-key"})
GENERIC_VALIDATORS = tuple(sorted(set(VALIDATORS) - PROVIDER_VALIDATORS))

# A fixed, provider-bound intake. The operator picks the adapter; the browser never can.
ADAPTERS: dict[str, dict[str, str]] = {
    "openrouter-hermes": {
        "env_key": "OPENROUTER_API_KEY",
        "label": "OpenRouter API key",
        "validator": "openrouter-api-key",
    },
}


def capability_digest(capability: str) -> str:
    if not TOKEN_RE.fullmatch(capability):
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND)
    return hashlib.sha256(capability.encode("ascii")).hexdigest()


def request_path(state_dir: Path, request_id: str) -> Path:
    if not REQUEST_ID_RE.fullmatch(request_id):
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND)
    return state_dir / "requests" / f"{request_id}.json"


def tombstone_path(state_dir: Path, request_id: str) -> Path:
    if not REQUEST_ID_RE.fullmatch(request_id):
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND)
    return state_dir / "tombstones" / f"{request_id}.json"


@contextmanager
def exclusive_lock(path: Path):
    ensure_private_dir(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


_LIFECYCLE_GUARD = threading.RLock()
_LIFECYCLE_STATE = threading.local()


@contextmanager
def lifecycle_lock(state_dir: Path):
    """Serialize issuing, retirement, and delivery across threads and processes.

    This is the single ordering boundary for the request lifecycle. Lock order is
    always lifecycle -> environment write and never the reverse, so no lock cycle
    exists. Re-entry on one thread does not take the file lock twice, which would
    otherwise deadlock because flock is not reentrant across descriptors.
    """
    depth = getattr(_LIFECYCLE_STATE, "depth", 0)
    if depth:
        _LIFECYCLE_STATE.depth = depth + 1
        try:
            yield
        finally:
            _LIFECYCLE_STATE.depth = depth
        return
    _LIFECYCLE_GUARD.acquire()
    try:
        with exclusive_lock(Path(state_dir) / LIFECYCLE_LOCK_NAME):
            _LIFECYCLE_STATE.depth = 1
            try:
                yield
            finally:
                _LIFECYCLE_STATE.depth = 0
    finally:
        _LIFECYCLE_GUARD.release()


def resolve_intake(
    key: str | None,
    label: str | None,
    validator: str | None,
    adapter: str | None,
    *,
    demo: bool,
) -> tuple[str | None, str, str, str | None]:
    """Return (env_key, label, validator, adapter) for one intake."""
    if demo:
        if adapter:
            raise SecretDropError("A demo request cannot use a provider adapter.")
        return None, validate_label(label or "Example API key"), "opaque", None

    if adapter is not None:
        spec = ADAPTERS.get(adapter)
        if not spec:
            raise SecretDropError("The requested adapter is not available.")
        if key is not None or label is not None or validator is not None:
            raise SecretDropError("An adapter already fixes the environment key, label, and validator.")
        return spec["env_key"], spec["label"], spec["validator"], adapter

    if not key or not label:
        raise SecretDropError("Provide --key and --label, or use --adapter.")
    validator = validator or "opaque"
    if validator in PROVIDER_VALIDATORS:
        raise SecretDropError("Provider validation is available only through --adapter.")
    if validator not in VALIDATORS:
        raise SecretDropError("The requested validator is not available.")
    return validate_env_key(key), validate_label(label), validator, None


def supersede_pending_requests(config: dict[str, Any], env_key: str) -> int:
    """Retire every older pending request that targets the same destination.

    Must be called while holding the lifecycle lock. Retirement is durable before
    the caller issues the replacement, so an older link can never win a later race.
    """
    state_dir = Path(config["state_dir"])
    requests_dir = state_dir / "requests"
    if not env_key or not requests_dir.is_dir():
        return 0
    superseded = 0
    for path in sorted(requests_dir.glob("*.json")):
        if not REQUEST_ID_RE.fullmatch(path.stem):
            continue
        try:
            request = load_json(path)
        except SecretDropError:
            continue
        if request.get("env_key") != env_key or request.get("mode") == "demo":
            continue
        if effective_request_status(request) != "pending":
            continue
        try:
            retire_request(config, path, request, "superseded")
        except (SecretDropError, OSError):
            raise SecretDropError(
                "Older Secret Drop requests for this destination could not be retired. Try again.",
                HTTPStatus.INTERNAL_SERVER_ERROR,
            ) from None
        superseded += 1
    return superseded


def create_request(
    config: dict[str, Any],
    key: str | None,
    label: str | None,
    validator: str | None,
    ttl_minutes: int,
    *,
    demo: bool = False,
    adapter: str | None = None,
) -> dict[str, Any]:
    key, label, validator, adapter = resolve_intake(key, label, validator, adapter, demo=demo)
    if ttl_minutes < 1 or ttl_minutes > MAX_TTL_MINUTES:
        raise SecretDropError(f"Request lifetime must be between 1 and {MAX_TTL_MINUTES} minutes.")

    state_dir = Path(config["state_dir"])
    with lifecycle_lock(state_dir):
        cleanup_requests(config)
        requests_dir = state_dir / "requests"
        ensure_private_dir(requests_dir)
        created = utc_now()
        for _ in range(10):
            capability = secrets.token_urlsafe(32)
            request_id = capability_digest(capability)
            path = request_path(state_dir, request_id)
            if not path.exists() and not tombstone_path(state_dir, request_id).exists():
                break
        else:
            raise SecretDropError("A unique request could not be created.", HTTPStatus.INTERNAL_SERVER_ERROR)

        superseded = supersede_pending_requests(config, key or "") if not demo else 0
        payload = {
            "version": 2,
            "request_id": request_id,
            "label": label,
            "env_key": key,
            "adapter": adapter,
            "validator": validator,
            "mode": "demo" if demo else "secret",
            "status": "pending",
            "created_at": isoformat(created),
            "expires_at": isoformat(created + timedelta(minutes=ttl_minutes)),
            "completed_at": None,
            "result": None,
        }
        atomic_write_json(path, payload)

    return {
        "request_id": request_id,
        "request_url": f"{config['public_base_url']}/#token={capability}",
        "expires_at": payload["expires_at"],
        "status": "pending",
        "mode": payload["mode"],
        "label": label,
        "env_key": key,
        "adapter": adapter,
        "validator": validator,
        "superseded_requests": superseded,
    }


def load_request(config: dict[str, Any], request_id: str) -> tuple[Path, dict[str, Any]]:
    path = request_path(Path(config["state_dir"]), request_id)
    request = load_json(path)
    if request.get("request_id") != request_id:
        raise SecretDropError("Secret Drop state is invalid.", HTTPStatus.INTERNAL_SERVER_ERROR)
    return path, request


def missing_request_error(config: dict[str, Any], request_id: str) -> SecretDropError:
    """Explain a missing active request from its sanitized tombstone, if any."""
    try:
        tombstone = load_tombstone(config, request_id)
    except SecretDropError:
        return SecretDropError("This Secret Drop link is not valid.", HTTPStatus.NOT_FOUND)
    status_value = str(tombstone.get("status", ""))
    if status_value == "superseded":
        return SecretDropError(
            "This Secret Drop link was replaced by a newer request. Use the most recent link.",
            HTTPStatus.GONE,
        )
    if status_value == "expired":
        return SecretDropError("This Secret Drop link has expired.", HTTPStatus.GONE)
    return SecretDropError("This Secret Drop link has already been used.", HTTPStatus.NOT_FOUND)


def load_active_request(config: dict[str, Any], request_id: str) -> tuple[Path, dict[str, Any]]:
    try:
        return load_request(config, request_id)
    except SecretDropError as exc:
        if exc.status != HTTPStatus.NOT_FOUND:
            raise
        raise missing_request_error(config, request_id) from None


def request_public_status(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": request.get("label"),
        "status": request.get("status"),
        "mode": request.get("mode", "secret"),
        "expires_at": request.get("expires_at"),
        "completed_at": request.get("completed_at"),
        "result": request.get("result"),
    }


def retire_request(
    config: dict[str, Any], path: Path, request: dict[str, Any], status_value: str
) -> dict[str, Any]:
    if status_value not in {"consumed", "expired", "superseded"}:
        raise SecretDropError("Secret Drop state is invalid.", HTTPStatus.INTERNAL_SERVER_ERROR)
    completed_at = isoformat(utc_now())
    request["status"] = status_value
    request["completed_at"] = completed_at
    if status_value == "expired":
        request["result"] = "expired"
    elif status_value == "superseded":
        request["result"] = "superseded"
    elif request.get("mode") == "demo":
        request["result"] = "discarded"
    else:
        request["result"] = "consumed"
    tombstone = {
        "version": 2,
        "status": status_value,
        "mode": request.get("mode", "secret"),
        "completed_at": completed_at,
        "expires_at": request.get("expires_at"),
        "result": request.get("result"),
    }
    atomic_write_json(tombstone_path(Path(config["state_dir"]), str(request["request_id"])), tombstone)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    fsync_directory(path.parent)
    return request_public_status(request)


def load_tombstone(config: dict[str, Any], request_id: str) -> dict[str, Any]:
    return load_json(tombstone_path(Path(config["state_dir"]), request_id))


def effective_request_status(request: dict[str, Any]) -> str:
    status_value = str(request.get("status", "invalid"))
    if status_value == "pending":
        try:
            if parse_time(str(request["expires_at"])) <= utc_now():
                return "expired"
        except (KeyError, TypeError, ValueError):
            return "invalid"
    return status_value


def get_request_state(config: dict[str, Any], request_id: str) -> tuple[str, dict[str, Any] | None]:
    state_dir = Path(config["state_dir"])
    request_path(state_dir, request_id)
    with lifecycle_lock(state_dir):
        try:
            path, request = load_request(config, request_id)
        except SecretDropError as exc:
            if exc.status != HTTPStatus.NOT_FOUND:
                raise
            tombstone = load_tombstone(config, request_id)
            return str(tombstone.get("status", "invalid")), None
        status_value = effective_request_status(request)
        if status_value == "expired":
            retire_request(config, path, request, "expired")
            return "expired", None
        return status_value, request


def atomic_update_env(env_path: Path, key: str, value: str, state_dir: Path) -> None:
    validate_env_key(key)
    env_path = env_path.expanduser()
    env_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / "env-write.lock"
    # Lock order is lifecycle -> env-write. Nothing takes them the other way round.
    with exclusive_lock(lock_path):
        if env_path.is_symlink():
            raise SecretDropError("The configured environment file cannot be a symlink.", HTTPStatus.INTERNAL_SERVER_ERROR)
        if env_path.exists():
            file_stat = env_path.stat()
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_ENV_BYTES:
                raise SecretDropError("The configured environment file is not safe to update.", HTTPStatus.INTERNAL_SERVER_ERROR)
            text = env_path.read_text(encoding="utf-8")
        else:
            text = ""

        matcher = re.compile(rf"^\s*(?:export\s+)?{re.escape(key)}\s*=", re.ASCII)
        replacement = f"{key}={quote_dotenv_value(value)}\n"
        output: list[str] = []
        replaced = False
        for line in text.splitlines(keepends=True):
            if matcher.match(line):
                if not replaced:
                    output.append(replacement)
                    replaced = True
                continue
            output.append(line)
        if not replaced:
            if output and not output[-1].endswith(("\n", "\r")):
                output[-1] += "\n"
            output.append(replacement)
        updated = "".join(output)

        fd, temp_name = tempfile.mkstemp(prefix=f".{env_path.name}.secret-drop.", dir=env_path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(updated)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, env_path)
            os.chmod(env_path, 0o600)
            fsync_directory(env_path.parent)
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise


def consume_request(config: dict[str, Any], request_id: str, submitted_value: str) -> dict[str, Any]:
    """Validate one submission, then deliver it only if the request is still current.

    Validation runs outside the lifecycle lock because it can reach the network.
    The request is re-checked under the lock afterwards, so a submission that was
    still in provider validation when a newer request was issued cannot commit.
    """
    state_dir = Path(config["state_dir"])
    request_path(state_dir, request_id)

    with lifecycle_lock(state_dir):
        _, request = load_active_request(config, request_id)
        validator_name = str(request.get("validator", ""))
        validator_entry = VALIDATORS.get(validator_name)
        if not validator_entry:
            raise SecretDropError("This Secret Drop request is not configured correctly.", HTTPStatus.INTERNAL_SERVER_ERROR)
        ensure_usable(config, request_id, request)

    validator, _ = validator_entry
    value = validator(submitted_value)

    with lifecycle_lock(state_dir):
        path, request = load_active_request(config, request_id)
        if str(request.get("validator", "")) != validator_name:
            raise SecretDropError("This Secret Drop request changed while it was being verified.", HTTPStatus.CONFLICT)
        ensure_usable(config, request_id, request)

        try:
            retired = retire_request(config, path, request, "consumed")
        except Exception:
            raise SecretDropError(
                "The request could not be secured for one-time use. Try again.",
                HTTPStatus.INTERNAL_SERVER_ERROR,
            ) from None
        if request.get("mode") == "demo":
            return retired

        try:
            atomic_update_env(Path(config["env_path"]), str(request["env_key"]), value, state_dir)
        except Exception:
            raise SecretDropError(
                "The submitted value could not be saved. Create a new Secret Drop request and try again.",
                HTTPStatus.INTERNAL_SERVER_ERROR,
            ) from None
        retired["result"] = "saved"
        return retired


def ensure_usable(config: dict[str, Any], request_id: str, request: dict[str, Any]) -> None:
    """Raise unless the loaded request is still pending. Retires it when expired."""
    status_value = effective_request_status(request)
    if status_value == "expired":
        retire_request(config, request_path(Path(config["state_dir"]), request_id), request, "expired")
        raise SecretDropError("This Secret Drop link has expired.", HTTPStatus.GONE)
    if status_value == "superseded":
        raise SecretDropError(
            "This Secret Drop link was replaced by a newer request. Use the most recent link.",
            HTTPStatus.GONE,
        )
    if status_value != "pending":
        raise SecretDropError("This Secret Drop link has already been used.", HTTPStatus.CONFLICT)


def build_app_shell() -> bytes:
    """Return the generic application shell. It carries no request-specific data."""
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow,noarchive">
<meta name="referrer" content="no-referrer">
<title>Hermes Secret Drop</title>
<style>
:root{{--ink:#111;--muted:#737373;--line:#dedede;--soft:#f6f6f6;--bad:#b42318;--ok:#087f5b}}
*{{box-sizing:border-box}}[hidden]{{display:none!important}}
body{{margin:0;min-height:100svh;background:#fff;color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{min-height:100svh;display:grid;place-items:center;padding:28px 20px}}
.panel{{position:relative;width:min(100%,420px)}}
.brand{{font-size:13px;font-weight:800;letter-spacing:-.01em}}.brand span{{color:var(--muted);font-weight:500}}
.countdown{{position:absolute;top:0;right:0;color:var(--muted);font-size:12px;font-weight:600;font-variant-numeric:tabular-nums}}
h1{{margin:52px 0 24px;font-size:clamp(27px,7vw,34px);line-height:1.12;letter-spacing:-.045em;font-weight:720}}
.field{{position:relative}}input{{width:100%;height:54px;border:1px solid var(--line);border-radius:12px;padding:0 52px 0 15px;background:#fff;color:var(--ink);font:inherit}}input:focus{{outline:2px solid #111;outline-offset:1px;border-color:#111}}input:disabled{{background:var(--soft);color:var(--muted)}}
.reveal{{position:absolute;right:5px;top:5px;width:44px;height:44px;display:grid;place-items:center;border:0;border-radius:9px;background:transparent;color:#666;cursor:pointer}}.reveal:hover{{background:var(--soft);color:#111}}.reveal:focus-visible{{outline:2px solid #111}}.reveal svg{{width:21px;height:21px}}
.submit{{width:100%;height:52px;margin-top:12px;border:0;border-radius:12px;background:#111;color:#fff;font:inherit;font-weight:700;cursor:pointer}}.submit:hover{{background:#2a2a2a}}.submit:focus-visible{{outline:2px solid #111;outline-offset:2px}}.submit:disabled{{background:#aaa;cursor:not-allowed}}
.feedback{{margin:-10px 0 16px;color:var(--bad);font-size:13px;line-height:1.45}}
.sr-only{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}}
@media(max-width:420px){{main{{place-items:start center;padding-top:max(48px,10svh)}}}}
</style>
</head>
<body><main><section class="panel">
<div class="brand">Hermes <span>Secret Drop</span></div>
<strong class="countdown" id="countdown" aria-label="Time remaining" aria-live="polite" hidden>15:00</strong>
<h1 id="heading">Secret Drop</h1>
<p class="feedback" id="feedback" role="alert" hidden></p>
<form id="secret-form" autocomplete="off" hidden>
<label class="sr-only" id="secret-label" for="secret">Value</label>
<div class="field">
<input id="secret" name="secret" type="password" required autocomplete="off" autocapitalize="off" spellcheck="false">
<button id="reveal-secret" class="reveal" type="button" aria-label="Show value" title="Show value">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/><path id="eye-slash" d="m4 4 16 16" hidden/>
</svg>
</button>
</div>
<button id="submit" class="submit" type="submit">Save</button>
</form>
</section></main><script>{CLIENT_SCRIPT}</script></body>
</html>"""
    return document.encode("utf-8")


APP_SHELL = build_app_shell()


def render_notice(title: str) -> bytes:
    """Return a static scriptless page for a route that carries no request state."""
    safe_title = html.escape(title)
    document = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow,noarchive">
<title>{safe_title} · Hermes Secret Drop</title></head>
<body><main><h1>{safe_title}</h1></main></body>
</html>"""
    return document.encode("utf-8")


def request_remaining_seconds(request: dict[str, Any]) -> int:
    try:
        remaining = (parse_time(str(request["expires_at"])) - utc_now()).total_seconds()
    except (KeyError, TypeError, ValueError):
        return 0
    return max(0, math.ceil(remaining))


def browser_metadata(request: dict[str, Any]) -> dict[str, Any]:
    """Return only what the entry page needs. Never the destination or command."""
    verifies = request.get("validator") != "opaque"
    return {
        "label": request.get("label"),
        "status": "pending",
        "mode": request.get("mode", "secret"),
        "expires_at": request.get("expires_at"),
        "expires_in_seconds": request_remaining_seconds(request),
        "submit_label": "Save & verify" if verifies else "Save",
        "progress_label": "Verifying…" if verifies else "Saving…",
    }


class SecretDropHandler(BaseHTTPRequestHandler):
    server_version = f"HermesSecretDrop/{APP_VERSION}"
    sys_version = ""

    @property
    def app_config(self) -> dict[str, Any]:
        return self.server.app_config  # type: ignore[attr-defined]

    def log_message(self, format_string: str, *args: Any) -> None:
        return

    def _send(self, status_code: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(int(status_code))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._send(status_code, body, "application/json; charset=utf-8")

    def _capability(self) -> str | None:
        values = list(self.headers.get_all(TOKEN_HEADER) or [])
        if len(values) != 1:
            return None
        raw = values[0]
        return raw if TOKEN_RE.fullmatch(raw or "") else None

    def _origins(self) -> list[str]:
        return list(self.headers.get_all("Origin") or [])

    def _origin_is_ours(self) -> bool:
        """True only for exactly one Origin header equal to the configured origin.

        More than one Origin header is never sent by a browser, and different hops
        can disagree about which one counts, so an ambiguous request is refused.
        """
        origins = self._origins()
        return len(origins) == 1 and origin_matches(self.app_config, origins[0])

    def _foreign_origin(self) -> bool:
        """True when an Origin header is present but is not exactly our origin."""
        return bool(self._origins()) and not self._origin_is_ours()

    def do_HEAD(self) -> None:
        if urlsplit(self.path).path == "/health":
            self._send(HTTPStatus.OK, b"")
        else:
            self._send(HTTPStatus.NOT_FOUND, b"")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            body = json.dumps({"status": "ok", "version": APP_VERSION}, separators=(",", ":")).encode("utf-8")
            self._send(HTTPStatus.OK, body, "application/json; charset=utf-8")
            return
        if path == "/":
            self._send(HTTPStatus.OK, APP_SHELL)
            return
        if path == "/api/request":
            self._metadata()
            return
        self._send(HTTPStatus.NOT_FOUND, render_notice("Not found"))

    def _metadata(self) -> None:
        # A fixed custom header cannot be sent cross-origin without a preflight this
        # service never approves; a present Origin must still match exactly.
        if self._foreign_origin():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "This request did not come from the Secret Drop page.", "title": "Blocked", "retry": False})
            return
        capability = self._capability()
        if capability is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "This Secret Drop link is not valid.", "title": "Not found", "retry": False})
            return
        try:
            status_value, request = get_request_state(self.app_config, capability_digest(capability))
        except SecretDropError as exc:
            self._send_json(exc.status, {"error": exc.message, "title": "Not found" if exc.status == HTTPStatus.NOT_FOUND else "Unavailable", "retry": False})
            return
        if status_value == "pending" and request is not None:
            self._send_json(HTTPStatus.OK, browser_metadata(request))
        elif status_value == "expired":
            self._send_json(HTTPStatus.GONE, {"error": "This Secret Drop link has expired.", "title": "Expired", "retry": False})
        elif status_value == "superseded":
            self._send_json(HTTPStatus.GONE, {"error": "This Secret Drop link was replaced by a newer request.", "title": "Replaced", "retry": False})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "This Secret Drop link is not valid.", "title": "Not found", "retry": False})

    def _reject_submission(self, status_code: int, message: str, content_length: int, title: str = "Not saved") -> None:
        """Answer a submission without inspecting it, draining any body first.

        Draining discards the bytes unread; it never consumes the Secret Drop
        request. It only stops the peer from seeing a reset while it is still
        writing, which would hide the real reason for the rejection.
        """
        if 0 < content_length <= MAX_BODY_BYTES:
            try:
                self.rfile.read(content_length)
            except OSError:
                pass
        self._send_json(status_code, {"error": message, "title": title, "retry": False})

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/api/secret":
            self._send(HTTPStatus.NOT_FOUND, render_notice("Not found"))
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        # Enforced before any state is read, so a rejected Origin never consumes a
        # request, reveals whether one exists, or writes the environment.
        if not self._origin_is_ours():
            self._reject_submission(
                HTTPStatus.FORBIDDEN,
                "This submission did not come from the Secret Drop page.",
                content_length,
                title="Blocked",
            )
            return
        capability = self._capability()
        if capability is None:
            self._reject_submission(
                HTTPStatus.NOT_FOUND, "This Secret Drop link is not valid.", content_length, title="Not found"
            )
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._reject_submission(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Use the Secret Drop page to submit this value.", content_length
            )
            return
        if content_length < 1 or content_length > MAX_BODY_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "The submitted value is missing or too large.", "title": "Not saved", "retry": False},
            )
            return
        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"secret"} or not isinstance(payload["secret"], str):
                raise ValueError
            submitted_value = payload["secret"]
        except (UnicodeDecodeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Use the Secret Drop page to submit one value.", "title": "Not saved", "retry": False})
            return

        request_id = capability_digest(capability)
        try:
            result = consume_request(self.app_config, request_id, submitted_value)
        except SecretDropError as exc:
            retry = False
            try:
                status_value, _ = get_request_state(self.app_config, request_id)
                retry = status_value == "pending"
            except SecretDropError:
                retry = False
            self._send_json(exc.status, {"error": exc.message, "title": "Try again" if retry else "Not saved", "retry": retry})
            return
        note = "" if result.get("mode") == "demo" else VALIDATORS_NOTE.get(str(result.get("result")), "")
        self._send_json(HTTPStatus.OK, {"status": "ok", "result": result.get("result"), "mode": result.get("mode"), "note": note})

    def do_PUT(self) -> None:
        self._send(HTTPStatus.METHOD_NOT_ALLOWED, b"")

    do_PATCH = do_PUT
    do_DELETE = do_PUT


VALIDATORS_NOTE = {"saved": "This value is now stored for Hermes."}


class SecretDropUnixServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, socket_path: Path, app_config: dict[str, Any]):
        self.socket_path = socket_path
        self.app_config = app_config
        state_dir = Path(app_config["state_dir"])
        ensure_private_dir(state_dir)
        self._server_lock_fd = os.open(state_dir / "server.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._server_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self._server_lock_fd)
            raise SecretDropError("Secret Drop is already running.", HTTPStatus.CONFLICT) from exc
        if socket_path.exists() or socket_path.is_symlink():
            mode = socket_path.lstat().st_mode
            if not stat.S_ISSOCK(mode):
                os.close(self._server_lock_fd)
                raise SecretDropError("Secret Drop socket path is unsafe.", HTTPStatus.INTERNAL_SERVER_ERROR)
            socket_path.unlink()
        super().__init__(str(socket_path), SecretDropHandler)
        os.chmod(socket_path, 0o600)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            try:
                if self.socket_path.exists() and stat.S_ISSOCK(self.socket_path.lstat().st_mode):
                    self.socket_path.unlink()
            finally:
                try:
                    fcntl.flock(self._server_lock_fd, fcntl.LOCK_UN)
                    os.close(self._server_lock_fd)
                except OSError:
                    pass


class SecretDropTLSServer(ThreadingHTTPServer):
    """HTTPS server bound only to a Tailscale IP as a rootless Serve fallback."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        host: str,
        port: int,
        cert_path: Path,
        key_path: Path,
        app_config: dict[str, Any],
    ):
        self.app_config = app_config
        super().__init__((host, port), SecretDropHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.socket = context.wrap_socket(self.socket, server_side=True)


def probe_unix_health(socket_path: Path) -> dict[str, Any]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(socket_path))
        client.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        raise SecretDropError("Secret Drop service is not reachable.", HTTPStatus.SERVICE_UNAVAILABLE) from exc
    finally:
        client.close()
    response = b"".join(chunks)
    if not response.startswith(b"HTTP/1.0 200") and not response.startswith(b"HTTP/1.1 200"):
        raise SecretDropError("Secret Drop service health check failed.", HTTPStatus.SERVICE_UNAVAILABLE)
    return {"status": "ok", "socket": str(socket_path)}


def cleanup_requests(
    config: dict[str, Any], tombstone_keep_hours: int = TOMBSTONE_KEEP_HOURS
) -> dict[str, int]:
    state_dir = Path(config["state_dir"])
    requests_dir = state_dir / "requests"
    retired = 0
    with lifecycle_lock(state_dir):
        if requests_dir.exists():
            for path in requests_dir.glob("*.json"):
                request_id = path.stem
                if not REQUEST_ID_RE.fullmatch(request_id) and TOKEN_RE.fullmatch(request_id):
                    # v1.0 stored the plaintext capability in both the filename and
                    # payload. Those links are incompatible with v1.1, so retire the
                    # legacy file without parsing it. Take the old per-request lock
                    # first in case cleanup overlaps an in-flight v1.0 process.
                    legacy_lock_path = state_dir / "locks" / f"{capability_digest(request_id)}.lock"
                    try:
                        with exclusive_lock(legacy_lock_path):
                            path.unlink()
                            fsync_directory(requests_dir)
                        try:
                            legacy_lock_path.unlink()
                            fsync_directory(legacy_lock_path.parent)
                        except OSError:
                            pass
                        retired += 1
                    except FileNotFoundError:
                        pass
                    except OSError:
                        raise SecretDropError(
                            "Legacy Secret Drop request state could not be removed.",
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                        ) from None
                    continue
                if not REQUEST_ID_RE.fullmatch(request_id):
                    continue
                try:
                    current_path, request = load_request(config, request_id)
                    if effective_request_status(request) == "expired":
                        retire_request(config, current_path, request, "expired")
                        retired += 1
                except (SecretDropError, OSError, TypeError, ValueError):
                    continue

        tombstones_dir = state_dir / "tombstones"
        tombstones_removed = 0
        cutoff = utc_now() - timedelta(hours=max(0, tombstone_keep_hours))
        if tombstones_dir.exists():
            for path in tombstones_dir.glob("*.json"):
                try:
                    tombstone = load_json(path)
                    completed_at = parse_time(str(tombstone["completed_at"]))
                    if completed_at <= cutoff:
                        path.unlink()
                        tombstones_removed += 1
                except (SecretDropError, OSError, KeyError, TypeError, ValueError):
                    continue

    return {"requests_retired": retired, "tombstones_removed": tombstones_removed}


def cleanup_loop(config: dict[str, Any], stop_event: threading.Event) -> None:
    while not stop_event.wait(CLEANUP_INTERVAL_SECONDS):
        try:
            cleanup_requests(config)
        except Exception:
            continue


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes Tailnet Secret Drop")
    parser.add_argument("--config", type=Path, default=default_config_path())
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create one one-time write-only request")
    create.add_argument("--adapter", choices=sorted(ADAPTERS), default=None, help="Provider-bound intake with a fixed key and validator")
    create.add_argument("--key", default=None)
    create.add_argument("--label", default=None)
    create.add_argument("--validator", choices=GENERIC_VALIDATORS, default=None)
    create.add_argument("--ttl-minutes", type=int, default=DEFAULT_TTL_MINUTES)

    demo = subparsers.add_parser("demo", help="Create a disposable demo that never stores the submitted value")
    demo.add_argument("--label", default="Example API key")
    demo.add_argument("--ttl-minutes", type=int, default=DEFAULT_TTL_MINUTES)

    status_parser = subparsers.add_parser("status", help="Read sanitized request status only")
    status_parser.add_argument("request_id")

    subparsers.add_parser("health", help="Probe the local Unix service")
    cleanup = subparsers.add_parser("cleanup", help="Retire expired requests and old tombstones")
    cleanup.add_argument("--tombstone-keep-hours", type=int, default=TOMBSTONE_KEEP_HOURS)
    subparsers.add_parser("serve", help="Run the Secret Drop web service")
    return parser


def main() -> None:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args()
    try:
        config = load_config(args.config.expanduser())
        if args.command == "create":
            result = create_request(
                config,
                args.key,
                args.label,
                args.validator,
                args.ttl_minutes,
                adapter=args.adapter,
            )
        elif args.command == "demo":
            result = create_request(
                config,
                None,
                args.label,
                None,
                args.ttl_minutes,
                demo=True,
            )
        elif args.command == "status":
            status_value, request = get_request_state(config, args.request_id)
            result = request_public_status(request) if request is not None else load_tombstone(config, args.request_id)
            result["status"] = status_value
        elif args.command == "health":
            result = probe_unix_health(Path(config["socket_path"]))
        elif args.command == "cleanup":
            result = {"status": "ok", **cleanup_requests(config, args.tombstone_keep_hours)}
        elif args.command == "serve":
            cleanup_requests(config)
            stop_event = threading.Event()
            cleanup_thread = threading.Thread(
                target=cleanup_loop,
                args=(config, stop_event),
                daemon=True,
                name="secret-drop-cleanup",
            )
            cleanup_thread.start()
            try:
                unix_server = SecretDropUnixServer(Path(config["socket_path"]), config)
                https_host = config.get("https_host")
                https_port = config.get("https_port")
                tls_cert = config.get("tls_cert")
                tls_key = config.get("tls_key")
                if all((https_host, https_port, tls_cert, tls_key)):
                    try:
                        tls_server = SecretDropTLSServer(
                            str(https_host),
                            int(str(https_port)),
                            Path(str(tls_cert)),
                            Path(str(tls_key)),
                            config,
                        )
                    except Exception:
                        unix_server.server_close()
                        raise
                    unix_thread = threading.Thread(
                        target=unix_server.serve_forever,
                        kwargs={"poll_interval": 0.5},
                        daemon=True,
                    )
                    unix_thread.start()
                    try:
                        tls_server.serve_forever(poll_interval=0.5)
                    finally:
                        tls_server.server_close()
                        unix_server.shutdown()
                        unix_server.server_close()
                        unix_thread.join(timeout=5)
                else:
                    try:
                        unix_server.serve_forever(poll_interval=0.5)
                    finally:
                        unix_server.server_close()
            finally:
                stop_event.set()
                cleanup_thread.join(timeout=5)
            return
        else:
            parser.error("unknown command")
            return
        print(json.dumps(result, indent=2, sort_keys=True))
    except SecretDropError as exc:
        print(json.dumps({"status": "error", "error": exc.message}, sort_keys=True))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
