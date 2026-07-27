#!/usr/bin/env python3
"""Tailnet-only, one-time, write-only secret entry for Hermes.

The browser can submit a new value but no HTTP or CLI surface can retrieve one.
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
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen

APP_VERSION = "1.0.0-draft"
DEFAULT_TTL_MINUTES = 15
MAX_TTL_MINUTES = 15
CLEANUP_INTERVAL_SECONDS = 30
TOMBSTONE_KEEP_HOURS = 24
MAX_SECRET_BYTES = 64 * 1024
MAX_ENV_BYTES = 10 * 1024 * 1024
MAX_CALENDAR_BYTES = 16 * 1024 * 1024
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")
ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{2,127}")
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
  const input = document.getElementById('secret');
  const reveal = document.getElementById('reveal-secret');
  const slash = document.getElementById('eye-slash');
  if (input && reveal) {
    reveal.addEventListener('click', () => {
      const showing = input.type === 'password';
      input.type = showing ? 'text' : 'password';
      reveal.setAttribute('aria-label', showing ? 'Hide value' : 'Show value');
      reveal.setAttribute('title', showing ? 'Hide value' : 'Show value');
      if (slash) slash.hidden = !showing;
      input.focus({preventScroll: true});
    });
  }

  const countdown = document.getElementById('countdown');
  const form = document.getElementById('secret-form');
  if (!countdown || !form) return;
  const initialSeconds = Number(countdown.dataset.seconds || 0);
  const deadline = performance.now() + Math.max(0, initialSeconds) * 1000;
  let expired = false;
  const tick = () => {
    const remaining = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
    const minutes = Math.floor(remaining / 60);
    const seconds = String(remaining % 60).padStart(2, '0');
    countdown.textContent = `${minutes}:${seconds}`;
    if (remaining <= 0) {
      if (!expired) {
        expired = true;
        countdown.textContent = 'Expired';
        form.querySelectorAll('input, button').forEach((element) => { element.disabled = true; });
        window.setTimeout(() => window.location.reload(), 250);
      }
      return;
    }
    window.setTimeout(tick, 250);
  };
  tick();
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
        f"script-src 'sha256-{CLIENT_SCRIPT_SHA256}'; form-action 'self'; "
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
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".ts.net"):
        raise SecretDropError("Secret Drop must use a private Tailscale HTTPS URL.", HTTPStatus.INTERNAL_SERVER_ERROR)
    config["public_base_url"] = base
    return config


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
        request = Request(value, headers={"User-Agent": "Hermes-Tailnet-Secret-Drop/0.1"})
        with urlopen(request, timeout=20) as response:
            status_code = getattr(response, "status", response.getcode())
            final_url = urlsplit(response.geturl())
            final_hostname = (final_url.hostname or "").lower()
            content_type = response.headers.get("Content-Type", "").lower()
            body = response.read(MAX_CALENDAR_BYTES + 1)
    except Exception as exc:
        raise SecretDropError("The calendar URL could not be fetched. Check it and try again.") from exc

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


VALIDATORS: dict[str, tuple[Callable[[str], str], str]] = {
    "opaque": (validate_opaque, "Saved"),
    "google-calendar-ics": (validate_google_calendar_ics, "Saved and verified as a Google Calendar ICS feed"),
}


def request_path(state_dir: Path, token: str) -> Path:
    if not TOKEN_RE.fullmatch(token):
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND)
    return state_dir / "requests" / f"{token}.json"


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


def tombstone_path(state_dir: Path, token: str) -> Path:
    if not TOKEN_RE.fullmatch(token):
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return state_dir / "tombstones" / f"{digest}.json"


def request_lock_path(state_dir: Path, token: str) -> Path:
    if not TOKEN_RE.fullmatch(token):
        raise SecretDropError("This Secret Drop request does not exist.", HTTPStatus.NOT_FOUND)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return state_dir / "locks" / f"{digest}.lock"


def create_request(
    config: dict[str, Any],
    key: str | None,
    label: str,
    validator: str,
    ttl_minutes: int,
    *,
    demo: bool = False,
) -> dict[str, Any]:
    label = validate_label(label)
    if demo:
        key = None
        validator = "opaque"
    else:
        key = validate_env_key(str(key or ""))
    if validator not in VALIDATORS:
        raise SecretDropError("The requested validator is not available.")
    if ttl_minutes < 1 or ttl_minutes > MAX_TTL_MINUTES:
        raise SecretDropError(f"Request lifetime must be between 1 and {MAX_TTL_MINUTES} minutes.")

    cleanup_requests(config)
    state_dir = Path(config["state_dir"])
    requests_dir = state_dir / "requests"
    ensure_private_dir(requests_dir)
    created = utc_now()
    for _ in range(10):
        token = secrets.token_urlsafe(32)
        path = request_path(state_dir, token)
        if not path.exists() and not tombstone_path(state_dir, token).exists():
            break
    else:
        raise SecretDropError("A unique request could not be created.", HTTPStatus.INTERNAL_SERVER_ERROR)

    payload = {
        "version": 1,
        "request_id": token,
        "label": label,
        "env_key": key,
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
        "request_id": token,
        "request_url": f"{config['public_base_url']}/r/{quote(token)}",
        "expires_at": payload["expires_at"],
        "status": "pending",
        "mode": payload["mode"],
        "label": label,
    }


def load_request(config: dict[str, Any], token: str) -> tuple[Path, dict[str, Any]]:
    path = request_path(Path(config["state_dir"]), token)
    request = load_json(path)
    if request.get("request_id") != token:
        raise SecretDropError("Secret Drop state is invalid.", HTTPStatus.INTERNAL_SERVER_ERROR)
    return path, request


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
    if status_value not in {"consumed", "expired"}:
        raise SecretDropError("Secret Drop state is invalid.", HTTPStatus.INTERNAL_SERVER_ERROR)
    completed_at = isoformat(utc_now())
    request["status"] = status_value
    request["completed_at"] = completed_at
    request["result"] = "discarded" if request.get("mode") == "demo" else "saved"
    tombstone = {
        "version": 1,
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
    return request_public_status(request)


def load_tombstone(config: dict[str, Any], token: str) -> dict[str, Any]:
    return load_json(tombstone_path(Path(config["state_dir"]), token))


def effective_request_status(request: dict[str, Any]) -> str:
    status_value = str(request.get("status", "invalid"))
    if status_value == "pending":
        try:
            if parse_time(str(request["expires_at"])) <= utc_now():
                return "expired"
        except (KeyError, TypeError, ValueError):
            return "invalid"
    return status_value


def get_request_state(config: dict[str, Any], token: str) -> tuple[str, dict[str, Any] | None]:
    state_dir = Path(config["state_dir"])
    request_path(state_dir, token)
    lock_path = request_lock_path(state_dir, token)
    with exclusive_lock(lock_path):
        try:
            path, request = load_request(config, token)
        except SecretDropError as exc:
            if exc.status != HTTPStatus.NOT_FOUND:
                raise
            tombstone = load_tombstone(config, token)
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
            try:
                dir_fd = os.open(env_path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise


def consume_request(config: dict[str, Any], token: str, submitted_value: str) -> dict[str, Any]:
    state_dir = Path(config["state_dir"])
    request_path(state_dir, token)
    lock_path = request_lock_path(state_dir, token)
    with exclusive_lock(lock_path):
        path, request = load_request(config, token)
        status_value = effective_request_status(request)
        if status_value == "expired":
            retire_request(config, path, request, "expired")
            raise SecretDropError("This Secret Drop link has expired.", HTTPStatus.GONE)
        if status_value != "pending":
            raise SecretDropError("This Secret Drop link has already been used.", HTTPStatus.CONFLICT)

        validator_name = str(request.get("validator", ""))
        validator_entry = VALIDATORS.get(validator_name)
        if not validator_entry:
            raise SecretDropError("This Secret Drop request is not configured correctly.", HTTPStatus.INTERNAL_SERVER_ERROR)
        validator, _ = validator_entry
        value = validator(submitted_value)
        if request.get("mode") != "demo":
            atomic_update_env(Path(config["env_path"]), str(request["env_key"]), value, state_dir)

        return retire_request(config, path, request, "consumed")


def page_shell(title: str, body: str) -> bytes:
    safe_title = html.escape(title)
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>{safe_title} · Hermes Secret Drop</title>
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
.state{{margin-top:52px}}.state h1{{margin:0}}.state .feedback{{margin:14px 0 0}}
.sr-only{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}}
@media(max-width:420px){{main{{place-items:start center;padding-top:max(48px,10svh)}}}}
</style>
</head>
<body><main><section class="panel"><div class="brand">Hermes <span>Secret Drop</span></div>{body}</section></main><script>{CLIENT_SCRIPT}</script></body>
</html>"""
    return document.encode("utf-8")


def request_remaining_seconds(request: dict[str, Any]) -> int:
    try:
        remaining = (parse_time(str(request["expires_at"])) - utc_now()).total_seconds()
    except (KeyError, TypeError, ValueError):
        return 0
    return max(0, math.ceil(remaining))


def render_form(request: dict[str, Any], error: str | None = None) -> bytes:
    raw_label = str(request.get("label", "Secret"))
    safe_label = html.escape(raw_label)
    error_block = f'<p class="feedback error" role="alert">{html.escape(error)}</p>' if error else ""
    remaining = request_remaining_seconds(request)
    body = f"""
<strong class="countdown" id="countdown" data-seconds="{remaining}" aria-label="Time remaining" aria-live="polite">15:00</strong>
<h1>{safe_label}</h1>
{error_block}
<form id="secret-form" method="post" autocomplete="off">
<label class="sr-only" for="secret">{safe_label}</label>
<div class="field">
<input id="secret" name="secret" type="password" required autofocus autocomplete="off" autocapitalize="off" spellcheck="false">
<button id="reveal-secret" class="reveal" type="button" aria-label="Show value" title="Show value">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/><path id="eye-slash" d="m4 4 16 16" hidden/>
</svg>
</button>
</div>
<button class="submit" type="submit">Save &amp; test</button>
</form>
"""
    return page_shell(f"Add {raw_label}", body)


def render_terminal_state(title: str, message: str = "") -> bytes:
    message_block = f'<p class="feedback">{html.escape(message)}</p>' if message else ""
    body = f"""<div class="state"><h1>{html.escape(title)}</h1>{message_block}</div>"""
    return page_shell(title, body)


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

    def _token(self) -> str | None:
        path = urlsplit(self.path).path
        match = re.fullmatch(r"/r/([A-Za-z0-9_-]{32,128})/?", path)
        return match.group(1) if match else None

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
        token = self._token()
        if not token:
            self._send(HTTPStatus.NOT_FOUND, render_terminal_state("Not found"))
            return
        try:
            status_value, request = get_request_state(self.app_config, token)
            if status_value == "pending" and request is not None:
                self._send(HTTPStatus.OK, render_form(request))
            elif status_value == "expired":
                self._send(HTTPStatus.GONE, render_terminal_state("Expired"))
            else:
                self._send(HTTPStatus.NOT_FOUND, render_terminal_state("Not found"))
        except SecretDropError as exc:
            title = "Not found" if exc.status == HTTPStatus.NOT_FOUND else "Unavailable"
            message = "" if exc.status == HTTPStatus.NOT_FOUND else exc.message
            self._send(exc.status, render_terminal_state(title, message))

    def do_POST(self) -> None:
        token = self._token()
        if not token:
            self._send(HTTPStatus.NOT_FOUND, render_terminal_state("Not found"))
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            self._send(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, render_terminal_state("Unsupported submission", "Use the Secret Drop form to submit this value."))
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if content_length < 1 or content_length > MAX_SECRET_BYTES + 1024:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, render_terminal_state("Invalid submission", "The submitted value is missing or too large."))
            return
        raw_body = self.rfile.read(content_length)
        try:
            form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
            values = form.get("secret", [])
            if set(form) != {"secret"} or len(values) != 1:
                raise ValueError
            submitted_value = values[0]
        except (UnicodeDecodeError, ValueError):
            self._send(HTTPStatus.BAD_REQUEST, render_terminal_state("Invalid submission", "Use the Secret Drop form to submit one value."))
            return

        try:
            result = consume_request(self.app_config, token, submitted_value)
            title = "Done" if result.get("mode") == "demo" else "Saved"
            self._send(HTTPStatus.OK, render_terminal_state(title))
        except SecretDropError as exc:
            try:
                _, request = load_request(self.app_config, token)
                if effective_request_status(request) == "pending":
                    self._send(exc.status, render_form(request, exc.message))
                    return
            except SecretDropError:
                pass
            self._send(exc.status, render_terminal_state("Not saved", exc.message))

    def do_PUT(self) -> None:
        self._send(HTTPStatus.METHOD_NOT_ALLOWED, b"")

    do_PATCH = do_PUT
    do_DELETE = do_PUT


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
    if requests_dir.exists():
        for path in requests_dir.glob("*.json"):
            token = path.stem
            if not TOKEN_RE.fullmatch(token):
                continue
            lock_path = request_lock_path(state_dir, token)
            try:
                with exclusive_lock(lock_path):
                    current_path, request = load_request(config, token)
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
                    lock_path = state_dir / "locks" / f"{path.stem}.lock"
                    try:
                        lock_path.unlink()
                    except FileNotFoundError:
                        pass
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
    create.add_argument("--key", required=True)
    create.add_argument("--label", required=True)
    create.add_argument("--validator", choices=sorted(VALIDATORS), default="opaque")
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
            result = create_request(config, args.key, args.label, args.validator, args.ttl_minutes)
        elif args.command == "demo":
            result = create_request(
                config,
                None,
                args.label,
                "opaque",
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
