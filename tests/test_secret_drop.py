from __future__ import annotations

import ast
import http.client
import importlib.util
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

SCRIPT = Path(__file__).resolve().parents[1] / "src" / "secret_drop.py"
SPEC = importlib.util.spec_from_file_location("secret_drop", SCRIPT)
assert SPEC and SPEC.loader
secret_drop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secret_drop)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path):
        super().__init__("localhost", timeout=5)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.socket_path))


class FakeCalendarResponse:
    status = 200
    headers = {"Content-Type": "text/calendar; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getcode(self):
        return self.status

    def geturl(self):
        return "https://calendar.google.com/calendar/ical/example/private-token/basic.ics"

    def read(self, limit):
        return b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"


class SecretDropTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.env = self.root / ".env"
        self.socket = self.state / "drop.sock"
        self.config = {
            "state_dir": str(self.state),
            "env_path": str(self.env),
            "socket_path": str(self.socket),
            "public_base_url": "https://test-node.example.ts.net:8805",
        }
        secret_drop.ensure_private_dir(self.state)
        self.server = None
        self.thread = None

    def tearDown(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)
        self.temp.cleanup()

    def start_server(self) -> None:
        self.server = secret_drop.SecretDropUnixServer(self.socket, self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def http(self, method: str, path: str, body: str | None = None, headers=None):
        connection = UnixHTTPConnection(self.socket)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        result = (response.status, dict(response.getheaders()), payload)
        connection.close()
        return result

    def create(self, ttl=15):
        return secret_drop.create_request(
            self.config,
            "TEST_CALENDAR_ICS_URL",
            "Private calendar ICS URL",
            "opaque",
            ttl,
        )

    def post_value(self, token: str, value: str):
        encoded = urlencode({"secret": value})
        return self.http(
            "POST",
            f"/r/{token}",
            encoded,
            {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(encoded))},
        )

    def test_atomic_env_update_preserves_other_lines_and_removes_duplicates(self):
        self.env.write_text(
            '# keep\nOTHER_TOKEN="one"\nTEST_CALENDAR_ICS_URL="old"\nTEST_CALENDAR_ICS_URL="duplicate"\n',
            encoding="utf-8",
        )
        os.chmod(self.env, 0o644)
        secret_drop.atomic_update_env(
            self.env,
            "TEST_CALENDAR_ICS_URL",
            "https://new.invalid/basic.ics",
            self.state,
        )
        text = self.env.read_text(encoding="utf-8")
        self.assertIn("# keep\n", text)
        self.assertIn('OTHER_TOKEN="one"\n', text)
        self.assertEqual(text.count("TEST_CALENDAR_ICS_URL="), 1)
        self.assertIn("TEST_CALENDAR_ICS_URL='https://new.invalid/basic.ics'", text)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)

    def test_dotenv_literal_round_trip_preserves_special_characters(self):
        value = "prefix$HOME\\segment'quoted"
        secret_drop.atomic_update_env(self.env, "TEST_CALENDAR_ICS_URL", value, self.state)
        stored = self.env.read_text(encoding="utf-8").strip().split("=", 1)[1]
        self.assertEqual(ast.literal_eval(stored), value)

    def test_dotenv_interpolation_sequence_is_rejected(self):
        with self.assertRaises(secret_drop.SecretDropError):
            secret_drop.validate_opaque("prefix${HOME}suffix")

    def test_dangerous_or_non_secret_environment_names_are_rejected(self):
        for key in ("PATH", "LD_PRELOAD", "ORDINARY_SETTING"):
            with self.subTest(key=key), self.assertRaises(secret_drop.SecretDropError):
                secret_drop.validate_env_key(key)

    def test_request_state_contains_metadata_only(self):
        created = self.create()
        path, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["status"], "pending")
        self.assertEqual(state["mode"], "secret")
        self.assertNotIn("secret", state)
        self.assertNotIn("value", state)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_request_lifetime_is_hard_capped_at_fifteen_minutes(self):
        with self.assertRaises(secret_drop.SecretDropError):
            self.create(ttl=16)
        self.assertEqual(secret_drop.DEFAULT_TTL_MINUTES, 15)
        self.assertEqual(secret_drop.MAX_TTL_MINUTES, 15)

    def test_client_script_hash_matches_content_security_policy(self):
        expected = f"script-src 'sha256-{secret_drop.CLIENT_SCRIPT_SHA256}'"
        self.assertIn(expected, secret_drop.SECURITY_HEADERS["Content-Security-Policy"])
        self.assertIn("reveal.addEventListener('click'", secret_drop.CLIENT_SCRIPT)
        self.assertIn("window.location.reload()", secret_drop.CLIENT_SCRIPT)

    def test_write_only_http_flow_saves_once_then_destroys_link(self):
        created = self.create()
        token = created["request_id"]
        self.start_server()

        status, headers, body = self.http("GET", f"/r/{token}")
        self.assertEqual(status, 200)
        self.assertIn(b"Save &amp; test", body)
        self.assertIn(b'id="reveal-secret"', body)
        self.assertIn(b'aria-label="Show value"', body)
        self.assertIn(b'id="countdown"', body)
        for removed_copy in (
            b"Paste the value. It never enters chat.",
            b"Tailnet only",
            b"one-time",
            b"write-only",
            b"Expires in",
            b"Paste value",
        ):
            self.assertNotIn(removed_copy, body)
        self.assertEqual(headers.get("Cache-Control"), "no-store, max-age=0")

        dummy_secret = "https://example.invalid/private-token/basic.ics"
        status, _, body = self.post_value(token, dummy_secret)
        self.assertEqual(status, 200)
        self.assertNotIn(dummy_secret.encode(), body)
        self.assertIn(b"Saved", body)
        self.assertIn("TEST_CALENDAR_ICS_URL=", self.env.read_text(encoding="utf-8"))
        self.assertFalse(secret_drop.request_path(self.state, token).exists())

        tombstone = secret_drop.load_tombstone(self.config, token)
        self.assertEqual(tombstone["status"], "consumed")
        self.assertNotIn(token, json.dumps(tombstone))

        status, _, second_body = self.post_value(token, dummy_secret)
        self.assertEqual(status, 404)
        self.assertNotIn(dummy_secret.encode(), second_body)
        status, _, _ = self.http("GET", f"/r/{token}")
        self.assertEqual(status, 404)

    def test_demo_discards_value_and_destroys_link(self):
        created = secret_drop.create_request(
            self.config,
            None,
            "Example API key",
            "opaque",
            15,
            demo=True,
        )
        token = created["request_id"]
        self.start_server()
        status, _, body = self.post_value(token, "fake-demo-value")
        self.assertEqual(status, 200)
        self.assertIn(b"Done", body)
        self.assertFalse(self.env.exists())
        self.assertFalse(secret_drop.request_path(self.state, token).exists())
        tombstone = secret_drop.load_tombstone(self.config, token)
        self.assertEqual(tombstone["mode"], "demo")
        self.assertEqual(tombstone["result"], "discarded")
        self.assertNotIn("fake-demo-value", json.dumps(tombstone))

    def test_invalid_submission_does_not_consume_request(self):
        created = self.create()
        token = created["request_id"]
        self.start_server()
        status, _, body = self.post_value(token, "line-one\nline-two")
        self.assertEqual(status, 400)
        self.assertNotIn(b"line-one", body)
        _, state = secret_drop.load_request(self.config, token)
        self.assertEqual(state["status"], "pending")
        self.assertFalse(self.env.exists())

    def test_retirement_failure_never_writes_the_environment(self):
        created = self.create()
        token = created["request_id"]
        with patch.object(secret_drop, "retire_request", side_effect=OSError("retirement failed")):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.consume_request(self.config, token, "fake-secret")

        self.assertNotIn("retirement failed", str(caught.exception))
        _, state = secret_drop.load_request(self.config, token)
        self.assertEqual(state["status"], "pending")
        self.assertFalse(self.env.exists())

    def test_request_directory_is_synced_before_the_environment_write(self):
        created = self.create()
        token = created["request_id"]
        events = []
        real_fsync_directory = secret_drop.fsync_directory

        def record_fsync(path):
            events.append(f"fsync:{Path(path).name}")
            real_fsync_directory(path)

        def record_environment_write(*_args):
            events.append("environment-write")

        with patch.object(secret_drop, "fsync_directory", side_effect=record_fsync):
            with patch.object(secret_drop, "atomic_update_env", side_effect=record_environment_write):
                secret_drop.consume_request(self.config, token, "fake-secret")

        self.assertLess(events.index("fsync:requests"), events.index("environment-write"))

    def test_request_directory_sync_failure_prevents_environment_write(self):
        created = self.create()
        token = created["request_id"]

        def fail_request_sync(path):
            if Path(path).name == "requests":
                raise OSError("private-path")

        with patch.object(secret_drop, "fsync_directory", side_effect=fail_request_sync):
            with patch.object(secret_drop, "atomic_update_env") as environment_write:
                with self.assertRaises(secret_drop.SecretDropError) as caught:
                    secret_drop.consume_request(self.config, token, "fake-secret")

        environment_write.assert_not_called()
        self.assertNotIn("private-path", str(caught.exception))

    def test_environment_write_failure_still_destroys_the_link(self):
        created = self.create()
        token = created["request_id"]
        with patch.object(secret_drop, "atomic_update_env", side_effect=OSError("private-path")):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.consume_request(self.config, token, "fake-secret")

        self.assertNotIn("private-path", str(caught.exception))
        self.assertFalse(secret_drop.request_path(self.state, token).exists())
        self.assertEqual(secret_drop.load_tombstone(self.config, token)["status"], "consumed")
        self.assertFalse(self.env.exists())
        with self.assertRaises(secret_drop.SecretDropError):
            secret_drop.consume_request(self.config, token, "fake-secret")

    def test_expired_request_is_retired_and_cannot_be_used(self):
        created = self.create()
        token = created["request_id"]
        path, state = secret_drop.load_request(self.config, token)
        state["expires_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(seconds=1))
        secret_drop.atomic_write_json(path, state)
        status_value, request = secret_drop.get_request_state(self.config, token)
        self.assertEqual(status_value, "expired")
        self.assertIsNone(request)
        self.assertFalse(path.exists())
        self.assertFalse(self.env.exists())
        self.assertEqual(secret_drop.load_tombstone(self.config, token)["status"], "expired")

    def test_expired_http_page_has_no_working_form(self):
        created = self.create()
        token = created["request_id"]
        path, state = secret_drop.load_request(self.config, token)
        state["expires_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(seconds=1))
        secret_drop.atomic_write_json(path, state)
        self.start_server()
        status, _, body = self.http("GET", f"/r/{token}")
        self.assertEqual(status, 410)
        self.assertIn(b">Expired<", body)
        self.assertNotIn(b'<form id="secret-form"', body)
        self.assertFalse(path.exists())

    def test_cleanup_retires_expired_requests_and_removes_old_tombstones(self):
        created = self.create()
        token = created["request_id"]
        path, state = secret_drop.load_request(self.config, token)
        state["expires_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(seconds=1))
        secret_drop.atomic_write_json(path, state)
        result = secret_drop.cleanup_requests(self.config)
        self.assertEqual(result["requests_retired"], 1)
        tombstone_path = secret_drop.tombstone_path(self.state, token)
        tombstone = secret_drop.load_json(tombstone_path)
        tombstone["completed_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(hours=2))
        secret_drop.atomic_write_json(tombstone_path, tombstone)
        result = secret_drop.cleanup_requests(self.config, tombstone_keep_hours=1)
        self.assertEqual(result["tombstones_removed"], 1)
        self.assertFalse(tombstone_path.exists())
        self.assertFalse(secret_drop.request_lock_path(self.state, token).exists())

    def test_no_list_or_reveal_http_endpoint_exists(self):
        self.start_server()
        for path in ("/", "/requests", "/secrets", "/env", "/api/secrets"):
            with self.subTest(path=path):
                status, _, _ = self.http("GET", path)
                self.assertEqual(status, 404)

    def test_google_calendar_validator_checks_calendar_without_returning_content(self):
        url = "https://calendar.google.com/calendar/ical/example/private-token/basic.ics"
        with patch.object(secret_drop, "urlopen", return_value=FakeCalendarResponse()):
            self.assertEqual(secret_drop.validate_google_calendar_ics(url), url)
        with self.assertRaises(secret_drop.SecretDropError):
            secret_drop.validate_google_calendar_ics("https://example.com/calendar/basic.ics")

    def test_google_calendar_transport_errors_are_sanitized(self):
        url = "https://calendar.google.com/calendar/ical/private-marker/basic.ics"
        with patch.object(secret_drop, "urlopen", side_effect=ValueError("private-marker")):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.validate_google_calendar_ics(url)
        self.assertNotIn("private-marker", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
