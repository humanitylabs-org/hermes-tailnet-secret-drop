from __future__ import annotations

import ast
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

SCRIPT = Path(__file__).resolve().parents[1] / "src" / "secret_drop.py"
SPEC = importlib.util.spec_from_file_location("secret_drop", SCRIPT)
assert SPEC and SPEC.loader
secret_drop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secret_drop)

PUBLIC_BASE_URL = "https://test-node.example.ts.net:8805"
ORIGIN = "https://test-node.example.ts.net:8805"
# Assembled at runtime so no source file ever contains a credential-shaped literal.
FAKE_OPENROUTER_KEY = "sk-" + "or-v1-" + ("a1b2c3d4" * 8)


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


class FakeJSONResponse:
    def __init__(self, payload: bytes, status: int = 200):
        self.status = status
        self._payload = payload
        self.headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getcode(self):
        return self.status

    def read(self, limit=None):
        return self._payload


class SecretDropTestCase(unittest.TestCase):
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
            "public_base_url": PUBLIC_BASE_URL,
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

    def create(self, ttl=15, key="TEST_CALENDAR_ICS_URL", label="Private calendar ICS URL", validator="opaque"):
        return secret_drop.create_request(self.config, key, label, validator, ttl)

    @staticmethod
    def capability(created: dict) -> str:
        url = created["request_url"]
        self_test = urlsplit(url)
        assert self_test.fragment.startswith("token=")
        return self_test.fragment.split("=", 1)[1]

    def get_metadata(self, capability: str, origin: str | None = None):
        headers = {secret_drop.TOKEN_HEADER: capability} if capability is not None else {}
        if origin is not None:
            headers["Origin"] = origin
        status, _, body = self.http("GET", "/api/request", None, headers)
        return status, body

    def post_secret(self, capability: str | None, value: str, origin: str | None = ORIGIN, content_type="application/json"):
        body = json.dumps({"secret": value})
        headers = {"Content-Type": content_type, "Content-Length": str(len(body))}
        if capability is not None:
            headers[secret_drop.TOKEN_HEADER] = capability
        if origin is not None:
            headers["Origin"] = origin
        return self.http("POST", "/api/secret", body, headers)

    def state_files_contain(self, needle: str) -> bool:
        for path in self.state.rglob("*"):
            if not path.is_file():
                continue
            if needle in path.name:
                return True
            try:
                if needle in path.read_text(encoding="utf-8"):
                    return True
            except (OSError, UnicodeDecodeError):
                continue
        return False


class CapabilityAndStorageTests(SecretDropTestCase):
    def test_request_url_carries_the_capability_only_in_the_fragment(self):
        created = self.create()
        url = created["request_url"]
        parsed = urlsplit(url)
        capability = self.capability(created)
        self.assertEqual(url, f"{PUBLIC_BASE_URL}/#token={capability}")
        self.assertEqual(parsed.path, "/")
        self.assertEqual(parsed.query, "")
        self.assertEqual(parsed.fragment, f"token={capability}")
        self.assertNotIn(capability, f"{parsed.scheme}://{parsed.netloc}{parsed.path}{parsed.query}")
        self.assertTrue(secret_drop.TOKEN_RE.fullmatch(capability))

    def test_only_the_capability_digest_is_stored_on_disk(self):
        created = self.create()
        capability = self.capability(created)
        digest = hashlib.sha256(capability.encode("ascii")).hexdigest()

        self.assertEqual(created["request_id"], digest)
        self.assertNotIn(capability, json.dumps(created["request_id"]))
        path, state = secret_drop.load_request(self.config, digest)
        self.assertEqual(path.name, f"{digest}.json")
        self.assertEqual(state["request_id"], digest)
        self.assertNotIn(capability, json.dumps(state))
        self.assertFalse(self.state_files_contain(capability))

    def test_no_capability_plaintext_survives_in_tombstone_state(self):
        created = self.create()
        capability = self.capability(created)
        digest = created["request_id"]
        self.start_server()
        status, _, _ = self.post_secret(capability, "https://example.invalid/private/basic.ics")
        self.assertEqual(status, 200)
        tombstone = secret_drop.load_tombstone(self.config, digest)
        self.assertEqual(tombstone["status"], "consumed")
        self.assertNotIn(capability, json.dumps(tombstone))
        self.assertFalse(self.state_files_contain(capability))

    def test_status_lookup_uses_the_digest_not_the_capability(self):
        created = self.create()
        capability = self.capability(created)
        status_value, request = secret_drop.get_request_state(self.config, created["request_id"])
        self.assertEqual(status_value, "pending")
        self.assertIsNotNone(request)
        with self.assertRaises(secret_drop.SecretDropError):
            secret_drop.get_request_state(self.config, capability)


class AppShellTests(SecretDropTestCase):
    def test_app_shell_is_generic_and_reads_the_fragment(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()
        status, headers, body = self.http("GET", "/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertNotIn(capability, text)
        self.assertNotIn("Private calendar ICS URL", text)
        self.assertIn("history.replaceState", text)
        self.assertIn(secret_drop.TOKEN_HEADER, text)
        self.assertIn('id="secret-form"', text)
        self.assertIn('id="reveal-secret"', text)
        self.assertIn('id="countdown"', text)
        self.assertNotIn("Save &amp; test", text)
        self.assertIn('type="submit">Save</button>', text)
        self.assertEqual(headers.get("Cache-Control"), "no-store, max-age=0")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")

    def test_client_script_clears_the_fragment_before_any_request(self):
        script = secret_drop.CLIENT_SCRIPT
        self.assertLess(script.index("history.replaceState"), script.index("fetch("))
        self.assertIn("location.hash", script)

    def test_client_script_hash_matches_content_security_policy(self):
        policy = secret_drop.SECURITY_HEADERS["Content-Security-Policy"]
        self.assertIn(f"script-src 'sha256-{secret_drop.CLIENT_SCRIPT_SHA256}'", policy)
        self.assertIn("connect-src 'self'", policy)
        self.assertIn("default-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn("form-action 'self'", policy)

        shell = secret_drop.APP_SHELL.decode("utf-8")
        script = shell.split("<script>", 1)[1].split("</script>", 1)[0]
        import base64

        recomputed = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
        self.assertEqual(recomputed, secret_drop.CLIENT_SCRIPT_SHA256)

    def test_removed_token_path_route_and_no_list_or_reveal_endpoint(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()
        for path in (
            f"/r/{capability}",
            f"/r/{created['request_id']}",
            "/requests",
            "/api/requests",
            "/secrets",
            "/api/secrets",
            "/env",
        ):
            with self.subTest(path=path):
                status, _, body = self.http("GET", path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"Private calendar ICS URL", body)
                self.assertNotIn(b'id="secret-form"', body)
        _, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["status"], "pending")

    def test_health_endpoint_is_unauthenticated_and_sanitized(self):
        self.start_server()
        status, _, body = self.http("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok", "version": secret_drop.APP_VERSION})
        status, _, _ = self.http("HEAD", "/health")
        self.assertEqual(status, 200)


class HeaderCapabilityTests(SecretDropTestCase):
    def test_metadata_requires_the_fixed_capability_header(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()

        status, _ = self.get_metadata(None)
        self.assertEqual(status, 404)
        status, body = self.get_metadata("x" * 40)
        self.assertEqual(status, 404)
        self.assertNotIn(b"Private calendar ICS URL", body)

        status, body = self.get_metadata(capability)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["label"], "Private calendar ICS URL")
        self.assertEqual(payload["status"], "pending")
        self.assertEqual(payload["mode"], "secret")
        self.assertGreater(payload["expires_in_seconds"], 0)
        self.assertNotIn("env_key", payload)
        self.assertNotIn(capability, body.decode("utf-8"))

    def test_metadata_rejects_a_foreign_origin(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()
        status, _ = self.get_metadata(capability, origin="https://evil.example.ts.net:8805")
        self.assertEqual(status, 403)
        status, _ = self.get_metadata(capability, origin=ORIGIN)
        self.assertEqual(status, 200)

    def test_submission_requires_the_capability_header(self):
        self.create()
        self.start_server()
        status, _, _ = self.post_secret(None, "value")
        self.assertEqual(status, 404)
        self.assertFalse(self.env.exists())


class OriginEnforcementTests(SecretDropTestCase):
    def test_submission_requires_an_exactly_matching_origin(self):
        created = self.create()
        capability = self.capability(created)
        digest = created["request_id"]
        self.start_server()

        for origin in (
            None,
            "null",
            "",
            "not-an-origin",
            "https://evil.example.ts.net:8805",
            "http://test-node.example.ts.net:8805",
            "https://test-node.example.ts.net",
            "https://test-node.example.ts.net:8806",
            "https://test-node.example.ts.net:8805/",
            "https://test-node.example.ts.net:8805 https://test-node.example.ts.net:8805",
            "https://[",
        ):
            with self.subTest(origin=origin):
                status, _, body = self.post_secret(capability, "https://example.invalid/x/basic.ics", origin=origin)
                self.assertEqual(status, 403)
                self.assertNotIn(b"example.invalid", body)
                _, state = secret_drop.load_request(self.config, digest)
                self.assertEqual(state["status"], "pending")
                self.assertFalse(self.env.exists())

        status, _, _ = self.post_secret(capability, "https://example.invalid/x/basic.ics", origin=ORIGIN)
        self.assertEqual(status, 200)
        self.assertIn("TEST_CALENDAR_ICS_URL=", self.env.read_text(encoding="utf-8"))

    def test_duplicate_origin_headers_are_refused(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()
        body = json.dumps({"secret": "https://example.invalid/x/basic.ics"})
        raw = (
            f"POST /api/secret HTTP/1.1\r\nHost: localhost\r\n"
            f"Origin: https://evil.example.ts.net:8805\r\nOrigin: {ORIGIN}\r\n"
            f"{secret_drop.TOKEN_HEADER}: {capability}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}"
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(str(self.socket))
        try:
            client.sendall(raw.encode("utf-8"))
            response = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
        finally:
            client.close()
        self.assertIn(b" 403 ", response.split(b"\r\n", 1)[0] + b" ")
        _, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["status"], "pending")
        self.assertFalse(self.env.exists())

    def test_request_origin_is_scheme_and_authority_only(self):
        self.assertEqual(secret_drop.request_origin(self.config), ORIGIN)

    def test_unsupported_content_type_is_refused(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()
        status, _, _ = self.post_secret(capability, "value", content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, 415)
        _, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["status"], "pending")


class AdapterTests(SecretDropTestCase):
    def test_openrouter_adapter_binds_key_label_and_validator(self):
        created = secret_drop.create_request(self.config, None, None, None, 15, adapter="openrouter-hermes")
        self.assertEqual(created["env_key"], "OPENROUTER_API_KEY")
        self.assertEqual(created["label"], "OpenRouter API key")
        self.assertEqual(created["validator"], "openrouter-api-key")
        self.assertEqual(created["adapter"], "openrouter-hermes")
        _, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["env_key"], "OPENROUTER_API_KEY")
        self.assertEqual(state["validator"], "openrouter-api-key")
        self.assertEqual(state["adapter"], "openrouter-hermes")

    def test_generic_key_label_validator_still_works(self):
        created = secret_drop.create_request(self.config, "EXAMPLE_API_KEY", "Example API key", "opaque", 15)
        self.assertEqual(created["env_key"], "EXAMPLE_API_KEY")
        self.assertEqual(created["validator"], "opaque")
        self.assertIsNone(created["adapter"])

    def test_provider_validators_are_reachable_only_through_an_adapter(self):
        self.assertNotIn("openrouter-api-key", secret_drop.GENERIC_VALIDATORS)
        self.assertIn("opaque", secret_drop.GENERIC_VALIDATORS)
        self.assertIn("google-calendar-ics", secret_drop.GENERIC_VALIDATORS)
        with self.assertRaises(secret_drop.SecretDropError):
            secret_drop.create_request(self.config, "EXAMPLE_API_KEY", "Example", "openrouter-api-key", 15)

    def test_adapter_conflicting_overrides_are_refused(self):
        for key, label, validator in (
            ("OTHER_API_KEY", None, None),
            (None, "Different label", None),
            (None, None, "opaque"),
        ):
            with self.subTest(key=key, label=label, validator=validator), self.assertRaises(
                secret_drop.SecretDropError
            ):
                secret_drop.create_request(self.config, key, label, validator, 15, adapter="openrouter-hermes")

    def test_cli_accepts_adapter_and_generic_flags(self):
        parser = secret_drop.build_parser()
        args = parser.parse_args(["create", "--adapter", "openrouter-hermes"])
        self.assertEqual(args.adapter, "openrouter-hermes")
        args = parser.parse_args(["create", "--key", "EXAMPLE_API_KEY", "--label", "Example", "--validator", "opaque"])
        self.assertIsNone(args.adapter)
        self.assertEqual(args.key, "EXAMPLE_API_KEY")

    def test_browser_metadata_never_exposes_adapter_destination_or_command(self):
        created = secret_drop.create_request(self.config, None, None, None, 15, adapter="openrouter-hermes")
        capability = self.capability(created)
        self.start_server()
        status, body = self.get_metadata(capability)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertNotIn("env_key", payload)
        self.assertNotIn("adapter", payload)
        self.assertNotIn("command", payload)
        self.assertNotIn("env_path", payload)
        self.assertEqual(payload["submit_label"], "Save & verify")
        self.assertEqual(payload["progress_label"], "Verifying…")

    def test_opaque_browser_copy_does_not_claim_provider_verification(self):
        created = self.create(key="EXAMPLE_API_KEY", label="Example API key", validator="opaque")
        self.start_server()
        status, body = self.get_metadata(self.capability(created))
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["submit_label"], "Save")
        self.assertEqual(payload["progress_label"], "Saving…")
        self.assertNotIn(b"validator", body)


class OpenRouterValidatorTests(SecretDropTestCase):
    def test_malformed_keys_are_rejected_before_any_network_call(self):
        def explode(*_args, **_kwargs):
            raise AssertionError("validation must not reach the network for a malformed key")

        with patch.object(secret_drop, "open_openrouter", side_effect=explode):
            for candidate in ("", "not-a-key", "sk-" + "wrong-v1-" + "a" * 40, "sk-" + "or-v1-" + "!" * 40, "sk-" + "or-v1-" + "a" * 8):
                with self.subTest(candidate=candidate), self.assertRaises(secret_drop.SecretDropError) as caught:
                    secret_drop.validate_openrouter_api_key(candidate)
                if candidate:
                    self.assertNotIn(candidate, str(caught.exception))

    def test_valid_key_is_accepted_with_a_non_mutating_bounded_request(self):
        seen = {}

        def fake_urlopen(request, timeout=None):
            seen["url"] = request.full_url
            seen["method"] = request.get_method()
            seen["headers"] = {name.lower(): value for name, value in request.header_items()}
            seen["timeout"] = timeout
            return FakeJSONResponse(json.dumps({"data": {"label": "test", "usage": 0}}).encode("utf-8"))

        with patch.object(secret_drop, "open_openrouter", side_effect=fake_urlopen):
            self.assertEqual(secret_drop.validate_openrouter_api_key(FAKE_OPENROUTER_KEY), FAKE_OPENROUTER_KEY)

        self.assertEqual(seen["url"], "https://openrouter.ai/api/v1/key")
        self.assertEqual(seen["method"], "GET")
        self.assertEqual(seen["headers"]["authorization"], f"Bearer {FAKE_OPENROUTER_KEY}")
        self.assertEqual(seen["headers"]["accept"], "application/json")
        self.assertIsInstance(seen["timeout"], int)
        self.assertLessEqual(seen["timeout"], 30)

    def test_valid_key_format_allows_provider_token_punctuation(self):
        candidate = "sk-" + "or-v1-" + "a_b.c-d" * 4
        response = FakeJSONResponse(json.dumps({"data": {"label": "ok"}}).encode("utf-8"))
        with patch.object(secret_drop, "open_openrouter", return_value=response):
            self.assertEqual(secret_drop.validate_openrouter_api_key(candidate), candidate)

    def test_rejected_key_and_upstream_errors_are_sanitized(self):
        rejection = HTTPError(
            "https://openrouter.ai/api/v1/key",
            401,
            "Unauthorized",
            {},
            None,
        )
        rejection.read = lambda *_args: b'{"error":{"message":"invalid key private-marker"}}'
        for failure in (
            rejection,
            ValueError(f"boom {FAKE_OPENROUTER_KEY}"),
            OSError("private-marker"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(secret_drop, "open_openrouter", side_effect=failure):
                    with self.assertRaises(secret_drop.SecretDropError) as caught:
                        secret_drop.validate_openrouter_api_key(FAKE_OPENROUTER_KEY)
                message = str(caught.exception)
                self.assertNotIn(FAKE_OPENROUTER_KEY, message)
                self.assertNotIn("private-marker", message)

    def test_unexpected_upstream_body_is_not_reflected(self):
        response = FakeJSONResponse(b'{"unexpected":"private-marker"}')
        with patch.object(secret_drop, "open_openrouter", return_value=response):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.validate_openrouter_api_key(FAKE_OPENROUTER_KEY)
        self.assertNotIn("private-marker", str(caught.exception))

    def test_validation_failure_preserves_previous_env_and_keeps_request_reusable(self):
        previous = "OPENROUTER_API_KEY='previous-value'\nOTHER_TOKEN='keep'\n"
        self.env.write_text(previous, encoding="utf-8")
        created = secret_drop.create_request(self.config, None, None, None, 15, adapter="openrouter-hermes")
        capability = self.capability(created)
        digest = created["request_id"]
        self.start_server()

        rejection = HTTPError("https://openrouter.ai/api/v1/key", 401, "Unauthorized", {}, None)
        with patch.object(secret_drop, "open_openrouter", side_effect=rejection):
            status, _, body = self.post_secret(capability, FAKE_OPENROUTER_KEY)
        self.assertEqual(status, 400)
        self.assertNotIn(FAKE_OPENROUTER_KEY.encode(), body)
        self.assertTrue(json.loads(body)["retry"])
        self.assertEqual(self.env.read_text(encoding="utf-8"), previous)
        _, state = secret_drop.load_request(self.config, digest)
        self.assertEqual(state["status"], "pending")

        good = FakeJSONResponse(json.dumps({"data": {"label": "ok"}}).encode("utf-8"))
        with patch.object(secret_drop, "open_openrouter", return_value=good):
            status, _, _ = self.post_secret(capability, FAKE_OPENROUTER_KEY)
        self.assertEqual(status, 200)
        text = self.env.read_text(encoding="utf-8")
        self.assertIn("OTHER_TOKEN='keep'", text)
        self.assertEqual(text.count("OPENROUTER_API_KEY="), 1)
        self.assertNotIn("previous-value", text)


class SupersessionTests(SecretDropTestCase):
    def test_creating_a_newer_request_supersedes_the_older_one_for_the_same_key(self):
        first = self.create(key="EXAMPLE_API_KEY", label="Example API key")
        first_capability = self.capability(first)
        second = self.create(key="EXAMPLE_API_KEY", label="Example API key")
        self.assertEqual(second["superseded_requests"], 1)

        tombstone = secret_drop.load_tombstone(self.config, first["request_id"])
        self.assertEqual(tombstone["status"], "superseded")
        self.assertEqual(tombstone["result"], "superseded")
        self.assertFalse(secret_drop.request_path(self.state, first["request_id"]).exists())

        self.start_server()
        status, _, body = self.post_secret(first_capability, "stale-value")
        self.assertEqual(status, 410)
        self.assertNotIn(b"stale-value", body)
        self.assertFalse(self.env.exists())

        status, _, _ = self.post_secret(self.capability(second), "fresh-value")
        self.assertEqual(status, 200)
        self.assertIn("EXAMPLE_API_KEY='fresh-value'", self.env.read_text(encoding="utf-8"))

    def test_requests_for_different_keys_stay_pending_concurrently(self):
        first = self.create(key="FIRST_API_KEY", label="First")
        second = self.create(key="SECOND_API_KEY", label="Second")
        self.assertEqual(second["superseded_requests"], 0)
        for created in (first, second):
            _, state = secret_drop.load_request(self.config, created["request_id"])
            self.assertEqual(state["status"], "pending")

    def test_demo_requests_are_not_superseded_by_real_requests(self):
        demo = secret_drop.create_request(self.config, None, "Example API key", "opaque", 15, demo=True)
        self.create(key="EXAMPLE_API_KEY", label="Example API key")
        _, state = secret_drop.load_request(self.config, demo["request_id"])
        self.assertEqual(state["status"], "pending")

    def test_status_reports_superseded_tombstones(self):
        first = self.create(key="EXAMPLE_API_KEY", label="Example API key")
        self.create(key="EXAMPLE_API_KEY", label="Example API key")
        status_value, request = secret_drop.get_request_state(self.config, first["request_id"])
        self.assertEqual(status_value, "superseded")
        self.assertIsNone(request)

    def test_older_slow_delivery_cannot_overwrite_a_newer_issued_request(self):
        self.env.write_text("EXAMPLE_API_KEY='previous-value'\n", encoding="utf-8")
        first = self.create(key="EXAMPLE_API_KEY", label="Example API key")
        entered_validation = threading.Event()
        release_validation = threading.Event()
        outcome: dict[str, object] = {}

        def slow_validator(value: str) -> str:
            entered_validation.set()
            self.assertTrue(release_validation.wait(10))
            return secret_drop.validate_opaque(value)

        def deliver() -> None:
            try:
                outcome["result"] = secret_drop.consume_request(
                    self.config, first["request_id"], "stale-value"
                )
            except secret_drop.SecretDropError as exc:
                outcome["error"] = exc

        with patch.dict(secret_drop.VALIDATORS, {"opaque": (slow_validator, "Saved")}):
            worker = threading.Thread(target=deliver, daemon=True)
            worker.start()
            self.assertTrue(entered_validation.wait(10))
            second = self.create(key="EXAMPLE_API_KEY", label="Example API key")
            self.assertEqual(second["superseded_requests"], 1)
            release_validation.set()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())

        self.assertNotIn("result", outcome)
        self.assertIsInstance(outcome.get("error"), secret_drop.SecretDropError)
        self.assertNotIn("stale-value", str(outcome["error"]))
        self.assertEqual(self.env.read_text(encoding="utf-8"), "EXAMPLE_API_KEY='previous-value'\n")
        self.assertEqual(
            secret_drop.load_tombstone(self.config, first["request_id"])["status"], "superseded"
        )

    def test_lifecycle_lock_is_reentrant_within_one_thread(self):
        with secret_drop.lifecycle_lock(self.state):
            with secret_drop.lifecycle_lock(self.state):
                self.assertTrue((self.state / secret_drop.LIFECYCLE_LOCK_NAME).exists())

    def test_lifecycle_lock_excludes_other_threads(self):
        held = threading.Event()
        entered = threading.Event()
        release = threading.Event()

        def hold() -> None:
            with secret_drop.lifecycle_lock(self.state):
                held.set()
                release.wait(10)

        def contend() -> None:
            with secret_drop.lifecycle_lock(self.state):
                entered.set()

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        self.assertTrue(held.wait(10))
        contender = threading.Thread(target=contend, daemon=True)
        contender.start()
        self.assertFalse(entered.wait(0.3))
        release.set()
        self.assertTrue(entered.wait(10))
        holder.join(timeout=5)
        contender.join(timeout=5)

    def test_lifecycle_lock_excludes_other_processes(self):
        child_code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import secret_drop
with secret_drop.lifecycle_lock(Path(sys.argv[2])):
    print("locked", flush=True)
    sys.stdin.readline()
"""
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(SCRIPT.parent), str(self.state)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert child.stdin is not None
        assert child.stdout is not None
        assert child.stderr is not None
        self.addCleanup(lambda: child.wait(timeout=5) if child.poll() is None else None)
        self.addCleanup(child.stderr.close)
        self.addCleanup(child.stdout.close)
        self.addCleanup(child.stdin.close)
        self.assertEqual(child.stdout.readline().strip(), "locked")

        entered = threading.Event()

        def acquire_in_parent():
            with secret_drop.lifecycle_lock(self.state):
                entered.set()

        contender = threading.Thread(target=acquire_in_parent)
        contender.start()
        self.assertFalse(entered.wait(timeout=0.2))
        child.stdin.write("release\n")
        child.stdin.flush()
        self.assertEqual(child.wait(timeout=5), 0, child.stderr.read())
        contender.join(timeout=5)
        self.assertTrue(entered.is_set())


class LifecycleTests(SecretDropTestCase):
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
        self.assertNotIn("capability", state)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_request_lifetime_is_hard_capped_at_fifteen_minutes(self):
        with self.assertRaises(secret_drop.SecretDropError):
            self.create(ttl=16)
        self.assertEqual(secret_drop.DEFAULT_TTL_MINUTES, 15)
        self.assertEqual(secret_drop.MAX_TTL_MINUTES, 15)

    def test_write_only_http_flow_saves_once_then_destroys_link(self):
        created = self.create()
        capability = self.capability(created)
        digest = created["request_id"]
        self.start_server()

        status, body = self.get_metadata(capability)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["label"], "Private calendar ICS URL")

        dummy_secret = "https://example.invalid/private-token/basic.ics"
        status, _, body = self.post_secret(capability, dummy_secret)
        self.assertEqual(status, 200)
        self.assertNotIn(dummy_secret.encode(), body)
        self.assertEqual(json.loads(body)["result"], "saved")
        self.assertIn("TEST_CALENDAR_ICS_URL=", self.env.read_text(encoding="utf-8"))
        self.assertFalse(secret_drop.request_path(self.state, digest).exists())

        tombstone = secret_drop.load_tombstone(self.config, digest)
        self.assertEqual(tombstone["status"], "consumed")
        self.assertNotIn(capability, json.dumps(tombstone))

        status, _, second_body = self.post_secret(capability, dummy_secret)
        self.assertEqual(status, 404)
        self.assertNotIn(dummy_secret.encode(), second_body)
        status, _ = self.get_metadata(capability)
        self.assertEqual(status, 404)

    def test_demo_discards_value_and_destroys_link(self):
        created = secret_drop.create_request(self.config, None, "Example API key", "opaque", 15, demo=True)
        capability = self.capability(created)
        self.start_server()
        status, _, body = self.post_secret(capability, "fake-demo-value")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["result"], "discarded")
        self.assertFalse(self.env.exists())
        self.assertFalse(secret_drop.request_path(self.state, created["request_id"]).exists())
        tombstone = secret_drop.load_tombstone(self.config, created["request_id"])
        self.assertEqual(tombstone["mode"], "demo")
        self.assertEqual(tombstone["result"], "discarded")
        self.assertNotIn("fake-demo-value", json.dumps(tombstone))

    def test_invalid_submission_does_not_consume_request(self):
        created = self.create()
        capability = self.capability(created)
        self.start_server()
        status, _, body = self.post_secret(capability, "line-one\nline-two")
        self.assertEqual(status, 400)
        self.assertNotIn(b"line-one", body)
        self.assertTrue(json.loads(body)["retry"])
        _, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["status"], "pending")
        self.assertFalse(self.env.exists())

    def test_retirement_failure_never_writes_the_environment(self):
        created = self.create()
        with patch.object(secret_drop, "retire_request", side_effect=OSError("retirement failed")):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.consume_request(self.config, created["request_id"], "fake-secret")

        self.assertNotIn("retirement failed", str(caught.exception))
        _, state = secret_drop.load_request(self.config, created["request_id"])
        self.assertEqual(state["status"], "pending")
        self.assertFalse(self.env.exists())

    def test_request_directory_is_synced_before_the_environment_write(self):
        created = self.create()
        events = []
        real_fsync_directory = secret_drop.fsync_directory

        def record_fsync(path):
            events.append(f"fsync:{Path(path).name}")
            real_fsync_directory(path)

        def record_environment_write(*_args):
            events.append("environment-write")

        with patch.object(secret_drop, "fsync_directory", side_effect=record_fsync):
            with patch.object(secret_drop, "atomic_update_env", side_effect=record_environment_write):
                secret_drop.consume_request(self.config, created["request_id"], "fake-secret")

        self.assertLess(events.index("fsync:requests"), events.index("environment-write"))

    def test_request_directory_sync_failure_prevents_environment_write(self):
        created = self.create()

        def fail_request_sync(path):
            if Path(path).name == "requests":
                raise OSError("private-path")

        with patch.object(secret_drop, "fsync_directory", side_effect=fail_request_sync):
            with patch.object(secret_drop, "atomic_update_env") as environment_write:
                with self.assertRaises(secret_drop.SecretDropError) as caught:
                    secret_drop.consume_request(self.config, created["request_id"], "fake-secret")

        environment_write.assert_not_called()
        self.assertNotIn("private-path", str(caught.exception))

    def test_environment_write_failure_still_destroys_the_link(self):
        created = self.create()
        digest = created["request_id"]
        with patch.object(secret_drop, "atomic_update_env", side_effect=OSError("private-path")):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.consume_request(self.config, digest, "fake-secret")

        self.assertNotIn("private-path", str(caught.exception))
        self.assertFalse(secret_drop.request_path(self.state, digest).exists())
        self.assertEqual(secret_drop.load_tombstone(self.config, digest)["status"], "consumed")
        self.assertFalse(self.env.exists())
        with self.assertRaises(secret_drop.SecretDropError):
            secret_drop.consume_request(self.config, digest, "fake-secret")

    def test_environment_directory_sync_failure_is_not_reported_as_saved(self):
        created = self.create()
        digest = created["request_id"]
        real_fsync_directory = secret_drop.fsync_directory

        def fail_environment_sync(path):
            if Path(path) == self.env.parent:
                raise OSError("private-path")
            real_fsync_directory(path)

        with patch.object(secret_drop, "fsync_directory", side_effect=fail_environment_sync):
            with self.assertRaises(secret_drop.SecretDropError) as caught:
                secret_drop.consume_request(self.config, digest, "fake-secret")

        self.assertNotIn("private-path", str(caught.exception))
        self.assertFalse(secret_drop.request_path(self.state, digest).exists())
        self.assertEqual(secret_drop.load_tombstone(self.config, digest)["status"], "consumed")
        self.assertTrue(self.env.exists())

    def test_expired_request_is_retired_and_cannot_be_used(self):
        created = self.create()
        digest = created["request_id"]
        path, state = secret_drop.load_request(self.config, digest)
        state["expires_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(seconds=1))
        secret_drop.atomic_write_json(path, state)
        status_value, request = secret_drop.get_request_state(self.config, digest)
        self.assertEqual(status_value, "expired")
        self.assertIsNone(request)
        self.assertFalse(path.exists())
        self.assertFalse(self.env.exists())
        self.assertEqual(secret_drop.load_tombstone(self.config, digest)["status"], "expired")

    def test_expired_link_has_no_working_metadata_or_submission(self):
        created = self.create()
        capability = self.capability(created)
        path, state = secret_drop.load_request(self.config, created["request_id"])
        state["expires_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(seconds=1))
        secret_drop.atomic_write_json(path, state)
        self.start_server()
        status, body = self.get_metadata(capability)
        self.assertEqual(status, 410)
        self.assertFalse(json.loads(body).get("retry"))
        self.assertFalse(path.exists())
        status, _, _ = self.post_secret(capability, "value")
        self.assertIn(status, (404, 410))
        self.assertFalse(self.env.exists())

    def test_cleanup_retires_expired_requests_and_removes_old_tombstones(self):
        created = self.create()
        digest = created["request_id"]
        path, state = secret_drop.load_request(self.config, digest)
        state["expires_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(seconds=1))
        secret_drop.atomic_write_json(path, state)
        result = secret_drop.cleanup_requests(self.config)
        self.assertEqual(result["requests_retired"], 1)
        tombstone_path = secret_drop.tombstone_path(self.state, digest)
        tombstone = secret_drop.load_json(tombstone_path)
        tombstone["completed_at"] = secret_drop.isoformat(secret_drop.utc_now() - timedelta(hours=2))
        secret_drop.atomic_write_json(tombstone_path, tombstone)
        result = secret_drop.cleanup_requests(self.config, tombstone_keep_hours=1)
        self.assertEqual(result["tombstones_removed"], 1)
        self.assertFalse(tombstone_path.exists())

    def test_cleanup_removes_legacy_v1_plaintext_capability_state(self):
        capability = "L" * 43
        requests_dir = self.state / "requests"
        secret_drop.ensure_private_dir(requests_dir)
        legacy_path = requests_dir / f"{capability}.json"
        secret_drop.atomic_write_json(
            legacy_path,
            {
                "version": 1,
                "request_id": capability,
                "status": "pending",
                "expires_at": secret_drop.isoformat(secret_drop.utc_now() + timedelta(minutes=10)),
            },
        )
        legacy_lock = self.state / "locks" / f"{secret_drop.capability_digest(capability)}.lock"

        result = secret_drop.cleanup_requests(self.config)

        self.assertEqual(result["requests_retired"], 1)
        self.assertFalse(legacy_path.exists())
        self.assertFalse(legacy_lock.exists())

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
