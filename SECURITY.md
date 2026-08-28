# Security model

Hermes Secret Drop is a narrow, write-only credential intake service. It supports a loopback-only origin behind Cloudflare Access and Tunnel, and a legacy Tailnet-only HTTPS mode.

## Intended guarantees

- Every request has a random capability, is single-use, defaults to a two-hour lifetime, and cannot exceed the configured five-hour hard cap.
- The browser encrypts entered values before transmission. The server accepts only the strict encrypted envelope and has no plaintext fallback.
- Values are never echoed, stored in request metadata, printed by the CLI, placed in command-line arguments, or written to application logs.
- There is no HTTP or CLI operation to list, retrieve, export, prefill, or reveal stored secrets.
- The eye control reveals only the value currently typed in the browser.
- Real values are written atomically to the configured Hermes `.env`; unrelated entries are preserved and permissions remain restrictive.
- Demo values are decrypted, validated, and discarded without storage.
- Used, expired, and superseded request files are retired. Short-lived tombstones contain sanitized state only.

## Application-layer encryption

- Each submission uses a new browser-generated AES-256-GCM key and 96-bit IV.
- The AES key is wrapped with the host's RSA-OAEP/SHA-256 public key. The private RSA key is created once on the VPS, stored as a mode-0600 regular file, and never returned by an HTTP or CLI read operation.
- Concurrent key generation is serialized through a no-follow, owner-checked private lock; a losing installer cannot delete or replace the winning key.
- AES-GCM additional authenticated data includes `SHA-256(capability)`, binding ciphertext to the exact one-time request. Moving a valid envelope to another request fails authentication.
- `POST /api/secret` accepts exactly `version`, `alg`, `enc`, `wrapped_key`, `iv`, and `ciphertext`. Plaintext fields, unknown fields, malformed encoding, tampering, or oversize values fail before request consumption or environment writes.
- Cloudflare Access mode exposes routing metadata, the capability header, and ciphertext to Cloudflare, but not the entered value during ordinary operation.

Because Cloudflare serves the HTML and JavaScript, application-layer encryption does not defend against a malicious or compelled edge substituting the page code or public key. Removing that final code-integrity trust requires an independently installed and pinned native client, browser extension, or direct private overlay. This release targets the honest-but-curious intermediary case while keeping browser-first deployment reproducible.

## Fragment capability and hash-only storage

- The random capability appears only in the URL fragment (`/#token=<capability>`). Fragments are not sent in request lines, proxy logs, or `Referer` headers.
- The page reads the fragment, removes it from browser history with `history.replaceState`, and sends it only in `X-Secret-Drop-Token` on same-origin API calls.
- Only `SHA-256(capability)` is written to disk. It is the active-request filename, tombstone filename, request binding, and sanitized `request_id`.
- Startup removes incompatible legacy request files that stored plaintext capabilities.

## Origin and browser enforcement

- `POST /api/secret` requires exactly one `Origin` header matching the scheme and authority of `public_base_url`. Refused submissions do not consume request state.
- `GET /api/request` requires the capability header. A foreign origin is rejected, and this service never approves a cross-origin preflight.
- Responses use `no-store`, `no-referrer`, `nosniff`, `DENY` framing, and a restrictive CSP that pins the exact inline-script SHA-256 hash.
- Cloudflare Access mode requires the configured public URL to equal `access_protected_public_base_url`, while the origin listener must be exactly IPv4 loopback. Direct TLS and loopback HTTP modes cannot be combined.

## Provider-bound adapters and bundles

- An adapter fixes the environment key, label, and validator together. `openrouter-hermes` binds `OPENROUTER_API_KEY` to the OpenRouter validator.
- Provider and transport errors map to fixed messages; submitted values and upstream bodies are never reflected.
- Validation completes before the previous `.env` value is replaced. A rejected value preserves the old credential and leaves the request reusable.
- `create-bundle` writes all fields atomically. Missing, unexpected, invalid, or oversized fields write nothing and do not consume the request.
- Generic `opaque` validation proves only that a value is safe, non-empty, and single-line. Provider verification requires an adapter.

## Stale-write protection

- Issuing, retirement, and delivery share one process-safe lifecycle lock. Lock order is lifecycle then environment write.
- A new request durably supersedes older pending requests that overlap any destination key.
- Provider validation runs outside the lifecycle lock, then request identity and fields are rechecked under the lock before delivery. An older slow submission cannot overwrite a newer request.

## Trust assumptions and non-goals

Secret Drop keeps raw credentials out of AI chat/model transcripts and ordinary Cloudflare edge plaintext processing. It does not hide an agent-usable secret from the VPS, the operating-system account running Hermes, a separately compromised browser, or a malicious code-serving edge. For use-without-raw-read semantics, place credentials behind a separately privileged capability broker.

The Hostinger/VPS account, operating-system user, local encryption private key, and browser device are trusted. Cloudflare Access authenticates the user and Tunnel carries traffic to loopback; Cloudflare is not expected to see plaintext during ordinary operation but remains trusted for page-code integrity.

## Deployment boundaries

- Linux and systemd user services are supported.
- Recommended WizardOS mode: exact Cloudflare Access application and Tunnel route to `127.0.0.1:<port>`.
- Migration removes an old Tailscale Serve listener only after its exact hostname, port, root handler, and Unix-socket target match the installer-owned record; mismatches fail closed and unrelated Serve routes are never reset.
- Legacy mode: Tailscale Serve on a dedicated HTTPS port, or TLS bound only to the device's Tailscale address. Funnel is never enabled.
- Only `/`, `/health`, `/api/request`, and `/api/secret`, relative to the configured public base path, exist. In Cloudflare mode the corresponding bare origin paths return 404. There is no per-capability path and no list, retrieval, or reveal route.

## Reporting a vulnerability

Do not open a public issue containing a credential, live request URL, private hostname, certificate, local path, or exploit payload tied to a real system. Use the repository's private **Report a vulnerability** flow instead.
