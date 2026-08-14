# Security model

Hermes Tailnet Secret Drop is a narrow write-only credential intake service.

## Intended guarantees

- The web surface is reachable only through the user's tailnet.
- Tailscale Funnel is never configured.
- Every request is random and single-use. Deployments default to a 15-minute cap; private operators may explicitly raise it to the five-hour package hard limit.
- Secret values are accepted only in an HTTPS request body.
- Values are never echoed in responses, stored in request metadata, printed by the CLI, included in command-line arguments, or written to application logs.
- There is no HTTP or CLI operation to list, retrieve, export, prefill, or reveal stored secrets.
- The eye control reveals only the value currently typed in the browser.
- The browser cannot select adapters, environment names, validators, paths, commands, programs, or destinations.
- Real values are written atomically to the configured Hermes `.env`; unrelated entries are preserved and file permissions are restricted.
- Demo values are validated and discarded without storage.
- Used, expired, and superseded active request files are retired. Sanitized status tombstones are keyed by the capability digest and automatically purged.

### Fragment capability and hash-only storage

- The random capability that authorizes one intake appears only in the URL fragment (`/#token=<capability>`). Fragments are not sent to servers, so the capability never appears in a request line, access log, proxy log, or `Referer` header.
- The entry page reads the fragment, removes it from browser history with `history.replaceState`, and replays it in a fixed `X-Secret-Drop-Token` header on same-origin API calls.
- Only `SHA-256(capability)` is written to disk. It is the request filename, the tombstone filename, and the `request_id` the CLI reports. No plaintext capability exists in active metadata, filenames, tombstones, logs, or error messages.
- On a v1.0 upgrade, startup invalidates and removes legacy active request files before the service begins listening, clearing the old format that stored plaintext capabilities in local state.
- The capability cannot be recovered from anything the CLI prints except the original `request_url`.

### Origin enforcement

- `POST /api/secret` requires an `Origin` header exactly equal to the scheme and authority of the configured `public_base_url`. Missing, `null`, malformed, or differing origins are refused with 403 before any request state is read, so a refused submission never consumes the request and never writes the environment.
- `GET /api/request` is capability-protected by the custom header, which a cross-origin page cannot send without a preflight this service never approves. A present but mismatched `Origin` is refused.
- Responses carry `no-store`, `no-referrer`, `nosniff`, `DENY` framing, and a restrictive CSP whose `script-src` pins the exact SHA-256 hash of the one inline script.

### Provider-bound adapters

- An adapter fixes the environment key, label, and validator together; `--adapter openrouter-hermes` binds `OPENROUTER_API_KEY` to the OpenRouter validator.
- OpenRouter validation rejects wrong prefixes and characters locally before any network call, then performs one bounded, non-mutating `GET https://openrouter.ai/api/v1/key` with bearer authorization and `Accept: application/json`.
- HTTP, network, and JSON failures are mapped to fixed messages. The submitted key and the upstream response body are never reflected into a response, an exception, or a log.
- Validation completes before the existing `.env` value is replaced. A rejected value leaves the previous credential byte-for-byte intact and leaves the request usable for a corrected submission.
- Generic `opaque` validation is described honestly: it verifies only that the value is a safe, non-empty, single-line string. API-key or account verification requires an adapter; the specialized Google Calendar URL/feed validator remains available generically.

### Stale-write protection

- Issuing, retirement, and delivery are serialized by one process-safe lifecycle lock (`flock` plus an in-process reentrant guard). Lock order is always lifecycle then environment write, so no lock cycle exists.
- Creating a request for an environment key durably retires older pending requests for that same key as `superseded` before the replacement is issued.
- Provider validation runs outside the lock, then the request is re-checked under the lock before delivery. A submission still validating when a newer request is issued is refused rather than committed, so an older intake can never overwrite a newer credential.
- Pending requests for different environment keys remain usable concurrently.

## Explicit non-goals

Secret Drop keeps raw credentials out of AI chat/model transcripts and public web surfaces. It does not hide an agent-usable secret from the operating-system account that runs Hermes. If that account can use or read the configured `.env`, it can technically access the value.

For use-without-raw-read semantics, place the credential behind a separately privileged broker that exposes only narrow operations. That is outside this package.

## Trust assumptions

- Tailnet membership is sufficient user authentication for the intended deployment.
- The Hermes host, the operating-system user running the service, and Tailscale control plane are trusted.
- The local machine is maintained and receives security updates.
- The user reviews privileged/package-manager actions before approval.

## Deployment boundaries

- Linux and systemd user services are the supported first-release platform.
- The service prefers Tailscale Serve on a dedicated HTTPS port.
- When Serve configuration is unavailable, the fallback binds TLS only to the device's Tailscale IPv4 address.
- Only four fixed routes exist: `/` (a generic app shell with no request data), `/health`, `/api/request`, and `/api/secret`. There is no per-capability path and no list, retrieval, or reveal route.

## Reporting a vulnerability

Do not open a public issue containing a credential, live request URL, private hostname, certificate, local path, or exploit payload tied to a real system. Use this repository's private **Report a vulnerability** flow instead.
