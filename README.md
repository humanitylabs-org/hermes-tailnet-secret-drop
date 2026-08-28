# Hermes Tailnet Secret Drop

A private, one-time, browser-encrypted credential handoff for Hermes Agent.

Secret Drop lets a user enter one secret or an atomic bundle without pasting values into AI chat. New WizardOS installs use an exact Cloudflare Access application and Tunnel route to a loopback-only origin; Tailnet-only HTTPS remains available for legacy/private-overlay deployments.

The capability lives only in the URL fragment, the service stores only its hash, and the browser encrypts values before transmission with a fresh AES-256-GCM key wrapped to the VPS's RSA-OAEP public key. The server accepts no plaintext fallback, never lists secrets, and cannot let an older link overwrite a newer request.

## Why it exists

Anything pasted into an AI chat should be treated as shared with that AI and potentially retained in transcripts. Secret Drop moves entry into a small deterministic service on the Hermes VPS. Hermes receives only the harmless request link and sanitized status.

This protects the chat boundary and, in normal Cloudflare operation, keeps the entered value opaque at the edge. It does not protect against a compromised browser, VPS, host account, or malicious page-code substitution by the edge. Read [SECURITY.md](SECURITY.md) for the exact trust model.

## Requirements

- Linux with systemd user services
- Python 3.10 or newer
- The dependencies in `requirements.txt`, including `cryptography>=41,<51` and the version parser used to enforce that interval
- Hermes Agent and Git
- One private delivery path:
  - recommended: Cloudflare Access plus Tunnel to IPv4 loopback; or
  - legacy: connected Tailscale with MagicDNS

Install Python dependencies into an isolated environment when needed:

```bash
python3 -m pip install -r requirements.txt
```

On Hermes Agent hosts, the existing Hermes virtual environment may already provide `cryptography`. The prerequisite checker reports missing requirements but never silently installs packages or runs privileged commands.

## Install with Cloudflare Access and Tunnel

First create the exact Access-protected public route and point its Tunnel origin at the chosen loopback port. Then run:

```bash
git clone https://github.com/humanitylabs-org/hermes-tailnet-secret-drop.git
cd hermes-tailnet-secret-drop
./scripts/prereq-check.sh --mode cloudflare-access
./scripts/setup.sh \
  --access-protected-public-base-url https://wizard.example/apps/secret-drop \
  --http-port 8805
```

The installer enforces the declared `cryptography>=41,<51` range, binds plain HTTP only to `127.0.0.1`, requires the protected URL to match `public_base_url` exactly, creates a mode-0600 RSA application key under a process-safe generation lock, installs a user service and `hermes-secret-drop` command, and verifies the prefixed loopback health route. When migrating an installer-owned Tailscale Serve deployment, it verifies that the exact listener still points to Secret Drop before removing only that listener; it never resets unrelated Serve configuration. It does not call Cloudflare APIs or create Access/Tunnel resources.

For legacy Tailnet mode, run `./scripts/prereq-check.sh` and `./scripts/setup.sh` without the Cloudflare arguments. The installer prefers Tailscale Serve and otherwise binds TLS only to the device's Tailscale address. It never enables Funnel.

## Try the interface safely

```bash
hermes-secret-drop demo
```

Open the returned link and enter only a fake value. Demo submissions are decrypted, validated, and discarded rather than written to the Hermes environment. The link works once and expires automatically.

## Create a real request

A provider adapter is the safest form because it fixes the destination key, label, and real provider validator together:

```bash
hermes-secret-drop create --adapter openrouter-hermes
```

Generic requests remain available:

```bash
hermes-secret-drop create \
  --key EXAMPLE_API_KEY \
  --label "Example API key" \
  --validator opaque
```

An atomic bundle can collect several related values in one form and writes all or none:

```bash
hermes-secret-drop create-bundle \
  --label "Provider credentials" \
  --field PROVIDER_API_KEY="API key" \
  --field PROVIDER_CLIENT_SECRET="Client secret"
```

Send only `request_url`, and send it whole. The capability is in the fragment (`https://host/private/path/#token=…`), which browsers omit from request lines, proxy logs, and `Referer`. The page removes the fragment from history with `history.replaceState`, then uses `X-Secret-Drop-Token` on same-origin API calls. Only `SHA-256(capability)` is stored.

`request_id` is that digest. It is safe for sanitized `status` checks and does not reveal the capability.

Validators:

| Validator | Selected by | What it proves |
| --- | --- | --- |
| `opaque` | `--validator opaque` | Syntax only: one non-empty, single-line, storable value. It does **not** contact any provider. |
| `google-calendar-ics` | `--validator google-calendar-ics` | The URL is a private Google Calendar ICS feed, checked with a bounded fetch. |
| `openrouter-api-key` | `--adapter openrouter-hermes` | OpenRouter accepts the key in a bounded, read-only request. |

API-key or account verification requires an adapter. The `google-calendar-ics` validator remains a generic URL/feed check, while `opaque` contacts no provider. The browser cannot choose adapters, environment names, validators, destinations, commands, or file paths.

## Link lifecycle

- Default lifetime: two hours; private operators may configure up to the five-hour package hard cap
- Single use: a successful submission retires the active request
- Supersession: a newer request retires older pending requests that overlap any destination key
- Validation first: rejected values preserve the previous `.env` and keep the link reusable
- Atomic bundles: missing, unexpected, or invalid fields write nothing
- Routes relative to the configured public base path: `/`, `/health`, `/api/request`, and `/api/secret`; no list, retrieval, export, or reveal route exists

## Commands

```bash
hermes-secret-drop health
hermes-secret-drop demo
hermes-secret-drop create --adapter openrouter-hermes
hermes-secret-drop create --key EXAMPLE_API_KEY --label "Example API key"
hermes-secret-drop create-bundle --label "Provider" --field PROVIDER_API_KEY="API key"
hermes-secret-drop status <request-id>
hermes-secret-drop cleanup
```

## Update

From a clean checkout:

```bash
git fetch --tags --prune
git pull --ff-only
python3 -m pip install -r requirements.txt
./scripts/setup.sh --access-protected-public-base-url https://wizard.example/apps/secret-drop --http-port 8805
```

Setup is idempotent and preserves the configured Hermes environment file. The v1.3 startup cleanup removes incompatible legacy active-request files; issue fresh links after upgrading.

## Uninstall

```bash
python3 scripts/uninstall.py
```

Uninstall stops the service, removes its configured listener and active request metadata, and removes the local package and skill. It does **not** delete secrets already saved in the Hermes `.env`.

## What changed in 1.3.1

- Cloudflare migration now fails closed when an existing installer-owned Tailscale Serve route is recorded but the Tailscale CLI is unavailable, preventing an unverified legacy route from surviving a reported-success migration.

## What changed in 1.3.0

- Added strict browser-side hybrid encryption: AES-256-GCM plus RSA-OAEP/SHA-256, bound to the capability digest
- Added exact Cloudflare Access mode with a loopback-only origin and path-prefix support
- Added atomic multi-field bundles while preserving single-use, validation, and stale-write protections
- Removed plaintext submission compatibility; malformed or tampered envelopes do not consume a request

## Security

Read [SECURITY.md](SECURITY.md) before adapting the service. The guarantees are enforced by deterministic code and tests, not AI instructions.

## Give this prompt to your AI

The Humanity Labs install prompt is in [docs/give-this-prompt-to-your-ai.md](docs/give-this-prompt-to-your-ai.md).
