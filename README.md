# Hermes Tailnet Secret Drop

A private, one-time credential handoff for Hermes Agent.

Secret Drop gives Hermes a temporary Tailnet-only page where you can enter an API key, token, password, credential, or private URL without pasting that value into chat. The page accepts one value and never provides a list, reveal, export, or retrieval screen.

The link's capability lives only in the URL fragment, the service stores only its hash, submissions must come from the service's own origin, and an older link can never overwrite a credential a newer link was issued for.

## Why it exists

Anything pasted into an AI chat should be treated as shared with that AI and potentially retained in transcripts. Secret Drop moves credential entry into a small deterministic web service on your own Tailscale network. Hermes receives only the harmless request link and sanitized state.

This protects the chat boundary, not the host boundary: secrets saved for Hermes remain readable by the operating-system account running Hermes.

## Requirements

- A Linux host with systemd user services
- Python 3.10 or newer
- Hermes Agent installed and configured
- Tailscale installed, signed in, and connected with MagicDNS
- Git

Tailscale is a hard prerequisite. Start at [tailscale.com/download](https://tailscale.com/download). The prerequisite checker explains the next missing step but does not silently install packages or run privileged commands.

## Install

```bash
git clone https://github.com/humanitylabs-org/hermes-tailnet-secret-drop.git
cd hermes-tailnet-secret-drop
./scripts/prereq-check.sh
./scripts/setup.sh
```

The setup script installs a user service, adds the `hermes-secret-drop` command, installs the Hermes skill, verifies private Tailnet HTTPS, and creates a disposable demo link.

The installer prefers Tailscale Serve on a dedicated HTTPS port. If this account cannot configure Serve, it falls back to a rootless HTTPS listener bound only to the device's Tailscale IP using a Tailscale certificate. It never enables Funnel.

## Try the interface safely

```bash
hermes-secret-drop demo
```

Open the returned link and use a fake value. Demo submissions are discarded rather than written to the Hermes environment. The active request is removed after it is used or expires.

## Create a real request

A provider adapter is the safest form. It fixes the environment key, the label, and a real provider validator in one flag:

```bash
hermes-secret-drop create --adapter openrouter-hermes
```

Generic requests still work exactly as before:

```bash
hermes-secret-drop create \
  --key EXAMPLE_API_KEY \
  --label "Example API key" \
  --validator opaque
```

Send only `request_url` to the user, and send it whole. The capability that authorizes the entry page lives in the URL fragment (`https://<node>.ts.net:8805/#token=…`), which browsers never place in a request line, so it is not in server logs, proxy logs, or the `Referer` header. The page reads the fragment, erases it from history with `history.replaceState`, and replays it in an `X-Secret-Drop-Token` header on same-origin API calls. Only the SHA-256 digest of the capability is stored on disk.

`request_id` is that digest. It is safe to keep for `status` checks and never reveals the capability. The form says **Save** for syntax-only `opaque` requests and **Save & verify** only when it will perform a real validator check.

Validators:

| Validator | Selected by | What it proves |
| --- | --- | --- |
| `opaque` | `--validator opaque` (default) | Syntax only: one non-empty, single-line, storable value. It does **not** contact any provider. |
| `google-calendar-ics` | `--validator google-calendar-ics` | The URL is a private Google Calendar ICS feed, checked with a bounded fetch. |
| `openrouter-api-key` | `--adapter openrouter-hermes` | The key is accepted by OpenRouter, checked with a bounded, read-only `GET https://openrouter.ai/api/v1/key`. |

Provider validation is available only through an adapter, so a generic request can never imply a verification it did not perform. Environment names are constrained to uppercase secret-like keys. The browser cannot choose the adapter, key, destination, validator, command, or file path.

## Link lifecycle

- Hard server-side lifetime: 15 minutes maximum
- Single use: successful submission retires the active request immediately
- Supersession: creating a new request for an environment key retires older pending requests for that same key as `superseded`, so a stale link can never overwrite a newer credential
- Ordering: issuing, retirement, and delivery share one process-safe lifecycle lock; a submission still in provider validation when a newer request is issued is refused instead of committing
- Validation first: a value is verified before the existing `.env` entry is touched, so a rejected value leaves the previous credential byte-for-byte intact and leaves the link usable for a corrected submission
- Expiration: a background cleanup loop retires expired active requests
- Status: short-lived tombstones keyed by the capability digest contain only sanitized state and are purged automatically
- Routes: `/` (generic app shell), `/health`, `/api/request` (metadata), `/api/secret` (submission). There is no request list, retrieval, or reveal endpoint.

## Commands

```bash
hermes-secret-drop health
hermes-secret-drop demo
hermes-secret-drop create --adapter openrouter-hermes
hermes-secret-drop create --key EXAMPLE_API_KEY --label "Example API key"
hermes-secret-drop status <request-id>
hermes-secret-drop cleanup
```

## Update

From a clean checkout:

```bash
git fetch --tags --prune
git pull --ff-only
./scripts/setup.sh
```

Setup is idempotent and preserves the configured Hermes environment file.

Upgrading from v1.0 intentionally invalidates and removes any still-pending v1.0 request files when the service starts. Those old URLs are incompatible with v1.1, and removing them clears the legacy format that stored the capability in local request state.

## Uninstall

```bash
python3 scripts/uninstall.py
```

Uninstall stops the service, removes its Tailnet listener, destroys active request metadata, and removes the local package and skill. It does **not** delete secrets already saved in the Hermes `.env`.

## What changed in 1.1.0

Intentional, breaking changes to the machine-readable contract:

- `request_url` is now `https://<node>.ts.net:<port>/#token=<capability>`. The old `/r/<token>` route is removed.
- `request_id` is now the SHA-256 digest of the capability rather than the capability itself. It is still the argument to `status`, and it is now safe to log or keep.
- HTTP routes are `/`, `/health`, `/api/request`, and `/api/secret`. Submission is `application/json` with an `X-Secret-Drop-Token` header and an exactly matching `Origin`.
- `create` output adds `env_key`, `adapter`, `validator`, and `superseded_requests`. `status` may now report `superseded`.

Unchanged: `expires_at`, `status`, `mode`, `label`, the 15-minute cap, demo behaviour, the `opaque` and `google-calendar-ics` validators, and the installer and uninstaller contracts.

## Security

Read [SECURITY.md](SECURITY.md) before adapting the service. Core guarantees are enforced by deterministic code and tests, not by AI instructions.

## Give this prompt to your AI

The Humanity Labs install prompt is in [docs/give-this-prompt-to-your-ai.md](docs/give-this-prompt-to-your-ai.md).
