# Hermes Tailnet Secret Drop

A private, one-time credential handoff for Hermes Agent.

Secret Drop gives Hermes a temporary Tailnet-only page where you can enter an API key, token, password, credential, or private URL without pasting that value into chat. The page accepts one value and never provides a list, reveal, export, or retrieval screen.

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

```bash
hermes-secret-drop create \
  --key OPENROUTER_API_KEY \
  --label "OpenRouter API key" \
  --validator opaque
```

Send only `request_url` to the user. The link contains a random request identifier, never the secret. The browser sends the value in an HTTPS POST body.

Supported validators:

- `opaque`: a non-empty single-line secret
- `google-calendar-ics`: a private Google Calendar ICS URL with bounded validation

Environment names are constrained to uppercase secret-like keys. The browser cannot choose the key, destination, validator, command, or file path.

## Link lifecycle

- Hard server-side lifetime: 15 minutes maximum
- Single use: successful submission retires the active request immediately
- Expiration: a background cleanup loop retires expired active requests
- Status: short-lived hashed tombstones contain only sanitized state and are purged automatically
- Base service: health and one-time request routes only; there is no request list or secret retrieval endpoint

## Commands

```bash
hermes-secret-drop health
hermes-secret-drop demo
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

## Uninstall

```bash
python3 scripts/uninstall.py
```

Uninstall stops the service, removes its Tailnet listener, destroys active request metadata, and removes the local package and skill. It does **not** delete secrets already saved in the Hermes `.env`.

## Security

Read [SECURITY.md](SECURITY.md) before adapting the service. Core guarantees are enforced by deterministic code and tests, not by AI instructions.

## Give this prompt to your AI

The Humanity Labs install prompt is in [docs/give-this-prompt-to-your-ai.md](docs/give-this-prompt-to-your-ai.md).
