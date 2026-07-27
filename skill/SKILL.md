---
name: hermes-tailnet-secret-drop
description: Create private, one-time Tailnet links so a user can enter agent credentials without pasting them into chat.
version: 1.0.0-draft
author: Humanity Labs
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [tailscale, secrets, credentials, onboarding, privacy]
---

# Hermes Tailnet Secret Drop

Use this skill when a user needs to add or replace an API key, token, password, credential, or private URL used by Hermes.

## Create a real request

1. Confirm the installed service is healthy:

```bash
hermes-secret-drop health
```

2. Create one narrowly named request. The key must be an uppercase environment variable that clearly ends in `_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_PASS`, `_URL`, `_URI`, or `_CREDENTIAL`.

```bash
hermes-secret-drop create \
  --key EXAMPLE_API_KEY \
  --label "Example API key" \
  --validator opaque
```

Use `--validator google-calendar-ics` only for a private Google Calendar ICS URL. Do not invent validator names.

3. Send only the returned `request_url` to the user. Never ask the user to paste the value into chat, and never include the request identifier in a summary.
4. Tell the user the link is Tailnet-only, works once, and expires within 15 minutes. Do not claim it hides the credential from the Hermes host; its purpose is to keep the value out of chat/model transcripts and public web surfaces.
5. After the user submits, check sanitized state with `hermes-secret-drop status <request-id>` if needed. Never inspect or print the stored value.
6. If the running Hermes process must pick up a newly written `.env` value, use Hermes's normal `/reload` or safe restart flow.

## Disposable demo

Use this after installation or when the user wants to see the interface:

```bash
hermes-secret-drop demo
```

The demo accepts only a fake value. It discards the submitted value instead of writing it to the Hermes environment. Its active request is removed after use or expiration.

## Security contract

- Tailscale is a prerequisite. The web service is never exposed with Tailscale Funnel.
- The browser can submit one value but cannot list, retrieve, export, prefill, or reveal stored values.
- The eye icon shows only the value currently typed in that browser.
- A link is single-use and has a hard server-side lifetime of at most 15 minutes.
- Active request metadata never stores the submitted secret. Used and expired request files are retired automatically; short-lived hashed tombstones preserve sanitized status only.
- The value is sent in an HTTPS POST body, never in the link, query string, fragment, logs, CLI arguments, or response.
- The browser cannot choose the environment key, destination, validator, command, or file path.
- Secrets are written atomically to the configured Hermes `.env` with restrictive permissions and unrelated entries preserved.
- Secret Drop keeps credentials out of chat; it does not make an agent-usable secret unreadable to the operating-system account running Hermes.

## Lifecycle

- Health: `hermes-secret-drop health`
- Retire expired requests now: `hermes-secret-drop cleanup`
- Reinstall/update from the checkout: `./scripts/setup.sh`
- Uninstall the service, routes, active links, and local package while preserving saved Hermes secrets: `python3 scripts/uninstall.py`
