---
name: hermes-tailnet-secret-drop
description: Create private, one-time encrypted links so a user can enter agent credentials without pasting them into chat.
version: 1.3.2-telos.2
author: Humanity Labs
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [cloudflare, tailscale, encryption, secrets, credentials, onboarding, privacy]
---

# Hermes Tailnet Secret Drop

Use this skill when a user needs to add or replace an API key, token, password, credential, or private URL used by Hermes.

## Create a real request

1. Confirm the installed service is healthy:

```bash
hermes-secret-drop health
```

2. Create one narrowly named request.

If an adapter exists for the provider, use it. It fixes the key, label, and a real provider check together:

```bash
hermes-secret-drop create --adapter openrouter-hermes
```

Available adapters: `openrouter-hermes` (binds `OPENROUTER_API_KEY` and verifies the key with OpenRouter). Do not invent adapter names.

Otherwise create a generic request. The key must be an uppercase environment variable that clearly ends in `_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_PASS`, `_URL`, `_URI`, or `_CREDENTIAL`.

```bash
hermes-secret-drop create \
  --key EXAMPLE_API_KEY \
  --label "Example API key" \
  --validator opaque
```

Use `--validator google-calendar-ics` only for a private Google Calendar ICS URL. Do not invent validator names. `--adapter` cannot be combined with `--key`, `--label`, or `--validator`; the adapter fixes all three.

3. Send only the returned `request_url`, as a raw URL on its own line. Its `/drop/...` path is the capability that opens the page; the app removes it from the address after loading. Never ask the user to paste the value into chat, and never include the capability in a summary.
4. Tell the user the link uses the installation's private delivery path, works once, and expires at the returned time. James's deployment defaults to 24 hours; new WizardOS installations normally use Cloudflare Access and Tunnel, while legacy/private-overlay installs may use Tailnet mode. Do not claim it hides the credential from the Hermes host.
5. Be accurate about what was verified. `opaque` checks only that the value is a safe, non-empty, single line; it contacts no provider. Claim a provider verified a key only when an adapter performed that check.
6. Creating a new request for a key you already requested retires the older pending link for that key as `superseded`. Tell the user to use the newest link.
7. After the user submits, check sanitized state with `hermes-secret-drop status <request-id>` if needed. The `request_id` is a one-way digest and is safe to keep; it is not the capability. Never inspect or print the stored value.
8. If the running Hermes process must pick up a newly written `.env` value, use Hermes's normal `/reload` or safe restart flow.

## Disposable demo

Use this after installation or when the user wants to see the interface:

```bash
hermes-secret-drop demo
```

The demo accepts only a fake value. It discards the submitted value instead of writing it to the Hermes environment. Its active request is removed after use or expiration.

## Security contract

- The service supports loopback-only HTTP behind an exact Cloudflare Access/Tunnel route and legacy Tailnet-only HTTPS. It never uses Tailscale Funnel or a public origin listener.
- The browser can submit one value but cannot list, retrieve, export, prefill, or reveal stored values.
- The eye icon shows only the value currently typed in that browser.
- A link is single-use. James's deployment defaults to a 24-hour lifetime and allows operators to configure a shorter cap.
- James's Cloudflare Access deployment carries the capability in the initial path so authentication redirects and chat clients preserve it, then removes it from the address after page load. Cloudflare may observe that routing metadata; the service stores only its SHA-256 digest and requires the capability in a fixed header for metadata and submission.
- Active request metadata never stores the submitted secret or the capability. Used, expired, and superseded request files are retired automatically; short-lived tombstones preserve sanitized status only.
- Before transmission, the browser encrypts all entered values with a fresh AES-256-GCM key, wraps that key with the host's RSA-OAEP/SHA-256 public key, and binds the ciphertext to the one-time capability digest. The server accepts no plaintext fallback.
- Cloudflare may observe routing metadata, the capability header, and ciphertext in Access mode, but not the entered value during ordinary operation. Because Cloudflare serves the page code, a malicious edge remains able to substitute code; removing that last trust requires a pinned client or direct private overlay.
- Submissions are accepted only from the service's own origin.
- The browser cannot choose the adapter, environment key, destination, validator, command, or file path.
- A value is verified before the existing `.env` entry is replaced. A rejected value leaves the previous credential intact and the link reusable.
- An older link can never overwrite a credential after a newer link for the same key has been issued.
- Secrets are written atomically to the configured Hermes `.env` with restrictive permissions and unrelated entries preserved.
- Secret Drop keeps credentials out of chat; it does not make an agent-usable secret unreadable to the operating-system account running Hermes.

## Lifecycle

- Health: `hermes-secret-drop health`
- Retire expired requests now: `hermes-secret-drop cleanup`
- Reinstall/update from the checkout: `./scripts/setup.sh`
- Uninstall the service, routes, active links, and local package while preserving saved Hermes secrets: `python3 scripts/uninstall.py`
