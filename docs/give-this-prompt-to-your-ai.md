# Draft: Give this prompt to your AI

Proposed copy for the Humanity Labs card. The `v1.0.0` tag must exist and be reviewed before this prompt is published.

```text
Install Hermes Tailnet Secret Drop v1.0.0 from https://github.com/humanitylabs-org/hermes-tailnet-secret-drop on this Hermes device.

Goal: give me a private, one-time Tailnet page where I can enter API keys, tokens, passwords, credentials, and private URLs without pasting the raw value into AI chat. This protects the chat/transcript boundary; do not claim it hides agent-usable secrets from the Hermes host.

Please complete this safely and verify each step:
1) Confirm this is a Linux host with Python 3.10+, git, systemd user services, and a working Hermes Agent installation. If Hermes is missing or unhealthy, use the official docs at https://hermes-agent.nousresearch.com/docs and fix one prerequisite at a time.
2) Treat Tailscale as mandatory. Check whether the Tailscale CLI is installed, connected, and has a `.ts.net` MagicDNS name.
   - If Tailscale is missing, explain that Secret Drop is private because it is reachable only through the user's tailnet. Point me to https://tailscale.com/download and offer the official Linux quick install: `curl -fsSL https://tailscale.com/install.sh | sh`. Ask for my approval before running that installer, sudo, or any package-manager command.
   - If Tailscale is installed but disconnected, run or propose `sudo tailscale up`, ask before sudo, give me the sign-in link or action, and wait for me to finish authentication.
   - Re-check Tailscale after every fix. Do not use Tailscale Funnel.
3) Install the reviewed release, not an arbitrary moving branch:
   - If no checkout exists, clone the repo at tag `v1.0.0` into a normal local projects folder.
   - If a checkout already exists, require a clean working tree, fetch tags, and check out `v1.0.0`. If it has unrelated local changes, stop and explain instead of overwriting them.
   - Verify `git describe --tags --exact-match` returns `v1.0.0`.
4) From the repo, run `./scripts/prereq-check.sh`. If it reports a missing prerequisite, use its Suggested safe fixes one at a time, ask before privileged/package-manager actions, and rerun the check after each fix.
5) Run `./scripts/setup.sh`. It should install or update the user service, install the `hermes-secret-drop` command and Hermes skill, configure private Tailnet HTTPS, verify health, and create a disposable demo link. It must never enable Funnel.
6) Verify the real installation:
   - `systemctl --user is-enabled hermes-tailnet-secret-drop.service`
   - `systemctl --user is-active hermes-tailnet-secret-drop.service`
   - `hermes-secret-drop health`
   - the returned private Tailnet `/health` URL returns status `ok`
   - the service is exposed only through Tailscale Serve or a TLS listener bound to the device's Tailscale IP, never a public interface
   - the public base route, `/requests`, `/secrets`, and `/env` do not list or reveal anything
7) Create a fresh disposable demo with `hermes-secret-drop demo` if setup did not already return one. Send me the clickable `request_url` and tell me to enter only a fake value. The demo must discard the submitted value, work once, expire within 15 minutes, and retire its active request after use or expiration.
8) In your final feedback, introduce the feature in plain English: Secret Drop lets Hermes ask me for a credential through a private one-time Tailnet page so the raw value never has to appear in chat. State honestly that values saved for Hermes remain readable by the Hermes host account. Include the demo link, its expiration, installed mode, health evidence, and these examples:
   - demo: `hermes-secret-drop demo`
   - real request: `hermes-secret-drop create --key EXAMPLE_API_KEY --label "Example API key"`
   - uninstall: `python3 scripts/uninstall.py` from the repo
9) After I test the demo, verify only sanitized state. Confirm the demo value was discarded and the active link is gone; never inspect, print, or repeat what I typed.

Rules:
- Never ask me to paste a real credential into chat.
- Never print existing `.env` contents or secret values.
- Never put a secret in a URL, query string, fragment, command-line argument, log, test fixture, or response.
- Do not add a read/list/export/reveal endpoint.
- Do not use Funnel or expose the service on a public interface.
- Do not claim success until the service and private Tailnet health checks pass.
- Preserve unrelated Hermes configuration and existing `.env` entries.
```
