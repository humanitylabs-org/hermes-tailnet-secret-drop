# Give this prompt to your AI

The fenced text below is the exact Humanity Labs copy prompt.

```text
Install Hermes Tailnet Secret Drop v1.1.0 from https://github.com/humanitylabs-org/hermes-tailnet-secret-drop on this Hermes device. It gives me a private, one-time Tailnet page for entering API keys, tokens, passwords, and private URLs without pasting them into AI chat.

Complete and verify the installation:

1. Check for Linux, Python 3.10+, git, systemd user services, Hermes Agent, and Tailscale. Tailscale is mandatory and must be connected with MagicDNS. If it is missing, explain why Secret Drop needs a tailnet, point me to https://tailscale.com/download, and offer the official Linux install command: `curl -fsSL https://tailscale.com/install.sh | sh`. Ask before running that command, sudo, or any package-manager action. If Tailscale needs authentication, help me run `sudo tailscale up`, ask before sudo, and wait for me to complete sign-in. Never enable Funnel.

2. Clone the repository at reviewed tag `v1.1.0`, or safely update an existing clean checkout to that tag. Do not overwrite unrelated local changes. Verify `git describe --tags --exact-match` returns `v1.1.0`.

3. Run `./scripts/prereq-check.sh`, fix missing requirements one safe step at a time, then run `./scripts/setup.sh`.

4. Verify the user service is enabled and active, `hermes-secret-drop health` passes, and the private Tailnet `/health` URL returns `ok`. Confirm exposure uses Tailscale Serve or TLS bound only to the device's Tailscale IP—not a public interface—and that no list, retrieval, export, or reveal endpoint exists.

5. Create a disposable demo with `hermes-secret-drop demo`. Send me its whole clickable link, including the part after the `#`, and tell me to enter only a fake value. The demo must discard the value, work once, expire within 15 minutes, and remove its active request after use or expiration.

In your final response, explain that Secret Drop lets Hermes request credentials through a private one-time page so raw values stay out of chat. State honestly that saved credentials remain readable by the Hermes host account. Include the demo link, expiration, installed mode, health evidence, this real-request example—`hermes-secret-drop create --key EXAMPLE_API_KEY --label "Example API key"`—the provider-bound form `hermes-secret-drop create --adapter openrouter-hermes`, and the uninstall command: `python3 scripts/uninstall.py`.

Never ask me to paste a real credential into chat, print existing `.env` contents, put secrets in URLs or command arguments, use Funnel, expose a public listener, claim a provider verified a key when only syntax was checked, or claim success before verification. Preserve unrelated Hermes configuration and `.env` entries. After I test the demo, verify only sanitized status and confirm the demo value was discarded and the active link is gone.
```
