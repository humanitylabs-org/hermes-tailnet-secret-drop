# Give this prompt to your AI

The fenced text below is the exact Humanity Labs copy prompt.

```text
Install Hermes Secret Drop v1.3.2 from https://github.com/humanitylabs-org/hermes-tailnet-secret-drop on this Hermes VPS. Use the recommended Cloudflare Access mode so I can enter API keys, tokens, passwords, and private URLs without pasting them into AI chat.

Complete and verify the installation:

1. Check for Linux, Python 3.10+, git, systemd user services, Hermes Agent, and the Python dependency in requirements.txt. Confirm I already have an exact Cloudflare Access-protected HTTPS route and Tunnel origin for Secret Drop. The origin must be `http://127.0.0.1:<port>`; do not expose a public listener. If a package or privileged action is needed, ask before running sudo or any package-manager command.

2. Clone the repository at reviewed tag `v1.3.2`, or safely update an existing clean checkout to that tag. Do not overwrite unrelated changes. Verify `git describe --tags --exact-match` returns `v1.3.2`.

3. Run `./scripts/prereq-check.sh --mode cloudflare-access`, fix missing requirements one safe step at a time, then run `./scripts/setup.sh --access-protected-public-base-url <exact-access-url> --http-port <loopback-port>`.

4. Verify the user service is enabled and active, `hermes-secret-drop health` passes, the loopback health route under the configured public path returns `ok`, the bare loopback `/health` path returns 404 in Cloudflare mode, and the public route stops at Cloudflare Access for an unauthenticated browser. Confirm the service accepts only encrypted envelopes and exposes no list, retrieval, export, or reveal endpoint.

5. Create a disposable demo with `hermes-secret-drop demo`. Send me its complete clickable link, including the part after `#`, and tell me to enter only a fake value. The demo must be discarded, work once, expire within two hours, and leave sanitized status showing the active link is gone.

In your final response, state that the browser encrypts values before transmission and that ordinary Cloudflare edge processing sees ciphertext, while saved credentials remain readable by the Hermes host account. Also state that Cloudflare still serves the page code, so removing all Cloudflare trust would require a pinned client or private overlay. Include health evidence, installed mode, demo link and expiration, `hermes-secret-drop create --key EXAMPLE_API_KEY --label "Example API key"`, `hermes-secret-drop create --adapter openrouter-hermes`, and `python3 scripts/uninstall.py`.

Never ask me to paste a real credential into chat, print `.env`, put values in URLs or command arguments, add a plaintext fallback, enable Funnel, expose a public origin listener, or claim provider verification when only syntax was checked. Preserve unrelated Hermes settings and `.env` entries.
```
