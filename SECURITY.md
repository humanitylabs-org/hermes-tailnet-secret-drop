# Security model

Hermes Tailnet Secret Drop is a narrow write-only credential intake service.

## Intended guarantees

- The web surface is reachable only through the user's tailnet.
- Tailscale Funnel is never configured.
- Every request is random, single-use, and valid for at most 15 minutes.
- The request URL contains only a random identifier.
- Secret values are accepted only in an HTTPS POST body.
- Values are never echoed in responses, stored in request metadata, printed by the CLI, included in command-line arguments, or written to application logs.
- There is no HTTP or CLI operation to list, retrieve, export, prefill, or reveal stored secrets.
- The eye control reveals only the value currently typed in the browser.
- The browser cannot select environment names, validators, paths, commands, programs, or destinations.
- Real values are written atomically to the configured Hermes `.env`; unrelated entries are preserved and file permissions are restricted.
- Demo values are validated and discarded without storage.
- Used and expired active request files are retired. Sanitized status tombstones are keyed by a one-way hash and automatically purged.

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
- The public base route returns no UI. Only `/health` and random `/r/<id>` routes exist.

## Reporting a vulnerability

Do not open a public issue containing a credential, live request URL, private hostname, certificate, local path, or exploit payload tied to a real system. Use this repository's private **Report a vulnerability** flow instead.
