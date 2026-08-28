#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

prereq_mode="tailnet"
for arg in "$@"; do
  if [[ "$arg" == "--access-protected-public-base-url" || "$arg" == --access-protected-public-base-url=* ]]; then
    prereq_mode="cloudflare-access"
    break
  fi
done
./scripts/prereq-check.sh --mode "$prereq_mode"

install_json="$(python3 scripts/install.py "$@")"
command_path="$(printf '%s' "$install_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["command"])')"
mode="$(printf '%s' "$install_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["mode"])')"
base_url="$(printf '%s' "$install_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_base_url"])')"

demo_json="$("$command_path" demo)"
demo_url="$(printf '%s' "$demo_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["request_url"])')"
expires_at="$(printf '%s' "$demo_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["expires_at"])')"

cat <<EOF

Hermes Tailnet Secret Drop is ready.

It gives Hermes a private way to ask you for an API key, token, password, or private URL without putting the value in chat. The entry page is reachable only on your tailnet, accepts one value, and never offers a list or reveal screen.

Disposable demo link:
$demo_url

Use a fake value. The demo discards what you enter. This link works once, expires within two hours, and its active request is removed after use or expiration.

Installed mode: $mode
Private service: $base_url
Create a real request: $command_path create --key EXAMPLE_API_KEY --label "Example API key"
EOF

printf 'Demo expires at: %s\n' "$expires_at"
