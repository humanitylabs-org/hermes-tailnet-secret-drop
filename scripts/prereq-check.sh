#!/usr/bin/env bash
set -euo pipefail

FAIL=0
FIXES=()
MODE="tailnet"
if [[ "${1:-}" == "--mode" && "${2:-}" == "cloudflare-access" ]]; then
  MODE="cloudflare-access"
elif [[ "${1:-}" == "--mode" && "${2:-}" != "tailnet" ]]; then
  printf 'Usage: %s [--mode tailnet|cloudflare-access]\n' "$0" >&2
  exit 2
fi

ok() { printf '[ok] %s\n' "$1"; }
fail() {
  printf '[missing] %s\n' "$1"
  FAIL=1
  FIXES+=("$2")
}

printf 'Hermes Tailnet Secret Drop prerequisites\n\n'

if [[ "$(uname -s)" == "Linux" ]]; then
  ok "Linux"
else
  fail "Linux is required by this first release" "Install on a Linux Hermes host with systemd user services."
fi

if command -v python3 >/dev/null 2>&1; then
  if python3 - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
  then
    ok "Python 3.10+"
  else
    fail "Python 3.10+" "Install Python 3.10 or newer, then rerun this check."
  fi
else
  fail "python3" "Install Python 3.10 or newer, then rerun this check."
fi

if python3 - <<'PY' >/dev/null 2>&1
import re
from importlib.metadata import version
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

match = re.match(r"^(\d+)(?:\.|$)", version("cryptography"))
raise SystemExit(0 if match and 41 <= int(match.group(1)) < 51 else 1)
PY
then
  ok "Python cryptography package"
else
  fail "Python cryptography>=41,<51" "Install the repository's declared Python dependency into the environment used for setup, then rerun this check."
fi

if command -v git >/dev/null 2>&1; then
  ok "git"
else
  fail "git" "Install git. On Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y git"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  ok "systemd user services"
else
  fail "systemd user services" "Use a systemd-based Linux host and make sure your user session can run: systemctl --user status"
fi

if command -v hermes >/dev/null 2>&1; then
  if hermes --version >/dev/null 2>&1 && hermes config path >/dev/null 2>&1; then
    ok "Hermes Agent"
  else
    fail "working Hermes Agent configuration" "Run: hermes doctor\nThen complete setup with: hermes setup"
  fi
else
  fail "Hermes Agent" "Install Hermes from https://hermes-agent.nousresearch.com/docs, then run: hermes setup"
fi

if [[ "$MODE" == "cloudflare-access" ]]; then
  ok "Cloudflare Access mode selected (Tailscale not required)"
elif command -v tailscale >/dev/null 2>&1; then
  ok "Tailscale CLI"
  if tailscale status --json | python3 -c '
import json, re, sys
p = json.load(sys.stdin)
s = p.get("Self") or {}
dns = str(s.get("DNSName") or "").rstrip(".")
ips = [str(x) for x in s.get("TailscaleIPs") or []]
ok = p.get("BackendState") == "Running" and dns.endswith(".ts.net") and any(re.fullmatch(r"100(?:\.\d{1,3}){3}", x) for x in ips)
raise SystemExit(0 if ok else 1)
' >/dev/null 2>&1; then
    ok "Tailscale connected with MagicDNS"
  else
    fail "connected Tailscale with MagicDNS" "Run: tailscale up\nComplete sign-in, make sure MagicDNS is enabled, then rerun this check."
  fi
else
  fail "Tailscale" "Install Tailscale from https://tailscale.com/download\nLinux quick install (requires your approval): curl -fsSL https://tailscale.com/install.sh | sh\nThen connect it with: sudo tailscale up"
fi

if [[ "$FAIL" -ne 0 ]]; then
  printf '\nSuggested safe fixes\n--------------------\n'
  i=1
  for fix in "${FIXES[@]}"; do
    printf '%s) %b\n\n' "$i" "$fix"
    i=$((i + 1))
  done
  printf 'Fix one required item at a time, rerun ./scripts/prereq-check.sh, and ask before any sudo or package-manager command.\n'
  exit 1
fi

printf '\nAll required checks passed.\n'
