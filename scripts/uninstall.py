#!/usr/bin/env python3
"""Uninstall Secret Drop without removing any saved Hermes secrets."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

APP_NAME = "hermes-tailnet-secret-drop"
SERVICE_NAME = f"{APP_NAME}.service"
CERT_SERVICE_NAME = f"{APP_NAME}-cert.service"
CERT_TIMER_NAME = f"{APP_NAME}-cert.timer"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Uninstall Hermes Tailnet Secret Drop")
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    parser.add_argument("--state-dir", type=Path, default=state_home / APP_NAME)
    parser.add_argument("--install-dir", type=Path, default=data_home / APP_NAME)
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local" / "bin")
    parser.add_argument("--unit-dir", type=Path, default=Path.home() / ".config" / "systemd" / "user")
    args = parser.parse_args()

    state_dir = args.state_dir.expanduser().resolve()
    config_path = state_dir / "config.json"
    config: dict[str, object] = {}
    if config_path.exists():
        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config = loaded
        except (OSError, json.JSONDecodeError):
            pass

    warnings: list[str] = []
    systemctl = shutil.which("systemctl")
    if systemctl:
        for unit in (CERT_TIMER_NAME, CERT_SERVICE_NAME, SERVICE_NAME):
            run([systemctl, "--user", "disable", "--now", unit])

    if config.get("mode") == "tailscale-serve" and shutil.which("tailscale"):
        port = int(str(config.get("https_port") or 0))
        if port:
            result = run(["tailscale", "serve", "--yes", f"--https={port}", "off"])
            if result.returncode != 0:
                warnings.append(f"Could not remove the Tailscale Serve handler on HTTPS port {port}; remove that handler manually.")

    for unit in (SERVICE_NAME, CERT_SERVICE_NAME, CERT_TIMER_NAME):
        try:
            (args.unit_dir.expanduser().resolve() / unit).unlink()
        except FileNotFoundError:
            pass
    if systemctl:
        run([systemctl, "--user", "daemon-reload"])

    try:
        (args.bin_dir.expanduser().resolve() / "hermes-secret-drop").unlink()
    except FileNotFoundError:
        pass
    shutil.rmtree(args.install_dir.expanduser().resolve(), ignore_errors=True)
    shutil.rmtree(state_dir, ignore_errors=True)

    hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")).expanduser().resolve()
    shutil.rmtree(hermes_home / "skills" / APP_NAME, ignore_errors=True)

    print(
        json.dumps(
            {
                "status": "uninstalled",
                "saved_secrets_preserved": True,
                "warnings": warnings,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
