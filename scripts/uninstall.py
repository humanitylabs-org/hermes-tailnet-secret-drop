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
INSTALL_MARKER = f".{APP_NAME}-managed"
MANAGED_FILE_MARKER = f"# Managed by {APP_NAME}"
SERVICE_NAME = f"{APP_NAME}.service"
CERT_SERVICE_NAME = f"{APP_NAME}-cert.service"
CERT_TIMER_NAME = f"{APP_NAME}-cert.timer"


class UninstallError(RuntimeError):
    pass


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True)


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def reject_symlink_components(path: Path) -> None:
    absolute = lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise UninstallError(f"Refusing to remove a path containing a symlink: {current}")


def managed_directory(path: Path) -> tuple[Path, bool]:
    expanded = lexical_absolute(path)
    reject_symlink_components(expanded)
    resolved = expanded.resolve()
    if not resolved.exists():
        return resolved, False
    if not resolved.is_dir() or resolved in {Path("/"), Path.home().resolve(), Path.home().resolve().parent}:
        raise UninstallError(f"Refusing to remove unsafe installation directory: {resolved}")
    marker = resolved / INSTALL_MARKER
    if marker.is_symlink() or not marker.is_file():
        raise UninstallError(f"Refusing to remove unmarked installation directory: {resolved}")
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UninstallError(f"Refusing to remove installation directory with an invalid marker: {resolved}") from exc
    if payload != {"app": APP_NAME, "marker_version": 1}:
        raise UninstallError(f"Refusing to remove installation directory with an invalid marker: {resolved}")
    return resolved, True


def managed_file(path: Path) -> tuple[Path, bool]:
    absolute = lexical_absolute(path)
    reject_symlink_components(absolute)
    if not absolute.exists():
        return absolute, False
    if not absolute.is_file():
        raise UninstallError(f"Refusing to remove non-file installation target: {absolute}")
    try:
        lines = absolute.read_text(encoding="utf-8").splitlines()[:3]
    except (OSError, UnicodeDecodeError) as exc:
        raise UninstallError(f"Refusing to remove unreadable installation target: {absolute}") from exc
    if MANAGED_FILE_MARKER not in lines:
        raise UninstallError(f"Refusing to remove unowned installation target: {absolute}")
    return absolute, True


def main() -> None:
    parser = argparse.ArgumentParser(description="Uninstall Hermes Tailnet Secret Drop")
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    parser.add_argument("--state-dir", type=Path, default=state_home / APP_NAME)
    parser.add_argument("--install-dir", type=Path, default=data_home / APP_NAME)
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local" / "bin")
    parser.add_argument("--unit-dir", type=Path, default=Path.home() / ".config" / "systemd" / "user")
    args = parser.parse_args()

    state_dir, state_exists = managed_directory(args.state_dir)
    install_dir, install_exists = managed_directory(args.install_dir)
    hermes_home = lexical_absolute(Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")))
    skill_dir, skill_exists = managed_directory(hermes_home / "skills" / APP_NAME)
    bin_dir = lexical_absolute(args.bin_dir)
    unit_dir = lexical_absolute(args.unit_dir)
    reject_symlink_components(bin_dir)
    reject_symlink_components(unit_dir)
    unit_files = [managed_file(unit_dir / unit) for unit in (SERVICE_NAME, CERT_SERVICE_NAME, CERT_TIMER_NAME)]
    wrapper, wrapper_exists = managed_file(bin_dir / "hermes-secret-drop")
    config_path = state_dir / "config.json"
    config: dict[str, object] = {}
    if state_exists and config_path.exists():
        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config = loaded
        except (OSError, json.JSONDecodeError):
            pass

    warnings: list[str] = []
    config_is_owned = config.get("app") == APP_NAME and config.get("state_dir") == str(state_dir)
    if config and not config_is_owned:
        warnings.append("Skipped Tailscale Serve cleanup because the installation config did not match this managed state directory.")
    systemctl = shutil.which("systemctl")
    if systemctl:
        for unit, (_, exists) in zip((SERVICE_NAME, CERT_SERVICE_NAME, CERT_TIMER_NAME), unit_files, strict=True):
            if exists:
                run([systemctl, "--user", "disable", "--now", unit])

    if config_is_owned and config.get("mode") == "tailscale-serve" and shutil.which("tailscale"):
        try:
            port = int(str(config.get("https_port") or 0))
        except ValueError:
            port = 0
        if 1024 <= port <= 65535:
            result = run(["tailscale", "serve", "--yes", f"--https={port}", "off"])
            if result.returncode != 0:
                warnings.append(f"Could not remove the Tailscale Serve handler on HTTPS port {port}; remove that handler manually.")

    for path, exists in unit_files:
        if exists:
            path.unlink()
    if systemctl:
        run([systemctl, "--user", "daemon-reload"])

    if wrapper_exists:
        wrapper.unlink()
    if install_exists:
        shutil.rmtree(install_dir)
    if state_exists:
        shutil.rmtree(state_dir)

    if skill_exists:
        shutil.rmtree(skill_dir)

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
    try:
        main()
    except UninstallError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        raise SystemExit(1) from exc
