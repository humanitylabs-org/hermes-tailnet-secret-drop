#!/usr/bin/env python3
"""Install Hermes Tailnet Secret Drop as a private user service."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

APP_NAME = "hermes-tailnet-secret-drop"
INSTALL_MARKER = f".{APP_NAME}-managed"
MANAGED_FILE_MARKER = f"# Managed by {APP_NAME}"
SERVICE_NAME = f"{APP_NAME}.service"
CERT_SERVICE_NAME = f"{APP_NAME}-cert.service"
CERT_TIMER_NAME = f"{APP_NAME}-cert.timer"
DEFAULT_HTTPS_PORT = 8805


class InstallError(RuntimeError):
    pass


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise InstallError(f"{shlex.join(command)}: {detail}")
    return result


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def reject_symlink_components(path: Path) -> None:
    absolute = lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise InstallError(f"Installation path contains a symlink: {current}")


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def prepare_managed_directory(path: Path) -> None:
    reject_symlink_components(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir():
        raise InstallError(f"Installation path is not a directory: {path}")
    marker = path / INSTALL_MARKER
    if marker.is_symlink():
        raise InstallError(f"Installation directory has an unsafe ownership marker: {path}")
    existing_entries = [entry for entry in path.iterdir() if entry != marker]
    if existing_entries and not marker.is_file():
        raise InstallError(f"Refusing to take ownership of non-empty unmarked directory: {path}")
    if marker.exists():
        marker_payload = load_json_if_present(marker)
        if marker_payload != {"app": APP_NAME, "marker_version": 1}:
            raise InstallError(f"Installation directory has an invalid ownership marker: {path}")
    os.chmod(path, 0o700)
    atomic_json(marker, {"app": APP_NAME, "marker_version": 1})


def atomic_replace_text(path: Path, content: str, mode: int) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def write_managed_text(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(path)
    if path.exists():
        if not path.is_file():
            raise InstallError(f"Refusing to replace non-file installation target: {path}")
        try:
            existing = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise InstallError(f"Refusing to replace unreadable installation target: {path}") from exc
        if MANAGED_FILE_MARKER not in existing.splitlines()[:3]:
            raise InstallError(f"Refusing to replace unowned installation target: {path}")
    if MANAGED_FILE_MARKER not in content.splitlines()[:3]:
        raise InstallError("Managed file content is missing its ownership marker.")
    atomic_replace_text(path, content, mode)


def copy_into_managed_directory(source: Path, destination: Path, mode: int) -> None:
    if source.is_symlink() or not source.is_file():
        raise InstallError(f"Installation source is unsafe: {source}")
    reject_symlink_components(destination)
    try:
        content = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InstallError(f"Installation source is unreadable: {source}") from exc
    atomic_replace_text(destination, content, mode)


def prepare_env_file(path: Path) -> None:
    reject_symlink_components(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        metadata = path.stat()
        if not path.is_file() or metadata.st_nlink != 1:
            raise InstallError(f"Refusing to use unsafe Hermes environment file: {path}")
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    os.chmod(path, 0o600)


def load_json_if_present(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def tailscale_identity() -> tuple[str, str]:
    if not shutil.which("tailscale"):
        raise InstallError("Tailscale is required. Install and connect it first: https://tailscale.com/download")
    try:
        payload = json.loads(run(["tailscale", "status", "--json"]).stdout)
    except (json.JSONDecodeError, InstallError) as exc:
        raise InstallError("Tailscale is installed but not connected. Run `tailscale up`, complete sign-in, then retry.") from exc
    if payload.get("BackendState") != "Running":
        raise InstallError("Tailscale is not connected. Run `tailscale up`, complete sign-in, then retry.")
    self_info = payload.get("Self") or {}
    dns_name = str(self_info.get("DNSName") or "").rstrip(".")
    addresses = [str(value) for value in self_info.get("TailscaleIPs") or []]
    ipv4 = next((value for value in addresses if re.fullmatch(r"100(?:\.\d{1,3}){3}", value)), "")
    if not dns_name.endswith(".ts.net") or not ipv4:
        raise InstallError("Tailscale MagicDNS and HTTPS must be available on this device before Secret Drop can be installed.")
    return dns_name, ipv4


def hermes_paths() -> tuple[Path, Path]:
    override = os.environ.get("HERMES_HOME")
    if override:
        hermes_home = lexical_absolute(Path(override))
    else:
        hermes_home = Path.home() / ".hermes"
        if shutil.which("hermes"):
            result = run(["hermes", "config", "path"], check=False)
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if result.returncode == 0 and lines:
                candidate = Path(lines[-1]).expanduser()
                if candidate.name in {"config.yaml", "config.yml"}:
                    hermes_home = lexical_absolute(candidate.parent)
    env_override = os.environ.get("HERMES_ENV_PATH")
    if env_override:
        env_path = lexical_absolute(Path(env_override))
    else:
        env_path = hermes_home / ".env"
        if shutil.which("hermes"):
            result = run(["hermes", "config", "env-path"], check=False)
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if result.returncode == 0 and lines:
                candidate = Path(lines[-1]).expanduser()
                if candidate.is_absolute():
                    env_path = lexical_absolute(candidate)
    return hermes_home, env_path


def ensure_safe_port(port: int, config_path: Path) -> None:
    if port < 1024 or port > 65535:
        raise InstallError("The HTTPS port must be between 1024 and 65535.")
    existing = load_json_if_present(config_path)
    same_install = int(existing.get("https_port") or 0) == port
    status = run(["tailscale", "serve", "status", "--json"], check=False)
    if status.returncode != 0 or not status.stdout.strip():
        return
    try:
        payload = json.loads(status.stdout)
    except json.JSONDecodeError:
        return
    if str(port) in (payload.get("TCP") or {}) and not same_install:
        raise InstallError(
            f"Tailscale HTTPS port {port} is already in use. Retry with `python3 scripts/install.py --https-port <free-port>`."
        )


def write_service(unit_path: Path, python: str, script: Path, config: Path, env_path: Path, state_dir: Path) -> None:
    for value in (python, str(script), str(config), str(env_path), str(state_dir)):
        if "\n" in value or "\r" in value:
            raise InstallError("Unsafe newline in service path.")
    unit = f"""{MANAGED_FILE_MARKER}
[Unit]
Description=Hermes Tailnet Secret Drop
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart={shlex.quote(python)} {shlex.quote(str(script))} --config {shlex.quote(str(config))} serve
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={shlex.quote(str(env_path))} {shlex.quote(str(state_dir))}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=default.target
"""
    write_managed_text(unit_path, unit, 0o600)


def write_cert_units(
    user_unit_dir: Path,
    tailscale_bin: str,
    systemctl_bin: str,
    dns_name: str,
    cert_path: Path,
    key_path: Path,
) -> None:
    service = f"""{MANAGED_FILE_MARKER}
[Unit]
Description=Refresh TLS certificate for Hermes Tailnet Secret Drop
After=network-online.target

[Service]
Type=oneshot
UMask=0077
ExecStart={shlex.quote(tailscale_bin)} cert --cert-file {shlex.quote(str(cert_path))} --key-file {shlex.quote(str(key_path))} {shlex.quote(dns_name)}
ExecStartPost={shlex.quote(systemctl_bin)} --user try-restart {SERVICE_NAME}
"""
    timer = f"""{MANAGED_FILE_MARKER}
[Unit]
Description=Weekly TLS certificate refresh for Hermes Tailnet Secret Drop

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h
Unit={CERT_SERVICE_NAME}

[Install]
WantedBy=timers.target
"""
    user_unit_dir.mkdir(parents=True, exist_ok=True)
    for path, content in (
        (user_unit_dir / CERT_SERVICE_NAME, service),
        (user_unit_dir / CERT_TIMER_NAME, timer),
    ):
        write_managed_text(path, content, 0o600)


def issue_certificate(tailscale_bin: str, dns_name: str, cert_path: Path, key_path: Path) -> None:
    reject_symlink_components(cert_path)
    reject_symlink_components(key_path)
    temp_dir = Path(tempfile.mkdtemp(prefix=".cert-install.", dir=cert_path.parent))
    temp_cert = temp_dir / "tls.crt"
    temp_key = temp_dir / "tls.key"
    try:
        result = run(
            [
                tailscale_bin,
                "cert",
                "--cert-file",
                str(temp_cert),
                "--key-file",
                str(temp_key),
                dns_name,
            ],
            check=False,
        )
        if result.returncode != 0 or not temp_cert.is_file() or not temp_key.is_file():
            raise InstallError(
                "Tailscale Serve was unavailable and a direct Tailnet certificate could not be issued. "
                "Enable HTTPS certificates for this tailnet/device, then retry."
            )
        os.replace(temp_cert, cert_path)
        os.replace(temp_key, key_path)
        os.chmod(cert_path, 0o644)
        os.chmod(key_path, 0o600)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def write_wrapper(path: Path, python: str, script: Path, config_path: Path) -> None:
    content = (
        "#!/usr/bin/env sh\n"
        f"{MANAGED_FILE_MARKER}\n"
        f"exec {shlex.quote(python)} {shlex.quote(str(script))} --config {shlex.quote(str(config_path))} \"$@\"\n"
    )
    write_managed_text(path, content, 0o700)


def probe_local(wrapper: Path) -> None:
    last = None
    for _ in range(40):
        last = run([str(wrapper), "health"], check=False)
        if last.returncode == 0:
            return
        time.sleep(0.25)
    detail = ((last.stderr or last.stdout) if last else "no response").strip()
    raise InstallError(f"Secret Drop service did not become healthy: {detail}")


def probe_tailnet(base_url: str) -> None:
    request_url = base_url.rstrip("/") + "/health"
    last_error: Exception | None = None
    for _ in range(30):
        try:
            request = Request(request_url, headers={"User-Agent": "Hermes-Secret-Drop-Installer/1.0"})
            with urlopen(request, timeout=10) as response:
                body = response.read(4096)
                if response.status == 200 and b'"status":"ok"' in body:
                    return
        except (URLError, TimeoutError, OSError) as exc:
            last_error = exc
        time.sleep(0.25)
    error_name = type(last_error).__name__ if last_error else "unexpected response"
    raise InstallError(f"Tailnet health endpoint was not reachable ({error_name}).")


def install(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[1]
    source_script = repo_root / "src" / "secret_drop.py"
    source_skill = repo_root / "skill" / "SKILL.md"
    if not source_script.is_file() or not source_skill.is_file():
        raise InstallError("Run the installer from a complete Hermes Tailnet Secret Drop checkout.")

    dns_name, tailscale_ipv4 = tailscale_identity()
    hermes_home, env_path = hermes_paths()
    state_dir = lexical_absolute(args.state_dir)
    install_dir = lexical_absolute(args.install_dir)
    bin_dir = lexical_absolute(args.bin_dir)
    user_unit_dir = lexical_absolute(args.unit_dir)
    skill_dir = hermes_home / "skills" / APP_NAME
    config_path = state_dir / "config.json"
    socket_path = state_dir / "secret-drop.sock"
    cert_path = state_dir / "tls.crt"
    key_path = state_dir / "tls.key"
    installed_script = install_dir / "secret_drop.py"
    wrapper = bin_dir / "hermes-secret-drop"
    https_port = args.https_port

    ensure_safe_port(https_port, config_path)
    for path in (state_dir, install_dir, skill_dir, env_path, bin_dir, user_unit_dir):
        reject_symlink_components(path)
    for directory in (state_dir, install_dir, skill_dir):
        prepare_managed_directory(directory)
    prepare_env_file(env_path)
    copy_into_managed_directory(source_script, installed_script, 0o700)
    copy_into_managed_directory(source_skill, skill_dir / "SKILL.md", 0o600)
    write_wrapper(wrapper, sys.executable, installed_script, config_path)

    public_base_url = f"https://{dns_name}:{https_port}"
    base_config: dict[str, Any] = {
        "app": APP_NAME,
        "env_path": str(env_path),
        "https_port": https_port,
        "mode": "staged",
        "public_base_url": public_base_url,
        "socket_path": str(socket_path),
        "state_dir": str(state_dir),
        "version": "1",
    }
    atomic_json(config_path, base_config)
    unit_path = user_unit_dir / SERVICE_NAME
    write_service(unit_path, sys.executable, installed_script, config_path, env_path, state_dir)

    if args.no_start:
        return {
            "status": "staged",
            "command": str(wrapper),
            "public_base_url": public_base_url,
            "service": SERVICE_NAME,
        }

    systemctl_bin = shutil.which("systemctl")
    tailscale_bin = shutil.which("tailscale")
    if not systemctl_bin or not tailscale_bin:
        raise InstallError("systemd user services and the Tailscale CLI are required on this Linux package.")
    run([systemctl_bin, "--user", "daemon-reload"])
    run([systemctl_bin, "--user", "enable", "--now", SERVICE_NAME])
    probe_local(wrapper)

    mode = "tailscale-serve"
    serve_result = run(
        [
            tailscale_bin,
            "serve",
            "--yes",
            "--bg",
            f"--https={https_port}",
            f"unix:{socket_path}",
        ],
        check=False,
    )
    if serve_result.returncode == 0:
        run([systemctl_bin, "--user", "disable", "--now", CERT_TIMER_NAME], check=False)
    else:
        mode = "rootless-tailnet-https"
        issue_certificate(tailscale_bin, dns_name, cert_path, key_path)
        tls_config = dict(base_config)
        tls_config.update(
            {
                "mode": mode,
                "https_host": tailscale_ipv4,
                "tls_cert": str(cert_path),
                "tls_key": str(key_path),
            }
        )
        atomic_json(config_path, tls_config)
        write_cert_units(
            user_unit_dir,
            tailscale_bin,
            systemctl_bin,
            dns_name,
            cert_path,
            key_path,
        )
        run([systemctl_bin, "--user", "daemon-reload"])
        run([systemctl_bin, "--user", "enable", "--now", CERT_TIMER_NAME])
        run([systemctl_bin, "--user", "restart", SERVICE_NAME])
        probe_local(wrapper)

    final_config = load_json_if_present(config_path)
    final_config["mode"] = mode
    atomic_json(config_path, final_config)
    probe_tailnet(public_base_url)
    return {
        "status": "installed",
        "command": str(wrapper),
        "demo_command": f"{wrapper} demo",
        "mode": mode,
        "public_base_url": public_base_url,
        "service": SERVICE_NAME,
        "skill": str(skill_dir / "SKILL.md"),
    }


def build_parser() -> argparse.ArgumentParser:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    parser = argparse.ArgumentParser(description="Install Hermes Tailnet Secret Drop")
    parser.add_argument("--https-port", type=int, default=DEFAULT_HTTPS_PORT)
    parser.add_argument("--state-dir", type=Path, default=state_home / APP_NAME)
    parser.add_argument("--install-dir", type=Path, default=data_home / APP_NAME)
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local" / "bin")
    parser.add_argument("--unit-dir", type=Path, default=Path.home() / ".config" / "systemd" / "user")
    parser.add_argument("--no-start", action="store_true", help=argparse.SUPPRESS)
    return parser


def main() -> None:
    os.umask(0o077)
    try:
        result = install(build_parser().parse_args())
        print(json.dumps(result, indent=2, sort_keys=True))
    except (InstallError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
