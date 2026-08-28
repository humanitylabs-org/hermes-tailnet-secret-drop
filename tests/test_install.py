from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "scripts" / "install.py"
UNINSTALL_SCRIPT = ROOT / "scripts" / "uninstall.py"
SPEC = importlib.util.spec_from_file_location("secret_drop_install", INSTALL_SCRIPT)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_dependency_preflight_enforces_the_declared_cryptography_interval(self):
        completed = subprocess.CompletedProcess([sys.executable], 0, "", "")
        with patch.object(installer, "run", return_value=completed) as run_mock:
            installer.require_cryptography()
        command = run_mock.call_args.args[0]
        self.assertIn("version('cryptography')", command[2])
        self.assertIn("41 <= int(m.group(1)) < 51", command[2])

        failed = subprocess.CompletedProcess([sys.executable], 1, "", "")
        with patch.object(installer, "run", return_value=failed), self.assertRaises(installer.InstallError):
            installer.require_cryptography()

    def test_cloudflare_migration_removes_only_its_owned_tailscale_listener(self):
        previous = {
            "mode": "tailscale-serve",
            "public_base_url": "https://node.example.ts.net:8805",
            "https_port": 8805,
            "socket_path": "/private/secret-drop.sock",
        }
        present = json.dumps(
            {
                "Web": {
                    "node.example.ts.net:8805": {
                        "Handlers": {"/": {"Proxy": "unix:/private/secret-drop.sock"}}
                    }
                }
            }
        )
        absent = json.dumps({"Web": {}})
        responses = [
            subprocess.CompletedProcess(["tailscale"], 0, present, ""),
            subprocess.CompletedProcess(["tailscale"], 0, "", ""),
            subprocess.CompletedProcess(["tailscale"], 0, absent, ""),
        ]
        with patch.object(installer.shutil, "which", return_value="/usr/bin/tailscale"):
            with patch.object(installer, "run", side_effect=responses) as run_mock:
                self.assertTrue(installer.remove_previous_tailscale_serve(previous))
        commands = [call.args[0] for call in run_mock.call_args_list]
        self.assertEqual(
            commands[1],
            ["/usr/bin/tailscale", "serve", "--yes", "--https=8805", "off"],
        )

    def test_cloudflare_migration_refuses_to_remove_a_reassigned_listener(self):
        previous = {
            "mode": "tailscale-serve",
            "public_base_url": "https://node.example.ts.net:8805",
            "https_port": 8805,
            "socket_path": "/private/secret-drop.sock",
        }
        reassigned = subprocess.CompletedProcess(
            ["tailscale"],
            0,
            json.dumps(
                {
                    "Web": {
                        "node.example.ts.net:8805": {
                            "Handlers": {"/": {"Proxy": "http://127.0.0.1:9999"}}
                        }
                    }
                }
            ),
            "",
        )
        with patch.object(installer.shutil, "which", return_value="/usr/bin/tailscale"):
            with patch.object(installer, "run", return_value=reassigned):
                with self.assertRaises(installer.InstallError):
                    installer.remove_previous_tailscale_serve(previous)

    def test_install_restarts_an_already_running_service(self):
        completed = subprocess.CompletedProcess(["systemctl"], 0, "", "")
        with patch.object(installer, "run", return_value=completed) as run_mock:
            installer.restart_service("/usr/bin/systemctl")

        commands = [call.args[0] for call in run_mock.call_args_list]
        self.assertEqual(
            commands,
            [
                ["/usr/bin/systemctl", "--user", "daemon-reload"],
                ["/usr/bin/systemctl", "--user", "enable", installer.SERVICE_NAME],
                ["/usr/bin/systemctl", "--user", "restart", installer.SERVICE_NAME],
            ],
        )

    def test_tailscale_identity_requires_running_magicdns_node(self):
        payload = {
            "BackendState": "Running",
            "Self": {
                "DNSName": "example-node.example-tailnet.ts.net.",
                "TailscaleIPs": ["100.64.1.2"],
            },
        }
        completed = subprocess.CompletedProcess(["tailscale"], 0, json.dumps(payload), "")
        with patch.object(installer.shutil, "which", return_value="/usr/bin/tailscale"):
            with patch.object(installer, "run", return_value=completed):
                self.assertEqual(
                    installer.tailscale_identity(),
                    ("example-node.example-tailnet.ts.net", "100.64.1.2"),
                )

    def test_systemd_unit_is_user_scoped_and_has_no_funnel(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unit = root / "secret-drop.service"
            installer.write_service(
                unit,
                "/usr/bin/python3",
                root / "secret_drop.py",
                root / "config.json",
                root / ".env",
                root / "state",
            )
            text = unit.read_text(encoding="utf-8")
            self.assertIn("NoNewPrivileges=true", text)
            self.assertIn("ProtectSystem=strict", text)
            self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", text)
            self.assertNotIn("Funnel", text)

    def test_installer_refuses_unmarked_nonempty_and_symlinked_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nonempty = root / "nonempty"
            nonempty.mkdir()
            (nonempty / "keep.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(installer.InstallError):
                installer.prepare_managed_directory(nonempty)

            victim = root / "victim"
            victim.mkdir()
            linked = root / "linked"
            linked.symlink_to(victim, target_is_directory=True)
            with self.assertRaises(installer.InstallError):
                installer.prepare_managed_directory(linked)
            ancestor_link = root / "ancestor-link"
            ancestor_link.symlink_to(victim, target_is_directory=True)
            with self.assertRaises(installer.InstallError):
                installer.prepare_managed_directory(ancestor_link / "managed")
            self.assertFalse((victim / "managed").exists())
            self.assertEqual((nonempty / "keep.txt").read_text(encoding="utf-8"), "keep")

            victim_file = victim / "wrapper-victim"
            victim_file.write_text("keep", encoding="utf-8")
            wrapper_link = root / "wrapper-link"
            wrapper_link.symlink_to(victim_file)
            with self.assertRaises(installer.InstallError):
                installer.write_wrapper(wrapper_link, "/usr/bin/python3", root / "script.py", root / "config.json")
            self.assertEqual(victim_file.read_text(encoding="utf-8"), "keep")

            unowned_unit = root / "unowned.service"
            unowned_unit.write_text("keep", encoding="utf-8")
            with self.assertRaises(installer.InstallError):
                installer.write_service(
                    unowned_unit,
                    "/usr/bin/python3",
                    root / "script.py",
                    root / "config.json",
                    root / ".env",
                    root / "state",
                )
            self.assertEqual(unowned_unit.read_text(encoding="utf-8"), "keep")

            source = root / "source.txt"
            source.write_text("replacement", encoding="utf-8")
            managed_link = root / "managed-link"
            managed_link.symlink_to(victim_file)
            with self.assertRaises(installer.InstallError):
                installer.copy_into_managed_directory(source, managed_link, 0o600)
            self.assertEqual(victim_file.read_text(encoding="utf-8"), "keep")

            managed_hardlink = root / "managed-hardlink"
            os.link(victim_file, managed_hardlink)
            installer.copy_into_managed_directory(source, managed_hardlink, 0o600)
            self.assertEqual(victim_file.read_text(encoding="utf-8"), "keep")
            self.assertEqual(managed_hardlink.read_text(encoding="utf-8"), "replacement")

            env_victim = root / "env-victim"
            env_victim.write_text("keep", encoding="utf-8")
            env_hardlink = root / ".env"
            os.link(env_victim, env_hardlink)
            with self.assertRaises(installer.InstallError):
                installer.prepare_env_file(env_hardlink)
            self.assertEqual(env_victim.read_text(encoding="utf-8"), "keep")

    def test_staged_install_and_uninstall_preserve_hermes_env(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            fake_bin = root / "fake-bin"
            state = root / "state"
            install_dir = root / "install"
            bin_dir = root / "bin"
            unit_dir = root / "units"
            hermes_home = root / "hermes"
            home.mkdir()
            fake_bin.mkdir()
            hermes_home.mkdir()
            (hermes_home / ".env").write_text("KEEP_API_KEY='preserve-me'\n", encoding="utf-8")

            tailscale = fake_bin / "tailscale"
            tailscale.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json, sys
                    if sys.argv[1:3] == ['status', '--json']:
                        print(json.dumps({'BackendState':'Running','Self':{'DNSName':'demo-node.demo-tailnet.ts.net.','TailscaleIPs':['100.64.1.2']}}))
                    elif sys.argv[1:4] == ['serve', 'status', '--json']:
                        print(json.dumps({'TCP':{},'Web':{}}))
                    else:
                        raise SystemExit(0)
                    """
                ),
                encoding="utf-8",
            )
            tailscale.chmod(0o700)
            systemctl = fake_bin / "systemctl"
            systemctl.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            systemctl.chmod(0o700)

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "HERMES_HOME": str(hermes_home),
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            install_result = subprocess.run(
                [
                    "python3",
                    str(INSTALL_SCRIPT),
                    "--no-start",
                    "--state-dir",
                    str(state),
                    "--install-dir",
                    str(install_dir),
                    "--bin-dir",
                    str(bin_dir),
                    "--unit-dir",
                    str(unit_dir),
                ],
                text=True,
                capture_output=True,
                env=env,
                cwd=ROOT,
            )
            self.assertEqual(install_result.returncode, 0, install_result.stderr or install_result.stdout)
            payload = json.loads(install_result.stdout)
            self.assertEqual(payload["status"], "staged")
            self.assertTrue((install_dir / "secret_drop.py").is_file())
            self.assertTrue((bin_dir / "hermes-secret-drop").is_file())
            staged_skill = hermes_home / "skills" / "hermes-tailnet-secret-drop" / "SKILL.md"
            self.assertTrue(staged_skill.is_file())
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            encryption_key = state / "encryption-key.pem"
            self.assertTrue(encryption_key.is_file())
            self.assertEqual(stat.S_IMODE(encryption_key.stat().st_mode), 0o600)
            installed_config = json.loads((state / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(installed_config["encryption_key_path"], str(encryption_key))
            self.assertNotIn("public_key", installed_config)

            # The staging model has no in-repo duplicate: the installer copies the
            # canonical sources, so they must land byte-for-byte identical.
            self.assertEqual(
                (install_dir / "secret_drop.py").read_bytes(),
                (ROOT / "src" / "secret_drop.py").read_bytes(),
            )
            self.assertEqual(staged_skill.read_bytes(), (ROOT / "skill" / "SKILL.md").read_bytes())

            uninstall_result = subprocess.run(
                [
                    "python3",
                    str(UNINSTALL_SCRIPT),
                    "--state-dir",
                    str(state),
                    "--install-dir",
                    str(install_dir),
                    "--bin-dir",
                    str(bin_dir),
                    "--unit-dir",
                    str(unit_dir),
                ],
                text=True,
                capture_output=True,
                env=env,
                cwd=ROOT,
            )
            self.assertEqual(uninstall_result.returncode, 0, uninstall_result.stderr or uninstall_result.stdout)
            uninstall_payload = json.loads(uninstall_result.stdout)
            self.assertTrue(uninstall_payload["saved_secrets_preserved"])
            self.assertEqual(
                (hermes_home / ".env").read_text(encoding="utf-8"),
                "KEEP_API_KEY='preserve-me'\n",
            )
            self.assertFalse(state.exists())
            self.assertFalse(install_dir.exists())

    def test_cloudflare_access_staging_uses_exact_url_and_loopback_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            hermes_home = root / "hermes"
            home.mkdir()
            hermes_home.mkdir()
            state = root / "state"
            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "HERMES_HOME": str(hermes_home),
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            public_base = "https://drop.example.com/apps/hermes-secrets"
            result = subprocess.run(
                [
                    sys.executable,
                    str(INSTALL_SCRIPT),
                    "--no-start",
                    "--access-protected-public-base-url",
                    public_base,
                    "--http-port",
                    "18805",
                    "--state-dir",
                    str(state),
                    "--install-dir",
                    str(root / "install"),
                    "--bin-dir",
                    str(root / "bin"),
                    "--unit-dir",
                    str(root / "units"),
                ],
                text=True,
                capture_output=True,
                env=env,
                cwd=ROOT,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["mode"], "cloudflare-access")
            config = json.loads((state / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(config["public_base_url"], public_base)
            self.assertEqual(config["access_protected_public_base_url"], public_base)
            self.assertEqual(config["http_host"], "127.0.0.1")
            self.assertEqual(config["http_port"], 18805)
            self.assertFalse(any(key.startswith("https_") or key.startswith("tls_") for key in config))

    def test_uninstall_refuses_unmarked_and_symlinked_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            hermes_home = root / "hermes"
            home.mkdir()
            hermes_home.mkdir()
            env = os.environ.copy()
            env.update({"HOME": str(home), "HERMES_HOME": str(hermes_home), "PYTHONDONTWRITEBYTECODE": "1"})

            victim = root / "victim"
            victim.mkdir()
            sentinel = victim / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            for state_dir in (victim, root / "state-link"):
                if state_dir.name == "state-link":
                    state_dir.symlink_to(victim, target_is_directory=True)
                result = subprocess.run(
                    [
                        "python3",
                        str(UNINSTALL_SCRIPT),
                        "--state-dir",
                        str(state_dir),
                        "--install-dir",
                        str(root / "missing-install"),
                        "--bin-dir",
                        str(root / "bin"),
                        "--unit-dir",
                        str(root / "units"),
                    ],
                    text=True,
                    capture_output=True,
                    env=env,
                    cwd=ROOT,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_uninstall_validates_every_tree_before_any_mutation(self):
        def mark(path):
            path.mkdir(parents=True, exist_ok=True)
            (path / ".hermes-tailnet-secret-drop-managed").write_text(
                json.dumps({"app": "hermes-tailnet-secret-drop", "marker_version": 1}),
                encoding="utf-8",
            )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for case in ("unmarked-install", "symlinked-hermes-home", "unowned-leaves"):
                trial = root / case
                home = trial / "home"
                fake_bin = trial / "fake-bin"
                state = trial / "state"
                install_dir = trial / "install"
                bin_dir = trial / "bin"
                unit_dir = trial / "units"
                actual_hermes = trial / "actual-hermes"
                home.mkdir(parents=True)
                fake_bin.mkdir()
                bin_dir.mkdir()
                unit_dir.mkdir()
                mark(state)

                if case == "unmarked-install":
                    install_dir.mkdir()
                    (install_dir / "keep.txt").write_text("keep", encoding="utf-8")
                    hermes_home = actual_hermes
                    actual_hermes.mkdir()
                elif case == "symlinked-hermes-home":
                    mark(install_dir)
                    mark(actual_hermes / "skills" / "hermes-tailnet-secret-drop")
                    hermes_home = trial / "hermes-link"
                    hermes_home.symlink_to(actual_hermes, target_is_directory=True)
                else:
                    mark(install_dir)
                    mark(actual_hermes / "skills" / "hermes-tailnet-secret-drop")
                    hermes_home = actual_hermes

                wrapper = bin_dir / "hermes-secret-drop"
                wrapper.write_text("keep", encoding="utf-8")
                service = unit_dir / "hermes-tailnet-secret-drop.service"
                service.write_text("keep", encoding="utf-8")
                systemctl_log = trial / "systemctl.log"
                systemctl = fake_bin / "systemctl"
                systemctl.write_text(
                    "#!/usr/bin/env sh\nprintf 'called\\n' >> \"$SYSTEMCTL_LOG\"\nexit 0\n",
                    encoding="utf-8",
                )
                systemctl.chmod(0o700)

                env = os.environ.copy()
                env.update(
                    {
                        "HOME": str(home),
                        "HERMES_HOME": str(hermes_home),
                        "PATH": f"{fake_bin}:{env['PATH']}",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "SYSTEMCTL_LOG": str(systemctl_log),
                    }
                )
                result = subprocess.run(
                    [
                        "python3",
                        str(UNINSTALL_SCRIPT),
                        "--state-dir",
                        str(state),
                        "--install-dir",
                        str(install_dir),
                        "--bin-dir",
                        str(bin_dir),
                        "--unit-dir",
                        str(unit_dir),
                    ],
                    text=True,
                    capture_output=True,
                    env=env,
                    cwd=ROOT,
                )
                self.assertNotEqual(result.returncode, 0, case)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertFalse(systemctl_log.exists(), case)
                self.assertEqual(wrapper.read_text(encoding="utf-8"), "keep")
                self.assertEqual(service.read_text(encoding="utf-8"), "keep")
                self.assertTrue(state.exists())
                self.assertTrue(install_dir.exists())


if __name__ == "__main__":
    unittest.main()
