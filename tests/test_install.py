from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
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
            self.assertTrue((hermes_home / "skills" / "hermes-tailnet-secret-drop" / "SKILL.md").is_file())
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)

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
