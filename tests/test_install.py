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


if __name__ == "__main__":
    unittest.main()
