"""Tracer bullet : scanner un dossier vide ne renvoie aucun finding."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestScanEmpty(unittest.TestCase):
    def test_scan_empty_folder_returns_no_findings(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [sys.executable, "-m", "sentinel", "scan", td, "--format", "json"],
                cwd=repo_root,
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "LC_ALL": "C.UTF-8"},
            )
            self.assertEqual(
                result.returncode,
                0,
                f"expected exit 0 on empty folder, got {result.returncode}\n"
                f"stderr: {result.stderr}",
            )
            payload = json.loads(result.stdout)
            self.assertEqual(payload["findings"], [])
            self.assertEqual(
                payload["severity_counts"],
                {"critical": 0, "high": 0, "medium": 0, "low": 0},
            )
