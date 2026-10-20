"""Tests P4-B : smoke tests E2E sur la console script.

Le bug : `__main__.py` est à 0% de couverture parce que les tests
unitaires n'invoquent jamais le main() — c'est typique pour les CLI.
Sans smoke test, une régression de l'argparse passe inaperçue.

Le fix : on invoque `python3 -m sentinel` via subprocess sur des
cas réels (--version, --help, scan, restore) et on vérifie :
  - exit code correct
  - sortie non-vide / contient la chaîne attendue
  - absence de traceback
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO = Path(__file__).resolve().parents[1]


def _run_sentinel(*args: str) -> subprocess.CompletedProcess:
    """Invoque `python3 -m sentinel` avec les args donnés.
    Retourne un CompletedProcess avec stdout/stderr capturés en texte.
    """
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=30,
    )


class TestCliSmoke(unittest.TestCase):
    def test_version(self) -> None:
        r = _run_sentinel("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sentinel", r.stdout.lower())
        self.assertRegex(r.stdout, r"\d+\.\d+\.\d+")

    def test_help_mentions_all_subcommands(self) -> None:
        r = _run_sentinel("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        for cmd in ("baseline", "scan", "train", "quarantine", "watch", "restore"):
            self.assertIn(cmd, r.stdout, f"subcommand {cmd!r} absent du help")

    def test_scan_help(self) -> None:
        r = _run_sentinel("scan", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        for opt in (
            "--baseline",
            "--anomaly",
            "--format",
            "--min-severity",
            "--only",
            "--ignore-file",
            "--encrypt-key",
            "--follow-links",
            "--strict",
        ):
            self.assertIn(opt, r.stdout, f"option {opt!r} absente de scan --help")

    def test_scan_on_empty_folder(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = _run_sentinel("scan", td)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_scan_json_format(self) -> None:
        """La sortie --format json doit être un JSON parsable avec
        les champs P3-2 (tool, version, schema)."""
        import json

        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            (td_p / "evil.sh").write_text("#!/bin/sh\nrm -rf /\n")
            r = _run_sentinel("scan", td, "--format", "json")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["tool"], "sentinel")
            self.assertEqual(data["schema"], 2)
            self.assertIn("findings", data)

    def test_scan_sarif_format(self) -> None:
        """La sortie --format sarif doit être un SARIF 2.1.0 valide.

        Note : exit 1 ici est ATTENDU (findings trouvés = `report.exit_code`
        = 1). Ce qu'on teste, c'est que la sortie est bien un SARIF valide
        (GitHub Code Scanning accepte exit != 0 quand findings présents,
        du moment que le JSON est bien formé)."""
        import json

        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            (td_p / "evil.php").write_text('<?php system($_GET["c"]); ?>\n')
            r = _run_sentinel("scan", td, "--format", "sarif")
            self.assertNotIn("Traceback", r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "sentinel")

    def test_scan_strict_missing_baseline_exits_2(self) -> None:
        """P1-5 : --strict + baseline manquante = exit 2."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            nonexistent = td_p / "does_not_exist.json"
            r = _run_sentinel("scan", td, "--baseline", str(nonexistent), "--strict")
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_restore_help(self) -> None:
        r = _run_sentinel("restore", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--manifest", r.stdout)
        self.assertIn("--force", r.stdout)


if __name__ == "__main__":
    unittest.main()
