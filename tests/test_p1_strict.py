"""Tests P1-5 : --strict change l'exit code à 2 si la baseline est
illisible, au lieu de sortir 0/1 avec un simple warning.

Le bug : un scan lancé pour vérifier l'intégrité qui n'a pas pu lire
la baseline sort en succès (0 ou 1 selon findings). Un CI qui s'attend
à « 0 = tout est OK » peut ainsi valider un scan qui n'a rien vérifié.

Le fix : un flag `--strict` qui force exit 2 si la baseline est
illisible (parse error, fichier absent, etc.). Sans `--strict`, on
garde le comportement actuel (warning + exit 0/1).
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


class TestStrictBaselineMode(unittest.TestCase):
    def test_default_baseline_missing_exits_0_or_1(self) -> None:
        """Sans --strict, un baseline inexistant est juste ignoré (exit 0/1)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "x.txt").write_text("safe\n")
            # Baseline inexistante.
            r = _run_cli(
                "scan", str(td), "--baseline", str(td / "no_such.json"), "--format", "text"
            )
            # L'exit code doit rester 0 (rien trouvé) ou 1 (findings), PAS 2.
            self.assertIn(
                r.returncode,
                (0, 1),
                f"sans --strict, exit {r.returncode} (attendu 0 ou 1)\nstderr: {r.stderr}",
            )
            # Pas d'erreur d'argparse.
            self.assertNotIn("unrecognized arguments", r.stderr)

    def test_strict_baseline_missing_exits_2(self) -> None:
        """Avec --strict, un baseline inexistant → exit 2."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "x.txt").write_text("safe\n")
            r = _run_cli(
                "scan",
                str(td),
                "--baseline",
                str(td / "no_such.json"),
                "--strict",
                "--format",
                "text",
            )
            self.assertEqual(
                r.returncode,
                2,
                f"avec --strict et baseline manquante, exit {r.returncode} (attendu 2)\n"
                f"stderr: {r.stderr}",
            )
            # Pas d'erreur d'argparse (sinon, c'est facile de sortir 2).
            self.assertNotIn("unrecognized arguments", r.stderr)
            # Le message doit mentionner le mot « baseline » pour
            # expliquer la sortie 2 à l'utilisateur CI.
            self.assertTrue(
                "baseline" in r.stderr.lower() or "baseline" in r.stdout.lower(),
                f"le message devrait mentionner baseline: stderr={r.stderr!r}, stdout={r.stdout!r}",
            )

    def test_strict_baseline_invalid_json_exits_2(self) -> None:
        """Avec --strict, un baseline corrompue → exit 2."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "x.txt").write_text("safe\n")
            bad = td / "bad.json"
            bad.write_text("not valid json {")
            r = _run_cli("scan", str(td), "--baseline", str(bad), "--strict", "--format", "text")
            self.assertEqual(
                r.returncode, 2, f"baseline corrompue + --strict → exit {r.returncode} (attendu 2)"
            )
            self.assertNotIn("unrecognized arguments", r.stderr)

    def test_no_strict_baseline_invalid_json_exits_0_or_1(self) -> None:
        """Sans --strict, baseline corrompue → warning + exit 0/1 (pas 2)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "x.txt").write_text("safe\n")
            bad = td / "bad.json"
            bad.write_text("not valid json {")
            r = _run_cli("scan", str(td), "--baseline", str(bad), "--format", "text")
            self.assertIn(
                r.returncode,
                (0, 1),
                f"baseline corrompue sans --strict → exit {r.returncode} (attendu 0/1)",
            )
            # Warning attendu.
            self.assertIn("illisible", r.stderr.lower())


if __name__ == "__main__":
    unittest.main()
