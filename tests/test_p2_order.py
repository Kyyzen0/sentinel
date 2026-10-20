"""Tests P2-2 : ordre déterministe du scan.

Le bug : `folder.rglob('*')` dans `sentinel.scanner` n'est pas trié, donc
les findings et anomalies peuvent changer d'ordre entre deux runs
identiques (selon l'ordre de l'OS sur le FS). Conséquence : les rapports
JSON ne sont pas reproductibles, et un `diff` sur la sortie CI est
inutilisable.

Le fix : trier le résultat du rglob avant de scanner. La baseline
fait déjà ce tri (cf. `_iter_files` dans `sentinel.integrity.py`) — le
scanner doit s'aligner.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.scanner import scan_folder


class TestScannerOrderIsDeterministic(unittest.TestCase):
    def test_findings_order_is_path_sorted(self) -> None:
        """Les findings sont triés par (path, line, rule_id) — déterministe."""
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            # 5 fichiers : on s'attend à les voir dans l'ordre alphabétique.
            (td / "z.txt").write_text("safe\n")
            (td / "a.txt").write_text("safe\n")
            (td / "m.txt").write_text("safe\n")
            (td / "b.txt").write_text("safe\n")
            (td / "c.txt").write_text("safe\n")
            r = scan_folder(td, with_anomaly=True)
            # Aucun finding attendu (contenu safe), mais l'itération des
            # fichiers (utilisée par l'anomalie) doit être triée.
            order = [a.path for a in r.anomalies]
            self.assertEqual(order, sorted(order), f"anomalies non triées : {order!r}")

    def test_two_runs_produce_same_json(self) -> None:
        """Deux scans successifs produisent un JSON identique (ordre stable)."""
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            # On mélange sciemment l'ordre de création pour stresser
            # l'OS (les FS récents ne garantissent pas l'ordre du rglob).
            for name in ["zeta.txt", "alpha.txt", "beta.txt", "gamma.txt", "delta.txt"]:
                (td / name).write_text("safe\n")
            r1 = scan_folder(td, with_anomaly=True)
            r2 = scan_folder(td, with_anomaly=True)
            from sentinel.reporting import render_json

            j1 = render_json(r1)
            j2 = render_json(r2)
            self.assertEqual(j1, j2, "deux scans successifs ne sont pas identiques")


if __name__ == "__main__":
    unittest.main()
