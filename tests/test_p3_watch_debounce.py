"""Tests P3-3 : watch sans debounce + arrêt sur SIGTERM.

Le bug :
  - une sauvegarde d'éditeur déclenche une rafale d'événements FS, donc
    une rafale de scans complets. Sans debounce, c'est très coûteux.
  - le docstring promet l'arrêt sur SIGTERM, seul Ctrl-C (SIGINT) est
    géré. SIGTERM (15) doit aussi être capturé.
  - pas de sortie `--json-lines` pour le piping / streaming.

Le fix :
  - `watch_polling(..., debounce=S)` : ne déclenche un scan que si
    le snapshot n'a pas changé pendant S secondes consécutives.
  - `watch_event` : installe aussi un handler SIGTERM (en plus de SIGINT).
  - `--json-lines` : un mode de sortie où chaque scan est un JSON compact
    sur une ligne (idéal pour `tail -f` ou l'ingestion streaming).
"""

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.watch import watch_polling


class TestDebounce(unittest.TestCase):
    def test_debounce_collapses_rapid_changes(self) -> None:
        """Si le snapshot change 10 fois en 50 ms, on n'envoie qu'UN
        callback (avec le diff final)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            target = td / "file.txt"
            target.write_text("v1\n")

            events: list[dict] = []

            def cb(diff: dict) -> None:
                events.append(dict(diff))

            # Lance la polling dans un thread.
            t = threading.Thread(
                target=watch_polling,
                args=(td, 0.05, cb),
                kwargs={"debounce": 0.1, "max_iterations": 30},
                daemon=True,
            )
            t.start()

            # Modifications rapides.
            for i in range(8):
                time.sleep(0.005)
                target.write_text(f"v{i}\n")

            # Attend que la boucle se termine.
            t.join(timeout=2.0)

            # Le callback doit avoir été appelé 1 ou 2 fois max (avec
            # debounce, les 8 modifs rapides ne déclenchent qu'un scan).
            self.assertLessEqual(
                len(events),
                3,
                f"trop d'événements ({len(events)}) pour 8 modifs — debounce insuffisant",
            )
            # L'événement doit être non-vide.
            self.assertTrue(
                any(e.get("modified") or e.get("added") for e in events),
                f"aucun diff non-vide capturé : {events!r}",
            )

    def test_debounce_reports_files_created_during_the_window(self) -> None:
        """Un fichier apparu pendant l'attente doit être dans le diff final."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("v0")
            events: list[dict] = []
            n = {"i": 0}

            def sleep(_dt: float) -> None:
                n["i"] += 1
                if n["i"] == 1:
                    (td / "a.txt").write_text("v1")
                elif n["i"] == 2:
                    (td / "b.txt").write_text("new")
                    (td / "a.txt").write_text("v2")

            watch_polling(td, 1.0, events.append, max_iterations=6, debounce=3.0, sleep=sleep)
            self.assertTrue(events, "aucun callback")
            added = {name for ev in events for name in ev["added"]}
            modified = {name for ev in events for name in ev["modified"]}
            self.assertIn("b.txt", added)
            self.assertIn("a.txt", modified)


class TestJsonLines(unittest.TestCase):
    def test_json_lines_is_one_json_per_line(self) -> None:
        """`render_json` produit un JSON compact sur une ligne (sans
        indentation ni newlines) quand appelé avec indent=None.
        Le rapport peut alors être streamé avec `tail -f`."""
        from sentinel.models import Finding, Report
        from sentinel.reporting import render_json

        r = Report()
        r.findings.append(
            Finding(
                rule_id="SIG-0001",
                severity="critical",
                path="test.php",
                line=1,
                message="m",
                evidence="e",
            )
        )
        out = render_json(r, indent=None)
        self.assertNotIn("\n", out, "render_json(indent=None) doit produire une seule ligne")
        # Doit être un JSON parsable.
        parsed = json.loads(out)
        self.assertEqual(len(parsed["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
