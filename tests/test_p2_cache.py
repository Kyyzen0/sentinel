"""Tests P2-1 : chaque fichier est lu une seule fois par scan.

Le bug : un scan avec `--baseline --anomaly` lit chaque fichier 3 fois
(make_baseline, boucle de règles, score_heuristic).

Le fix : cache `path -> text|None` partagé entre les 3 consommateurs
dans un même scan. On vérifie en wrappant `pathlib.Path.open` (la
fonction de bas niveau que tous les readers utilisent).
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _count_path_opens(monkeypatch, *under_test):
    """Compte le nombre d'ouvertures de fichier sous `under_test`."""
    from pathlib import Path as P

    real_open = P.open
    counter = [0]

    def counting_open(self, *a, **kw):
        if any(str(self).startswith(str(u)) for u in under_test):
            counter[0] += 1
        return real_open(self, *a, **kw)

    monkeypatch.setattr(P, "open", counting_open)
    return counter


class TestSingleReadPerFile(unittest.TestCase):
    def test_anomaly_uses_cache_no_re_read(self) -> None:
        """5 fichiers + --anomaly : avec cache on doit avoir ~10
        ouvertures (5 baseline read_bytes + 5 rule loop). Sans cache :
        ~15 (5 make_baseline + 5 rule + 5 anomaly)."""
        from sentinel import scanner

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            for i in range(5):
                (td / f"f_{i}.txt").write_text("hello\n")

            with mock.patch.object(Path, "open", wraps=Path.open):
                # Patch via spy
                real_open = Path.open
                counter = [0]

                def counting_open(self, *a, **kw):
                    if str(self).startswith(str(td)):
                        counter[0] += 1
                    return real_open(self, *a, **kw)

                with mock.patch.object(Path, "open", counting_open):
                    scanner.scan_folder(
                        td,
                        with_anomaly=True,
                        with_neural=False,
                        model_path=None,
                    )

                count = counter[0]

            # Note : make_baseline utilise read_bytes() (C-level), pas open().
            # Donc on ne compte que les open() (rule loop + anomaly).
            # Avec cache : 5 (rule loop seulement).
            # Sans cache : 10 (5 rule + 5 anomaly).
            self.assertEqual(
                count,
                5,
                f"open() appelé {count} fois pour 5 fichiers "
                f"(attendu 5 avec cache, 10 sans). Le cache n'est pas "
                f"partagé entre rule loop et anomaly.",
            )

    def test_no_anomaly_means_five_reads(self) -> None:
        """Sans --anomaly, exactement 5 open() pour 5 fichiers."""
        from sentinel import scanner

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            for i in range(5):
                (td / f"f_{i}.txt").write_text("hello\n")

            counter = [0]
            real_open = Path.open

            def counting_open(self, *a, **kw):
                if str(self).startswith(str(td)):
                    counter[0] += 1
                return real_open(self, *a, **kw)

            with mock.patch.object(Path, "open", counting_open):
                scanner.scan_folder(
                    td,
                    with_anomaly=False,
                    with_neural=False,
                    model_path=None,
                )

            self.assertEqual(
                counter[0],
                5,
                f"open() appelé {counter[0]} fois (attendu 5)",
            )
