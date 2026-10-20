"""Tests pour la commande `quarantine`."""

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.quarantine import quarantine_file, quarantine_paths


class TestQuarantineFile(unittest.TestCase):
    def test_move_makes_file_readonly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "evil.sh"
            payload = b"#!/bin/bash\nrm -rf /\n"
            src.write_bytes(payload)
            # Dest séparé (en dehors du dossier de la source) pour ne pas
            # déclencher les garde-fous chemin (P1-3).
            dest_dir = Path(tempfile.mkdtemp(prefix="q-"))
            rec = quarantine_file(src, dest_dir)

            # Le fichier source n'existe plus.
            self.assertFalse(src.exists())
            # Le fichier est dans le dossier de quarantaine.
            self.assertTrue(Path(rec.quarantined).is_file())
            # Il est en read-only.
            mode = Path(rec.quarantined).stat().st_mode
            self.assertFalse(mode & stat.S_IWUSR)
            self.assertFalse(mode & stat.S_IWGRP)
            self.assertFalse(mode & stat.S_IWOTH)
            # Le contenu est préservé.
            self.assertEqual(Path(rec.quarantined).read_bytes(), payload)
            # Le SHA-256 est correct.
            import hashlib

            self.assertEqual(rec.sha256, hashlib.sha256(payload).hexdigest())

    def test_unique_name_on_collision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            sub1 = td / "a"
            sub1.mkdir()
            sub2 = td / "b"
            sub2.mkdir()
            src1 = sub1 / "evil.sh"
            src1.write_text("one")
            src2 = sub2 / "evil.sh"
            src2.write_text("two")
            dest_dir = Path(tempfile.mkdtemp(prefix="q-"))

            r1 = quarantine_file(src1, dest_dir)
            r2 = quarantine_file(src2, dest_dir)

            # Deux fichiers distincts sous dest_dir.
            self.assertNotEqual(r1.quarantined, r2.quarantined)
            self.assertTrue(Path(r1.quarantined).is_file())
            self.assertTrue(Path(r2.quarantined).is_file())

    def test_quarantine_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "evil_dir"
            src.mkdir()
            (src / "x").write_text("x")
            (src / "y").write_text("y")
            dest_dir = Path(tempfile.mkdtemp(prefix="q-"))
            rec = quarantine_file(src, dest_dir)
            self.assertTrue(Path(rec.quarantined).is_dir())
            self.assertFalse(src.exists())


class TestQuarantinePaths(unittest.TestCase):
    def test_manifest_records_all_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src1 = td / "a"
            src1.write_text("A")
            src2 = td / "b"
            src2.write_text("B")
            dest_dir = Path(tempfile.mkdtemp(prefix="q-"))
            manifest = Path(tempfile.mkdtemp(prefix="m-")) / "manifest.jsonl"
            recs, fails = quarantine_paths([src1, src2], dest_dir, manifest)
            self.assertEqual(len(recs), 2)
            self.assertEqual(len(fails), 0)
            # Journal en deux phases : intention « en cours », puis confirmation.
            parsed = [json.loads(line) for line in manifest.read_text().splitlines()]
            done = [rec for rec in parsed if rec["_status"] == "done"]
            pending = [rec for rec in parsed if rec["_status"] == "en cours"]
            self.assertEqual(len(done), 2)
            self.assertEqual(len(pending), 2)
            self.assertEqual(done[0]["original"], str(src1))
            self.assertEqual(done[1]["original"], str(src2))
            self.assertEqual(done[0]["id"], pending[0]["id"])
            self.assertEqual(pending[0]["size"], done[0]["size"])
            self.assertEqual(pending[0]["sha256"], done[0]["sha256"])

    def test_continues_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src1 = td / "good"
            src1.write_text("ok")
            # src2 inexistant : doit échouer sans bloquer src1.
            src2 = td / "ghost"
            dest_dir = Path(tempfile.mkdtemp(prefix="q-"))
            manifest = Path(tempfile.mkdtemp(prefix="m-")) / "manifest.json"
            recs, fails = quarantine_paths([src1, src2], dest_dir, manifest)
            self.assertEqual(len(recs), 1)
            self.assertEqual(len(fails), 1)
            self.assertEqual(fails[0][0], src2)


if __name__ == "__main__":
    unittest.main()
