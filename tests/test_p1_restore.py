"""Tests P1-1 : `sentinel restore` doit rejouer l'opération inverse.

Le bug : `quarantine` déplace les fichiers et tient un manifest, mais
aucune fonction ne les remet à leur emplacement d'origine. Sans ça,
l'outil n'est pas utilisable en production (les utilisateurs n'osent
pas mettre en quarantaine de peur de perdre le fichier).

Le fix : `restore_paths(manifest, dest, force)` lit le manifest, et pour
chaque record :
  1. remet le fichier read-write (`chmod 0o644` ou 0o755)
  2. le déplace vers `record.original` (le chemin d'origine)
  3. retire l'entrée du manifest
  4. logge le résultat

Cas couverts :
  - restauration complète → manifest vide
  - fichier d'origine déjà présent (refus sans --force)
  - manifest corrompu (refus)
  - fichier en quarantaine introuvable (skip, erreur explicite)
"""

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.quarantine import (
    quarantine_paths,
    restore_paths,
)
from tests.osutil import release_quarantine_write, unlink_readonly


def _quarantine_some(tmpdir: Path) -> tuple[list[Path], Path, Path]:
    """Helper : crée 3 fichiers, les met en quarantaine, retourne
    (sources originales, dest_dir, manifest_path)."""
    src_dir = tmpdir / "src"
    src_dir.mkdir()
    files = []
    for i, content in enumerate(["evil1\n", "evil2\n", "evil3\n"]):
        p = src_dir / f"file_{i}.sh"
        p.write_text(content)
        files.append(p)

    dest = tmpdir / "quarantine"
    manifest = dest / "manifest.json"
    records, failures = quarantine_paths(files, dest_dir=dest, manifest_path=manifest)
    assert not failures, f"quarantine a échoué : {failures}"
    assert len(records) == 3
    return files, dest, manifest


class TestRestoreBasic(unittest.TestCase):
    def test_restore_moves_files_back(self) -> None:
        """Un fichier mis en quarantaine revient à sa place après
        `restore_paths`."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig_files, dest, manifest = _quarantine_some(td)

            # Les originaux n'existent plus.
            for f in orig_files:
                self.assertFalse(f.exists(), f"{f} existe encore après quarantine")

            # Restore.
            restore_records, restore_failures = restore_paths(
                manifest_path=manifest,
                dest_dir=dest,
            )

            self.assertEqual(restore_failures, [], f"restore a échoué : {restore_failures}")
            self.assertEqual(len(restore_records), 3)

            # Les fichiers sont revenus à leur place.
            for f in orig_files:
                self.assertTrue(f.exists(), f"{f} n'a pas été restauré")
                # Le contenu est préservé.
                self.assertIn("evil", f.read_text())

    def test_restore_makes_files_writable(self) -> None:
        """Le fichier en quarantaine est read-only (0444). Après restore,
        il est réécrit avec le `mode_before` d'origine (0644 par défaut
        sur les fichiers)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig = td / "src" / "evil.sh"
            orig.parent.mkdir()
            orig.write_text("evil\n")
            orig.chmod(0o644)

            dest = td / "quarantine"
            manifest = dest / "manifest.json"
            quarantine_paths([orig], dest_dir=dest, manifest_path=manifest)

            # Le fichier en quarantaine est 0444.
            qfile = dest / "evil.sh"
            self.assertEqual(qfile.stat().st_mode & 0o777, 0o444)

            # Restore.
            restore_paths(manifest_path=manifest, dest_dir=dest)

            # Le fichier restauré a son mode d'origine (0644, ou 0666
            # sur Windows où seul le bit d'écriture est réel).
            self.assertTrue(orig.exists())
            if os.name == "nt":
                self.assertTrue(orig.stat().st_mode & stat.S_IWUSR)
            else:
                self.assertEqual(orig.stat().st_mode & 0o777, 0o644)


class TestRestoreFailures(unittest.TestCase):
    def test_restore_refuses_when_target_exists(self) -> None:
        """Si le chemin d'origine est déjà occupé (l'utilisateur a créé
        un nouveau fichier entre-temps), restore refuse par défaut.
        Avec --force, il écrase."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig, dest, manifest = _quarantine_some(td)
            # Recrée un fichier à l'emplacement d'origine.
            (td / "src" / "file_0.sh").write_text("innocent\n")

            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            # 1 échec (file_0 existe, refusé), 2 succès (file_1, file_2).
            self.assertEqual(
                len(fails),
                1,
                f"attendu 1 échec, vu {len(fails)}: {fails}",
            )
            self.assertEqual(
                len(rec),
                2,
                f"attendu 2 restaurations, vu {len(rec)}: {rec}",
            )
            # Le fichier innocent est préservé.
            self.assertEqual((td / "src" / "file_0.sh").read_text(), "innocent\n")
            # Le chemin d'origine refusé est bien file_0.
            self.assertEqual(str(fails[0][0]), str(orig[0]))

    def test_restore_force_overwrites_existing(self) -> None:
        """Avec `force=True`, restore écrase le fichier d'origine."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig, dest, manifest = _quarantine_some(td)
            (td / "src" / "file_0.sh").write_text("innocent\n")

            rec, fails = restore_paths(
                manifest_path=manifest,
                dest_dir=dest,
                force=True,
            )
            self.assertEqual(fails, [], f"restore a échoué : {fails}")
            # Le fichier est écrasé par le contenu de la quarantaine.
            self.assertEqual((td / "src" / "file_0.sh").read_text(), "evil1\n")

    def test_restore_skips_missing_quarantined_file(self) -> None:
        """Si le fichier en quarantaine a été supprimé manuellement,
        restore skip l'entrée (l'erreur est dans `failures`)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig, dest, manifest = _quarantine_some(td)

            # Supprime un fichier de la quarantaine.
            unlink_readonly(dest / "file_0.sh")

            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            # 1 échec (file_0), 2 succès.
            self.assertEqual(len(fails), 1, f"attendu 1 échec, vu {len(fails)}: {fails}")
            self.assertEqual(len(rec), 2)

    def test_restore_manifest_after(self) -> None:
        """Après restore, le journal garde TOUTES les entrées.

        Le comportement d'origine supprimait les entrées restaurées : le
        manifest ne contenait plus que les échecs, et il ne restait aucune
        trace qu'un fichier avait été mis en quarantaine puis remis. Pour
        un outil d'audit c'est une perte d'information — les entrées
        restaurées sont désormais conservées avec `_status="restored"` et
        `restored_at`, et seules les entrées encore actives sont rejouées.
        """
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig, dest, manifest = _quarantine_some(td)
            unlink_readonly(dest / "file_1.sh")  # 1 entrée irréversible

            restore_paths(manifest_path=manifest, dest_dir=dest)
            lines = manifest.read_text().splitlines()
            self.assertEqual(
                len(lines),
                6,
                "intention et résultat restent au journal pour chacune des 3 entrées",
            )

            entries = [json.loads(ln) for ln in lines]
            by_original = {e["original"]: e for e in entries}
            # Les deux restaurés portent la trace de la restauration.
            self.assertEqual(by_original[str(orig[0])]["_status"], "restored")
            self.assertEqual(by_original[str(orig[2])]["_status"], "restored")
            self.assertIn("restored_at", by_original[str(orig[0])])
            # L'échec reste actif, donc rejouable.
            self.assertEqual(by_original[str(orig[1])]["_status"], "done")

    def test_restore_is_not_replayed_twice(self) -> None:
        """Une entrée `restored` ne doit pas être restaurée une 2e fois."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig, dest, manifest = _quarantine_some(td)
            restore_paths(manifest_path=manifest, dest_dir=dest)

            # 2e passage : plus rien à restaurer, aucun échec.
            rec2, fails2 = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(rec2, [])
            self.assertEqual(fails2, [])

    def test_restore_refuses_corrupted_quarantine_file(self) -> None:
        """Un fichier de quarantaine modifié n'est pas restauré en silence."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig, dest, manifest = _quarantine_some(td)

            target = dest / "file_0.sh"
            release_quarantine_write(target)
            target.write_text("#!/bin/sh\necho remplacé\n")

            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            restored_names = {Path(r["original"]).name for r in rec}
            self.assertNotIn("file_0.sh", restored_names)
            self.assertTrue(
                any("intégrité compromise" in msg for _p, msg in fails),
                f"attendu un refus pour intégrité, vu {fails}",
            )
            # L'original n'a pas été recréé avec le contenu corrompu.
            self.assertFalse((td / "src" / "file_0.sh").exists())

    def test_empty_file_hash_is_real_and_tamper_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig = td / "src" / "empty"
            orig.parent.mkdir()
            orig.write_bytes(b"")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            records, failures = quarantine_paths([orig], dest_dir=dest, manifest_path=manifest)
            self.assertEqual(failures, [])
            self.assertEqual(records[0].sha256, hashlib.sha256(b"").hexdigest())

            qf = dest / "empty"
            release_quarantine_write(qf)
            qf.write_text("malware\n")
            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(rec, [])
            self.assertTrue(any("intégrité compromise" in msg for _p, msg in fails), fails)
            self.assertFalse(orig.exists())

    def test_directory_content_tamper_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "pkg"
            src.mkdir()
            (src / "a.txt").write_text("secret\n")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            records, failures = quarantine_paths([src], dest_dir=dest, manifest_path=manifest)
            self.assertEqual(failures, [])

            qdir = dest / "pkg"
            release_quarantine_write(qdir)
            release_quarantine_write(qdir / "a.txt")
            (qdir / "a.txt").write_text("pwned\n")
            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(rec, [])
            self.assertTrue(any("intégrité compromise" in msg for _p, msg in fails), fails)
            self.assertFalse(src.exists())

    def test_force_puts_original_back_if_move_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig = td / "src" / "file.sh"
            orig.parent.mkdir()
            orig.write_text("quarantined\n")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            quarantine_paths([orig], dest_dir=dest, manifest_path=manifest)
            orig.write_text("innocent\n")

            real_move = __import__("shutil").move
            calls = {"n": 0}

            def flaky(src, dst):
                calls["n"] += 1
                if calls["n"] == 2:
                    raise OSError("disk full")
                return real_move(src, dst)

            with mock.patch("sentinel.quarantine.shutil.move", side_effect=flaky):
                rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest, force=True)
            self.assertEqual(rec, [])
            self.assertTrue(fails, fails)
            self.assertEqual(orig.read_text(), "innocent\n")
            self.assertTrue((dest / "file.sh").exists())

    def test_legacy_directory_name_hash_still_restores(self) -> None:
        """Un dossier quarantainé par l'ancienne empreinte (noms seuls) se restaure."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "pkg"
            src.mkdir()
            (src / "a.txt").write_text("secret\n")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            records, failures = quarantine_paths([src], dest_dir=dest, manifest_path=manifest)
            self.assertEqual(failures, [])
            self.assertNotEqual(records[0].sha256, hashlib.sha256(b"a.txt").hexdigest())

            lines = []
            for raw in manifest.read_text().splitlines():
                rec = json.loads(raw)
                rec["sha256"] = hashlib.sha256(b"a.txt").hexdigest()
                lines.append(json.dumps(rec, sort_keys=True))
            manifest.write_text("\n".join(lines) + "\n")

            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(fails, [])
            self.assertEqual(len(rec), 1)
            self.assertEqual((src / "a.txt").read_text(), "secret\n")

    def test_relative_symlink_is_quarantined_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src"
            src.mkdir()
            target = src / "target.txt"
            target.write_text("ok\n")
            target.chmod(0o644)
            link = src / "link"
            link.symlink_to("target.txt")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            records, failures = quarantine_paths([link], dest_dir=dest, manifest_path=manifest)
            self.assertEqual(failures, [], failures)
            self.assertEqual(records[0].sha256, hashlib.sha256(b"l\0target.txt").hexdigest())
            self.assertFalse(link.is_symlink())
            quarantined = dest / "link"
            self.assertTrue(quarantined.is_symlink())
            self.assertEqual(quarantined.readlink(), Path("target.txt"))
            self.assertEqual(target.read_text(), "ok\n")
            if os.name == "nt":
                self.assertTrue(target.stat().st_mode & stat.S_IWUSR)
            else:
                self.assertEqual(target.stat().st_mode & 0o777, 0o644)

            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(fails, [], fails)
            self.assertEqual(len(rec), 1)
            self.assertEqual(link.readlink(), Path("target.txt"))
            self.assertEqual(target.read_text(), "ok\n")
            if os.name == "nt":
                self.assertTrue(target.stat().st_mode & stat.S_IWUSR)
            else:
                self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_chmod_failure_after_move_puts_source_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src" / "a.sh"
            src.parent.mkdir()
            src.write_text("echo ok\n")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            real_chmod = Path.chmod

            def boom(path: Path, mode: int) -> None:
                if path.name == "a.sh" and "q" in path.parts:
                    raise OSError("chmod refused")
                real_chmod(path, mode)

            with mock.patch.object(Path, "chmod", boom):
                records, failures = quarantine_paths([src], dest_dir=dest, manifest_path=manifest)
            self.assertEqual(records, [])
            self.assertTrue(failures, failures)
            self.assertEqual(src.read_text(), "echo ok\n")
            self.assertFalse((dest / "a.sh").exists())

    def test_force_discards_partial_copy_and_restores_occupant(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            orig = td / "src" / "file.sh"
            orig.parent.mkdir()
            orig.write_text("quarantined\n")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            quarantine_paths([orig], dest_dir=dest, manifest_path=manifest)
            orig.write_text("innocent\n")

            real_move = __import__("shutil").move
            calls = {"n": 0}

            def flaky(src, dst):
                calls["n"] += 1
                if calls["n"] == 2:
                    Path(dst).write_text("partial\n")
                    raise OSError("disk full")
                return real_move(src, dst)

            with mock.patch("sentinel.quarantine.shutil.move", side_effect=flaky):
                rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest, force=True)
            self.assertEqual(rec, [])
            self.assertTrue(fails, fails)
            self.assertEqual(orig.read_text(), "innocent\n")
            self.assertTrue((dest / "file.sh").exists())
            leftover = list(orig.parent.glob(".file.sh.sentinel-restore-aside*"))
            self.assertEqual(leftover, [])


class TestRestoreNoop(unittest.TestCase):
    def test_restore_empty_manifest(self) -> None:
        """Un manifest inexistant ou vide → restore ne fait rien."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            dest = td / "q"
            dest.mkdir()
            manifest = dest / "manifest.json"
            # Pas de fichier manifest encore.
            rec, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(rec, [])
            self.assertEqual(fails, [])


if __name__ == "__main__":
    unittest.main()
