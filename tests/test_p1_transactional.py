"""Tests P1-2 : quarantaine transactionnelle.

Le bug : `quarantine_file` fait hash → move → chmod → écrit le manifest
à la fin. Si on crash entre la 1ère et la 5ème entrée :
  - les 4 premiers fichiers sont déplacés (perdu pour l'utilisateur)
  - le manifest est corrompu ou n'existe pas (perdu pour l'audit)
  - shutil.move en cross-filesystem fait copie + suppression, donc le
    « ne supprime jamais » est faux au niveau source.

Le fix :
  1. Append `+ fsync` APRÈS chaque entrée (manifest = JSONL).
  2. Vérification du hash APRÈS le déplacement (lit le fichier déplacé,
     recompute SHA-256, compare à celui calculé avant). Si différent,
     on annule l'entrée et on tente de remettre l'original.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sentinel.quarantine as quarantine
from sentinel.quarantine import (
    _manifest_append,
    _manifest_read,
    quarantine_paths,
    restore_paths,
)


class TestManifestJsonl(unittest.TestCase):
    def test_append_creates_file(self) -> None:
        """Sur un manifest inexistant, _manifest_append crée le fichier
        avec un en-tête (première ligne)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            manifest = td / "m.jsonl"
            record = {"original": "/foo", "sha256": "abc", "_status": "done"}
            _manifest_append(manifest, record)
            self.assertTrue(manifest.is_file())
            lines = manifest.read_text().splitlines()
            self.assertEqual(len(lines), 1)
            obj = json.loads(lines[0])
            self.assertEqual(obj["original"], "/foo")

    def test_append_concatenates(self) -> None:
        """Sur un manifest existant, _manifest_append ajoute une ligne."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            manifest = td / "m.jsonl"
            _manifest_append(manifest, {"original": "/a"})
            _manifest_append(manifest, {"original": "/b"})
            _manifest_append(manifest, {"original": "/c"})
            lines = manifest.read_text().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertEqual(json.loads(lines[0])["original"], "/a")
            self.assertEqual(json.loads(lines[2])["original"], "/c")

    def test_read_parses_all_lines(self) -> None:
        """`_manifest_read` lit un JSONL et retourne tous les records."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            manifest = td / "m.jsonl"
            _manifest_append(manifest, {"original": "/a", "sha256": "1"})
            _manifest_append(manifest, {"original": "/b", "sha256": "2"})
            records = _manifest_read(manifest)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1]["sha256"], "2")


class TestTransactionalQuarantine(unittest.TestCase):
    def test_manifest_is_written_per_entry(self) -> None:
        """Le manifest doit contenir une ligne par fichier déplacé
        dès la fin de l'opération (pas un seul write en bloc)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src_dir = td / "src"
            src_dir.mkdir()
            files = []
            for i in range(5):
                p = src_dir / f"f_{i}.txt"
                p.write_text(f"content {i}\n")
                files.append(p)

            dest = td / "quarantine"
            manifest = dest / "manifest.jsonl"
            records, failures = quarantine_paths(
                files,
                dest_dir=dest,
                manifest_path=manifest,
            )
            self.assertEqual(failures, [])
            self.assertEqual(len(records), 5)

            # Deux lignes par fichier : intention, puis confirmation.
            self.assertTrue(manifest.is_file(), "manifest manquant")
            parsed = [json.loads(line) for line in manifest.read_text().splitlines()]
            done = [rec for rec in parsed if rec["_status"] == "done"]
            self.assertEqual(len(done), 5, f"attendu 5 confirmations, vu {len(done)}")
            self.assertEqual(len(parsed), 10, f"attendu 10 lignes, vu {len(parsed)}")
            for rec in done:
                self.assertEqual(rec["_status"], "done")
                self.assertIn("original", rec)
                self.assertIn("sha256", rec)
                self.assertIn("moved_at", rec)
                self.assertTrue(rec["id"])

    def test_hash_is_verified_after_move(self) -> None:
        """Le hash stocké est celui du fichier À L'ARRIVÉE, pas seulement
        celui d'avant. Si shutil.move corrompt, le sha256 doit diverger."""
        import tempfile as _tf

        with _tf.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src.txt"
            src.write_text("hello world\n")
            # P1-3 : dest séparé pour ne pas déclencher le path guard.
            dest = Path(_tf.mkdtemp(prefix="q-"))

            manifest = dest / "manifest.jsonl"
            quarantine_paths([src], dest_dir=dest, manifest_path=manifest)
            lines = manifest.read_text().splitlines()
            stored_sha = json.loads(lines[0])["sha256"]

            # Recompute depuis la destination.
            import hashlib

            actual_sha = hashlib.sha256((dest / "src.txt").read_bytes()).hexdigest()
            self.assertEqual(stored_sha, actual_sha)

    def test_restore_works_with_jsonl_manifest(self) -> None:
        """`restore_paths` doit fonctionner avec le nouveau format JSONL
        (pas seulement l'ancien JSON-array)."""
        import tempfile as _tf

        with _tf.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src" / "evil.sh"
            src.parent.mkdir()
            src.write_text("evil\n")
            dest = Path(_tf.mkdtemp(prefix="q-"))
            manifest = dest / "manifest.jsonl"
            quarantine_paths([src], dest_dir=dest, manifest_path=manifest)
            # src a été déplacé par quarantine.

            restored, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(fails, [])
            self.assertEqual(len(restored), 1)
            self.assertTrue(src.exists())
            self.assertEqual(src.read_text(), "evil\n")


class TestTwoPhaseJournal(unittest.TestCase):
    def test_kill_between_move_and_commit_recovers_four_cases(self) -> None:
        """SIGKILL entre le move et la confirmation, puis les quatre reprises.

        Le fichier tué est en quarantaine (confirmation). Les trois autres
        états sont posés dans le même journal : origine seule (annulation),
        les deux emplacements, aucun des deux (incohérent, rien n'est effacé).
        """
        import contextlib
        import hashlib
        import io
        import os
        import signal
        import subprocess
        import textwrap
        import threading

        from sentinel.quarantine import (
            _manifest_append,
            init_engine,
            recover_journal,
            restore_paths,
        )

        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src_dir = td / "src"
            src_dir.mkdir()
            payload = b"secret-alice\n"
            src = src_dir / "secret.txt"
            src.write_bytes(payload)
            dest = td / "quarantine"
            manifest = dest / "manifest.jsonl"
            script = textwrap.dedent(
                """
                import os
                import signal
                import sys
                from pathlib import Path

                import sentinel.quarantine as quarantine

                def die() -> None:
                    if os.name == "posix":
                        os.kill(os.getpid(), signal.SIGKILL)
                    os._exit(91)

                quarantine._crash_before_commit = die
                quarantine.quarantine_paths(
                    [Path(sys.argv[1])], Path(sys.argv[2]), Path(sys.argv[3])
                )
                """
            )
            env = os.environ.copy()
            previous = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(root) + (os.pathsep + previous if previous else "")
            proc = subprocess.run(
                [sys.executable, "-c", script, str(src), str(dest), str(manifest)],
                cwd=td,
                env=env,
                capture_output=True,
                text=True,
            )
            if os.name == "posix":
                self.assertEqual(proc.returncode, -signal.SIGKILL, proc.stderr)
            else:
                self.assertEqual(proc.returncode, 91, proc.stderr)

            quarantined = dest / "secret.txt"
            self.assertFalse(src.exists())
            self.assertEqual(quarantined.read_bytes(), payload)
            killed = [json.loads(line) for line in manifest.read_text().splitlines()]
            self.assertEqual(len(killed), 1)
            intent = killed[0]
            self.assertEqual(intent["_status"], "en cours")
            self.assertEqual(intent["original"], str(src))
            self.assertEqual(intent["quarantined"], str(quarantined))
            self.assertEqual(intent["size"], len(payload))
            self.assertEqual(intent["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertTrue(intent["id"])

            case_dir = td / "cases"
            case_dir.mkdir()
            only_origin = case_dir / "only-origin.txt"
            only_origin.write_bytes(b"origin\n")
            both_origin = case_dir / "both-origin.txt"
            both_origin.write_bytes(b"both\n")
            both_quar = dest / "both-origin.txt"
            both_quar.write_bytes(b"both\n")
            missing_origin = case_dir / "missing-origin.txt"
            missing_quar = dest / "missing-origin.txt"

            def intention(ident: str, original: Path, quarantined_path: Path) -> dict:
                return {
                    "id": ident,
                    "original": str(original),
                    "quarantined": str(quarantined_path),
                    "sha256": "abc",
                    "size": 1,
                    "mode_before": 0o644,
                    "_status": "en cours",
                }

            _manifest_append(
                manifest,
                intention("only-origin", only_origin, dest / "only-origin.txt"),
            )
            _manifest_append(manifest, intention("both", both_origin, both_quar))
            _manifest_append(manifest, intention("neither", missing_origin, missing_quar))

            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                issues = init_engine([manifest])
            report = captured.getvalue()
            self.assertIn("Rien n'a été supprimé", report)
            self.assertIn("les deux emplacements existent", report)
            self.assertIn("aucun des deux emplacements n'existe", report)
            self.assertEqual(
                {issue["id"]: issue["reason"] for issue in issues},
                {
                    "both": "les deux emplacements existent",
                    "neither": "aucun des deux emplacements n'existe",
                },
            )

            latest: dict[str, dict] = {}
            for rec in (json.loads(line) for line in manifest.read_text().splitlines()):
                latest[rec["id"]] = rec
            self.assertEqual(latest[intent["id"]]["_status"], "done")
            self.assertEqual(latest["only-origin"]["_status"], "annulé")
            self.assertEqual(latest["both"]["_status"], "incohérent")
            self.assertEqual(latest["neither"]["_status"], "incohérent")
            self.assertEqual(quarantined.read_bytes(), payload)
            self.assertFalse(src.exists())
            self.assertTrue(only_origin.is_file())
            self.assertFalse((dest / "only-origin.txt").exists())
            self.assertTrue(both_origin.is_file())
            self.assertTrue(both_quar.is_file())
            self.assertFalse(missing_origin.exists())
            self.assertFalse(missing_quar.exists())

            snapshot = manifest.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(init_engine([manifest]), [])
            self.assertEqual(manifest.read_bytes(), snapshot)

            race_origin = case_dir / "race.txt"
            race_origin.write_bytes(b"race\n")
            _manifest_append(
                manifest,
                intention("race", race_origin, dest / "race.txt"),
            )
            errors: list[BaseException] = []

            def recover_once() -> None:
                try:
                    recover_journal(manifest)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=recover_once) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
                self.assertFalse(thread.is_alive())
            self.assertFalse(errors)
            race_lines = [
                json.loads(line)
                for line in manifest.read_text().splitlines()
                if json.loads(line).get("id") == "race"
            ]
            self.assertEqual([rec["_status"] for rec in race_lines], ["en cours", "annulé"])
            self.assertTrue(race_origin.is_file())

            restored, fails = restore_paths(
                manifest_path=manifest,
                dest_dir=dest,
                only={str(src)},
            )
            self.assertEqual(fails, [])
            self.assertEqual(len(restored), 1)
            self.assertEqual(src.read_bytes(), payload)

    def test_restore_rewrites_the_journal_under_the_lock(self) -> None:
        import os
        from unittest import mock

        from sentinel import quarantine as journal

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src" / "note.txt"
            src.parent.mkdir()
            src.write_text("note\n", encoding="utf-8")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            quarantine_paths([src], dest_dir=dest, manifest_path=manifest)
            seen: dict[str, object] = {}
            real_replace = os.replace

            def spy(src_name: str, dst_name: str) -> None:
                seen["locked"] = journal._journal_lock.locked()
                seen["payload"] = Path(src_name).read_bytes()
                if os.name == "posix":
                    import fcntl

                    probe = os.open(journal._lock_file_path(manifest), os.O_RDWR)
                    try:
                        try:
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            seen["file_locked"] = True
                        else:
                            seen["file_locked"] = False
                            fcntl.flock(probe, fcntl.LOCK_UN)
                    finally:
                        os.close(probe)
                real_replace(src_name, dst_name)

            parents: list[str] = []
            real_dir = journal._fsync_directory

            def spy_dir(parent: str) -> None:
                parents.append(parent)
                real_dir(parent)

            with (
                mock.patch("sentinel.quarantine.os.replace", spy),
                mock.patch("sentinel.quarantine._fsync_directory", spy_dir),
            ):
                restored, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(fails, [])
            self.assertEqual(len(restored), 1)
            self.assertTrue(seen["locked"])
            if os.name == "posix":
                self.assertTrue(seen["file_locked"])
                self.assertEqual(parents, [os.path.dirname(journal._journal_key(manifest))])
                handle = journal._journal_handles[journal._journal_key(manifest)]
                self.assertEqual(os.fstat(handle.fileno()).st_ino, manifest.stat().st_ino)
            payload = seen["payload"]
            self.assertIsInstance(payload, bytes)
            assert isinstance(payload, bytes)
            self.assertIn(b'"restored"', payload)
            self.assertTrue(src.is_file())

            src2 = td / "src" / "other.txt"
            src2.write_text("other\n", encoding="utf-8")
            quarantine_paths([src2], dest_dir=dest, manifest_path=manifest)
            kept = manifest.read_bytes()

            def boom(_src: str, _dst: str) -> None:
                raise OSError("remplacement impossible")

            with (
                mock.patch("sentinel.quarantine.os.replace", boom),
                self.assertRaises(OSError),
            ):
                restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(manifest.read_bytes(), kept)


def _subprocess_env() -> dict[str, str]:
    import os

    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    previous = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(root) + (os.pathsep + previous if previous else "")
    return env


class TestJournalProcessLock(unittest.TestCase):
    def test_multiprocess_quarantine_and_restore_keep_journal_lines(self) -> None:
        """Une restauration ne doit pas effacer les lignes d'une quarantaine en cours.

        Le premier fichier est restauré pendant que le processus de
        quarantaine a encore son descripteur append ouvert. Les deux
        suivants doivent quand même être confirmés dans le fichier du chemin.
        """
        import subprocess
        import textwrap
        import time

        root_env = _subprocess_env()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src_dir = td / "src"
            src_dir.mkdir()
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            paused = td / "paused"
            resume = td / "resume"
            names = ("one.txt", "two.txt", "three.txt")
            payloads = {name: f"alice-{name}\n".encode() for name in names}
            paths = []
            for name in names:
                path = src_dir / name
                path.write_bytes(payloads[name])
                paths.append(path)
            script = textwrap.dedent(
                """
                import sys
                import time
                from pathlib import Path

                import sentinel.quarantine as quarantine

                files = [Path(item) for item in sys.argv[1].split("|")]
                dest = Path(sys.argv[2])
                manifest = Path(sys.argv[3])
                paused = Path(sys.argv[4])
                resume = Path(sys.argv[5])
                quarantine.quarantine_paths([files[0]], dest, manifest)
                paused.write_text("paused", encoding="utf-8")
                while not resume.exists():
                    time.sleep(0.02)
                quarantine.quarantine_paths(files[1:], dest, manifest)
                """
            )
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    script,
                    "|".join(str(path) for path in paths),
                    str(dest),
                    str(manifest),
                    str(paused),
                    str(resume),
                ],
                cwd=td,
                env=root_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while not paused.exists():
                    if proc.poll() is not None:
                        _out, err = proc.communicate()
                        self.fail(err)
                    if time.monotonic() > deadline:
                        self.fail("quarantaine non pausée")
                    time.sleep(0.02)
                restore_script = textwrap.dedent(
                    """
                    import sys
                    from pathlib import Path

                    from sentinel.quarantine import restore_paths

                    restore_paths(Path(sys.argv[1]), Path(sys.argv[2]))
                    """
                )
                restored = subprocess.run(
                    [sys.executable, "-c", restore_script, str(manifest), str(dest)],
                    cwd=td,
                    env=root_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(restored.returncode, 0, restored.stderr)
                resume.write_text("go", encoding="utf-8")
                _out, err = proc.communicate(timeout=15)
            except Exception:
                proc.kill()
                proc.communicate()
                raise
            self.assertEqual(proc.returncode, 0, err)
            self.assertTrue(paths[0].is_file())
            self.assertEqual(paths[0].read_bytes(), payloads["one.txt"])
            journal = manifest.read_text(encoding="utf-8")
            rows = [json.loads(line) for line in journal.splitlines() if line.strip()]
            latest: dict[str, dict] = {}
            for row in rows:
                quarantined = row.get("quarantined")
                if isinstance(quarantined, str):
                    latest[quarantined] = row
            for name in ("two.txt", "three.txt"):
                found = dest / name
                self.assertTrue(found.is_file(), name)
                self.assertEqual(found.read_bytes(), payloads[name])
                self.assertIn(str(found), journal)
                self.assertEqual(latest[str(found)]["_status"], "done")
            self.assertEqual(latest[str(dest / "one.txt")]["_status"], "restored")
            stray = {
                path.name
                for path in dest.iterdir()
                if path.is_file()
                and path.name not in {"manifest.jsonl", "manifest.jsonl.lock"}
                and not path.name.startswith(".journal-")
            }
            self.assertEqual(stray, {"two.txt", "three.txt"})

    def test_concurrent_recoveries_write_one_resolution_each(self) -> None:
        """Dix intentions, plusieurs processus : une seule résolution par id."""
        import subprocess
        import textwrap
        import time

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            manifest = td / "manifest.jsonl"
            case = td / "case"
            case.mkdir()
            for index in range(10):
                original = case / f"origin-{index}.txt"
                original.write_bytes(b"origin\n")
                _manifest_append(
                    manifest,
                    {
                        "id": f"id-{index}",
                        "original": str(original),
                        "quarantined": str(td / "q" / f"origin-{index}.txt"),
                        "sha256": "abc",
                        "size": 1,
                        "mode_before": 0o644,
                        "_status": "en cours",
                    },
                )
            slots = td / "slots"
            slots.mkdir()
            release = td / "release"
            script = textwrap.dedent(
                """
                import os
                import sys
                import time
                from pathlib import Path

                import sentinel.quarantine as quarantine

                slots = Path(sys.argv[2])
                release = Path(sys.argv[3])

                def pause() -> None:
                    (slots / str(os.getpid())).write_text("read", encoding="utf-8")
                    while not release.exists():
                        time.sleep(0.02)

                quarantine._after_pending_read = pause
                quarantine.recover_journal(Path(sys.argv[1]))
                """
            )
            procs = [
                subprocess.Popen(
                    [sys.executable, "-c", script, str(manifest), str(slots), str(release)],
                    cwd=td,
                    env=_subprocess_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(4)
            ]
            try:
                deadline = time.monotonic() + 10
                while len(list(slots.iterdir())) < 1:
                    if time.monotonic() > deadline:
                        self.fail("aucune reprise n'a lu le journal")
                    time.sleep(0.02)
                time.sleep(0.4)
                self.assertEqual(
                    len(list(slots.iterdir())),
                    1,
                    "plusieurs reprises ont lu le journal en même temps",
                )
                release.write_text("go", encoding="utf-8")
                for proc in procs:
                    _out, err = proc.communicate(timeout=15)
                    self.assertEqual(proc.returncode, 0, err)
            except Exception:
                release.write_text("go", encoding="utf-8")
                for proc in procs:
                    proc.kill()
                    proc.communicate()
                raise
            grouped: dict[str, list[str]] = {}
            for line in manifest.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                grouped.setdefault(row["id"], []).append(row["_status"])
            self.assertEqual(set(grouped), {f"id-{index}" for index in range(10)})
            for statuses in grouped.values():
                self.assertEqual(statuses, ["en cours", "annulé"])

    def test_process_started_during_move_does_not_cancel(self) -> None:
        """Un second processus ne marque pas « annulé » un move encore vivant.

        S'il est tué après le déplacement, la reprise confirme l'entrée
        et le fichier se restaure.
        """
        import os
        import signal
        import subprocess
        import textwrap
        import time

        if os.name != "posix":
            self.skipTest("SIGKILL requis pour lâcher le verrou sans confirmation")
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src" / "secret.txt"
            src.parent.mkdir()
            payload = b"secret-alice\n"
            src.write_bytes(payload)
            dest = td / "q"
            manifest = dest / "manifest.jsonl"
            holding = td / "holding"
            proceed = td / "proceed"
            moved = td / "moved"
            script = textwrap.dedent(
                """
                import os
                import signal
                import sys
                import time
                from pathlib import Path

                import sentinel.quarantine as quarantine

                def before() -> None:
                    Path(sys.argv[4]).write_text("holding", encoding="utf-8")
                    while not Path(sys.argv[5]).exists():
                        time.sleep(0.02)

                def after() -> None:
                    Path(sys.argv[6]).write_text("moved", encoding="utf-8")
                    time.sleep(30)
                    os.kill(os.getpid(), signal.SIGKILL)

                quarantine._before_move = before
                quarantine._crash_before_commit = after
                quarantine.quarantine_paths(
                    [Path(sys.argv[1])], Path(sys.argv[2]), Path(sys.argv[3])
                )
                """
            )
            mover = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    script,
                    str(src),
                    str(dest),
                    str(manifest),
                    str(holding),
                    str(proceed),
                    str(moved),
                ],
                cwd=td,
                env=_subprocess_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            recover = None
            try:
                deadline = time.monotonic() + 10
                while not holding.exists():
                    if mover.poll() is not None:
                        _out, err = mover.communicate()
                        self.fail(err)
                    if time.monotonic() > deadline:
                        self.fail("move non suspendu")
                    time.sleep(0.02)
                recover_script = textwrap.dedent(
                    """
                    import sys
                    from pathlib import Path

                    from sentinel.quarantine import recover_journal

                    recover_journal(Path(sys.argv[1]))
                    """
                )
                recover = subprocess.Popen(
                    [sys.executable, "-c", recover_script, str(manifest)],
                    cwd=td,
                    env=_subprocess_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                time.sleep(0.4)
                self.assertIsNone(recover.poll(), "la reprise n'a pas attendu le verrou")
                rows = [
                    json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual([row["_status"] for row in rows], ["en cours"])
                proceed.write_text("go", encoding="utf-8")
                deadline = time.monotonic() + 10
                while not moved.exists():
                    if mover.poll() is not None:
                        _out, err = mover.communicate()
                        self.fail(err)
                    if time.monotonic() > deadline:
                        self.fail("déplacement non terminé")
                    time.sleep(0.02)
                time.sleep(0.2)
                self.assertIsNone(recover.poll())
                self.assertEqual(
                    [json.loads(line)["_status"] for line in manifest.read_text().splitlines()],
                    ["en cours"],
                )
                os.kill(mover.pid, signal.SIGKILL)
                mover.communicate(timeout=10)
                _out, err = recover.communicate(timeout=15)
            except Exception:
                if recover is not None and recover.poll() is None:
                    recover.kill()
                    recover.communicate()
                if mover.poll() is None:
                    mover.kill()
                    mover.communicate()
                raise
            self.assertEqual(recover.returncode, 0, err)
            quarantined = dest / "secret.txt"
            self.assertEqual(quarantined.read_bytes(), payload)
            self.assertFalse(src.exists())
            statuses = [json.loads(line)["_status"] for line in manifest.read_text().splitlines()]
            self.assertEqual(statuses, ["en cours", "done"])
            restored, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertEqual(fails, [])
            self.assertEqual(len(restored), 1)
            self.assertEqual(src.read_bytes(), payload)

    def test_truncated_line_is_separated_and_kept(self) -> None:
        """Une ligne coupée ne colle pas à l'append, et la réécriture la garde."""
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            dest = td / "q"
            dest.mkdir()
            manifest = dest / "manifest.jsonl"
            fragment = '{"id": "cut", "_status": "en cours"'
            manifest.write_bytes(fragment.encode("utf-8"))
            _manifest_append(
                manifest,
                {
                    "id": "ok",
                    "original": str(td / "missing.txt"),
                    "quarantined": str(dest / "missing.txt"),
                    "sha256": "abc",
                    "size": 1,
                    "mode_before": 0o644,
                    "_status": "done",
                },
            )
            raw_lines = manifest.read_bytes().splitlines()
            self.assertEqual(raw_lines[0], fragment.encode("utf-8"))
            parsed = json.loads(raw_lines[1])
            self.assertEqual(parsed["id"], "ok")
            self.assertNotIn(b'cours"{', manifest.read_bytes().replace(b" ", b""))
            with contextlib.redirect_stderr(io.StringIO()):
                _restored, fails = restore_paths(manifest_path=manifest, dest_dir=dest)
            self.assertTrue(fails)
            kept = manifest.read_text(encoding="utf-8").splitlines()
            self.assertEqual(kept[0], fragment)
            self.assertEqual(json.loads(kept[1])["id"], "ok")

    def test_journal_lock_is_reentrant_and_keeps_the_process_lock(self) -> None:
        """Une section imbriquée ne lâche pas le flock du déplacement extérieur."""
        import fcntl
        import os

        if os.name == "nt":
            self.skipTest("sonde flock")
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("", encoding="utf-8")
            with quarantine._journal_exclusive(manifest):
                self.assertTrue(quarantine._journal_lock.locked())
                self.assertTrue(quarantine._journal_lock.acquire(timeout=0.2))
                quarantine._journal_lock.release()
                with quarantine._journal_exclusive(manifest):
                    probe = os.open(quarantine._lock_file_path(manifest), os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(probe)
                probe = os.open(quarantine._lock_file_path(manifest), os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe)
            self.assertFalse(quarantine._journal_lock.locked())

    def test_flush_does_not_wait_on_the_journal_lock(self) -> None:
        """Une sortie forcée n'attend pas le move qui tient le verrou."""
        import threading
        import time

        from sentinel.quarantine import flush_quarantine_journals

        release = threading.Event()
        held = threading.Event()

        def holder() -> None:
            with quarantine._journal_lock:
                held.set()
                release.wait(20)

        thread = threading.Thread(target=holder)
        thread.start()
        try:
            self.assertTrue(held.wait(2))
            started = time.monotonic()
            flush_quarantine_journals()
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            release.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())

    def test_thread_lock_wait_is_bounded(self) -> None:
        import threading
        import time
        from unittest import mock

        from sentinel.quarantine import JournalLocked

        release = threading.Event()
        held = threading.Event()

        def holder() -> None:
            with quarantine._journal_lock:
                held.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        manifest = Path(tempfile.mkdtemp()) / "manifest.jsonl"
        try:
            self.assertTrue(held.wait(2))
            manifest.write_text("", encoding="utf-8")
            started = time.monotonic()
            with (
                mock.patch.object(quarantine, "JOURNAL_LOCK_TIMEOUT", 0.4),
                self.assertRaises(JournalLocked) as caught,
                quarantine._journal_exclusive(manifest),
            ):
                pass
            elapsed = time.monotonic() - started
            self.assertEqual(str(caught.exception), "journal verrouillé par un autre processus")
            self.assertGreaterEqual(elapsed, 0.3)
            self.assertLess(elapsed, 2.0)
        finally:
            release.set()
            thread.join(2)

    def test_process_lock_wait_is_bounded_and_names_the_holder(self) -> None:
        """``flock`` / ``msvcrt`` n'attendent pas sans fin, et le message le dit."""
        import contextlib
        import io
        import subprocess
        import textwrap
        import time
        from unittest import mock

        from sentinel.__main__ import main
        from sentinel.quarantine import JournalLocked, recover_journal

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            manifest = td_path / "manifest.jsonl"
            ready = td_path / "ready"
            release = td_path / "release"
            script = textwrap.dedent(
                """
                import sys
                import time
                from pathlib import Path

                import sentinel.quarantine as quarantine

                manifest = Path(sys.argv[1])
                ready = Path(sys.argv[2])
                release = Path(sys.argv[3])
                manifest.write_text("", encoding="utf-8")
                with quarantine._journal_exclusive(manifest):
                    ready.write_text("holding", encoding="utf-8")
                    deadline = time.monotonic() + 30
                    while not release.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                """
            )
            proc = subprocess.Popen(
                [sys.executable, "-c", script, str(manifest), str(ready), str(release)],
                cwd=td,
                env=_subprocess_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    if proc.poll() is not None:
                        _out, err = proc.communicate()
                        self.fail(err)
                    if time.monotonic() > deadline:
                        self.fail("verrou non pris")
                    time.sleep(0.02)
                started = time.monotonic()
                with (
                    mock.patch.object(quarantine, "JOURNAL_LOCK_TIMEOUT", 0.4),
                    self.assertRaises(JournalLocked) as caught,
                ):
                    recover_journal(manifest)
                elapsed = time.monotonic() - started
            finally:
                release.write_text("go", encoding="utf-8")
                if proc.poll() is None:
                    proc.wait(timeout=10)
                if proc.poll() is None:
                    proc.kill()
                proc.communicate()
            self.assertEqual(str(caught.exception), "journal verrouillé par un autre processus")
            self.assertGreaterEqual(elapsed, 0.3)
            self.assertLess(elapsed, 2.0)
            self.assertEqual(proc.returncode, 0)

        buf = io.StringIO()
        with (
            mock.patch("sentinel.__main__.init_engine", side_effect=JournalLocked),
            contextlib.redirect_stderr(buf),
        ):
            code = main(["scan", str(Path(tempfile.gettempdir()))])
        self.assertEqual(code, 1)
        self.assertIn("journal verrouillé par un autre processus", buf.getvalue())

    def test_remote_filesystem_uses_an_exclusive_hostlock(self) -> None:
        """NFS/SMB : flock ne suffit pas. O_EXCL + pid/hôte exclut vraiment."""
        import contextlib
        import io
        import os
        from unittest import mock

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("keep\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))
            buf = io.StringIO()
            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs4"),
                contextlib.redirect_stderr(buf),
            ):
                quarantine._acquire_process_lock(manifest, timeout=1)
                self.assertTrue(hostlock.is_file())
                owner = quarantine._hostlock_owner(str(hostlock))
                self.assertEqual(owner, quarantine._our_hostlock())
                self.assertEqual(manifest.read_text(encoding="utf-8"), "keep\n")
                quarantine._acquire_process_lock(manifest, timeout=1)
                quarantine._release_process_lock(manifest)
                self.assertTrue(hostlock.is_file())
                quarantine._release_process_lock(manifest)
            self.assertFalse(hostlock.exists())
            self.assertEqual(manifest.read_text(encoding="utf-8"), "keep\n")
            text = buf.getvalue()
            self.assertIn("nfs4", text)
            self.assertIn("flock", text)
            self.assertIn("NFS", text)
            self.assertIn("SMB", text)
            self.assertIn("O_EXCL", text)
            self.assertEqual(text.count("O_EXCL"), 1)

    def test_hostlock_excludes_even_if_flock_does_not(self) -> None:
        """Un flock qui réussit toujours (client NFS) ne laisse pas passer un second O_EXCL."""
        import contextlib
        import io
        import os
        import time
        from unittest import mock

        from sentinel.quarantine import JournalLocked

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("keep\n", encoding="utf-8")
            hostlock = quarantine._hostlock_path(manifest)

            def flock_noop(*_args: object, **_kwargs: object) -> None:
                return None

            buf = io.StringIO()
            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="smb3"),
                mock.patch("fcntl.flock", flock_noop),
                contextlib.redirect_stderr(buf),
            ):
                quarantine._acquire_process_lock(manifest, timeout=1)
                try:
                    self.assertTrue(Path(hostlock).is_file())
                    started = time.monotonic()
                    with self.assertRaises(JournalLocked) as caught:
                        quarantine._acquire_hostlock(hostlock, time.monotonic() + 0.3)
                    self.assertGreaterEqual(time.monotonic() - started, 0.2)
                    message = str(caught.exception)
                    self.assertIn("journal verrouillé par un autre processus", message)
                    self.assertIn(f"hôte : {quarantine._our_host()}", message)
                    self.assertIn(f"pid : {os.getpid()}", message)
                    self.assertIn("âge :", message)
                    self.assertIn(hostlock, message)
                    self.assertEqual(manifest.read_text(encoding="utf-8"), "keep\n")
                finally:
                    quarantine._release_process_lock(manifest)
            self.assertFalse(Path(hostlock).exists())
            self.assertIn("O_EXCL", buf.getvalue())

    def test_stale_same_host_lock_is_reclaimed_foreign_and_live_are_not(self) -> None:
        import os
        from unittest import mock

        from sentinel.quarantine import JournalLocked

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("same\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))

            def alive(pid: int) -> bool:
                return pid == os.getpid()

            def start_token(pid: int) -> str:
                return "self-start" if pid == os.getpid() else "other-start"

            def write_lock(lock: quarantine._HostLock) -> None:
                hostlock.write_bytes(quarantine._encode_hostlock(lock))

            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs"),
                mock.patch.object(quarantine, "_pid_alive", side_effect=alive),
                mock.patch.object(quarantine, "_process_start_token", side_effect=start_token),
                mock.patch.object(quarantine, "_our_boot_id", return_value="boot-a"),
                mock.patch.object(quarantine, "_our_machine_id", return_value="machine-a"),
            ):
                ours = quarantine._our_hostlock()
                write_lock(
                    quarantine._HostLock(424242, ours.host, "old", ours.boot_id, ours.machine_id)
                )
                quarantine._acquire_process_lock(manifest, timeout=1)
                owner = quarantine._hostlock_owner(str(hostlock))
                self.assertEqual(owner, quarantine._our_hostlock())
                quarantine._release_process_lock(manifest)
                self.assertFalse(hostlock.exists())

                write_lock(ours)
                with self.assertRaises(JournalLocked):
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(
                    hostlock.read_bytes(),
                    quarantine._encode_hostlock(ours),
                )

                foreign = quarantine._HostLock(1, "other-host", "x", "boot-b", "machine-b")
                write_lock(foreign)
                with self.assertRaises(JournalLocked) as caught:
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(hostlock.read_bytes(), quarantine._encode_hostlock(foreign))
                message = str(caught.exception)
                self.assertIn("hôte : other-host", message)
                self.assertIn("pid : 1", message)
                self.assertIn("âge :", message)
                self.assertIn(str(hostlock), message)
                self.assertIn("SENTINEL_HOSTLOCK_STALE_SECONDS", message)
                self.assertIn("supprimez ce fichier", message)
                self.assertEqual(manifest.read_text(encoding="utf-8"), "same\n")
            hostlock.unlink()

    def test_pid_reuse_reclaims_only_when_the_start_time_differs(self) -> None:
        """Un pid recyclé n'est pas le détenteur : l'instant de démarrage tranche."""
        import os
        from unittest import mock

        from sentinel.quarantine import JournalLocked

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("reuse\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))

            def alive(pid: int) -> bool:
                return pid in {50, os.getpid()}

            def start_token(pid: int) -> str:
                if pid == 50:
                    return "reused-start"
                if pid == os.getpid():
                    return "self-start"
                return "other-start"

            def write_lock(lock: quarantine._HostLock) -> None:
                hostlock.write_bytes(quarantine._encode_hostlock(lock))

            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs"),
                mock.patch.object(quarantine, "_pid_alive", side_effect=alive),
                mock.patch.object(quarantine, "_process_start_token", side_effect=start_token),
                mock.patch.object(quarantine, "_our_boot_id", return_value="boot-a"),
                mock.patch.object(quarantine, "_our_machine_id", return_value="machine-a"),
            ):
                reused = quarantine._HostLock(
                    50, quarantine._our_host(), "original-start", "boot-a", "machine-a"
                )
                write_lock(reused)
                quarantine._acquire_process_lock(manifest, timeout=1)
                owner = quarantine._hostlock_owner(str(hostlock))
                self.assertIsNotNone(owner)
                assert owner is not None
                self.assertEqual(owner.pid, os.getpid())
                self.assertEqual(owner.start, "self-start")
                quarantine._release_process_lock(manifest)
                self.assertFalse(hostlock.exists())

                live = quarantine._HostLock(
                    50, quarantine._our_host(), "reused-start", "boot-a", "machine-a"
                )
                write_lock(live)
                with self.assertRaises(JournalLocked):
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(hostlock.read_bytes(), quarantine._encode_hostlock(live))
            if hostlock.exists():
                hostlock.unlink()

    def test_same_hostname_on_another_machine_is_not_the_same_process(self) -> None:
        """Même hostname, autre boot id et machine-id : le pid local ne compte pas."""
        import os
        from unittest import mock

        from sentinel.quarantine import JournalLocked

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("remote\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))
            foreign = quarantine._HostLock(
                1,
                "shared-name",
                "their-start",
                "boot-other",
                "machine-other",
            )
            hostlock.write_bytes(quarantine._encode_hostlock(foreign))

            def alive(pid: int) -> bool:
                return pid == os.getpid()

            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs"),
                mock.patch.object(quarantine, "_pid_alive", side_effect=alive),
                mock.patch.object(quarantine, "_our_host", return_value="shared-name"),
                mock.patch.object(quarantine, "_our_boot_id", return_value="boot-here"),
                mock.patch.object(quarantine, "_our_machine_id", return_value="machine-here"),
                mock.patch.object(quarantine, "HOSTLOCK_STALE_AFTER_S", 10_000),
            ):
                with self.assertRaises(JournalLocked) as caught:
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(hostlock.read_bytes(), quarantine._encode_hostlock(foreign))
                message = str(caught.exception)
                self.assertIn("hôte : shared-name", message)
                self.assertIn("pid : 1", message)
                self.assertIn(str(hostlock), message)
                self.assertIn("boot id : boot-other", message)
                self.assertIn("machine-id : machine-other", message)
            hostlock.unlink()

    def test_boot_id_without_machine_id_does_not_reclaim_a_dead_pid(self) -> None:
        """Sans machine-id, le boot id seul ne reprend pas un pid mort ou recyclé."""
        import os
        import time
        from unittest import mock

        from sentinel.quarantine import JournalLocked

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("boot\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))

            def alive(pid: int) -> bool:
                return pid in {50, os.getpid()}

            def start_token(pid: int) -> str:
                if pid == 50:
                    return "reused-start"
                if pid == os.getpid():
                    return "self-start"
                return "other-start"

            def write_lock(lock: quarantine._HostLock, *, age: float | None = None) -> None:
                hostlock.write_bytes(quarantine._encode_hostlock(lock))
                if age is not None:
                    old = time.time() - age
                    os.utime(hostlock, (old, old))

            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs"),
                mock.patch.object(quarantine, "_pid_alive", side_effect=alive),
                mock.patch.object(quarantine, "_process_start_token", side_effect=start_token),
                mock.patch.object(quarantine, "_our_boot_id", return_value="boot-shared"),
                mock.patch.object(quarantine, "_our_machine_id", return_value=""),
                mock.patch.object(quarantine, "HOSTLOCK_STALE_AFTER_S", 10_000),
            ):
                dead = quarantine._HostLock(
                    1, quarantine._our_host(), "gone-start", "boot-shared", ""
                )
                write_lock(dead)
                with self.assertRaises(JournalLocked):
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(hostlock.read_bytes(), quarantine._encode_hostlock(dead))

                reused = quarantine._HostLock(
                    50, quarantine._our_host(), "original-start", "boot-shared", ""
                )
                write_lock(reused)
                with self.assertRaises(JournalLocked):
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(hostlock.read_bytes(), quarantine._encode_hostlock(reused))

                live = quarantine._HostLock(
                    50, quarantine._our_host(), "reused-start", "boot-shared", ""
                )
                write_lock(live)
                with self.assertRaises(JournalLocked):
                    quarantine._acquire_process_lock(manifest, timeout=0.3)
                self.assertEqual(hostlock.read_bytes(), quarantine._encode_hostlock(live))

                write_lock(dead, age=5_000)
            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs"),
                mock.patch.object(quarantine, "_pid_alive", side_effect=alive),
                mock.patch.object(quarantine, "_process_start_token", side_effect=start_token),
                mock.patch.object(quarantine, "_our_boot_id", return_value="boot-shared"),
                mock.patch.object(quarantine, "_our_machine_id", return_value=""),
                mock.patch.dict(os.environ, {"SENTINEL_HOSTLOCK_STALE_SECONDS": "1000"}),
            ):
                quarantine._acquire_process_lock(manifest, timeout=1)
                owner = quarantine._hostlock_owner(str(hostlock))
                self.assertIsNotNone(owner)
                assert owner is not None
                self.assertEqual(owner.pid, os.getpid())
                quarantine._release_process_lock(manifest)
            self.assertFalse(hostlock.exists())

    def test_foreign_hostlock_expires_when_the_heartbeat_is_old(self) -> None:
        import os
        import time
        from unittest import mock

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("age\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))
            foreign = quarantine._HostLock(99, "other-host", "start", "boot-b", "machine-b")
            hostlock.write_bytes(quarantine._encode_hostlock(foreign))
            old = time.time() - 5_000
            os.utime(hostlock, (old, old))
            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="smb"),
                mock.patch.dict(os.environ, {"SENTINEL_HOSTLOCK_STALE_SECONDS": "1000"}),
            ):
                quarantine._acquire_process_lock(manifest, timeout=1)
                owner = quarantine._hostlock_owner(str(hostlock))
                self.assertIsNotNone(owner)
                assert owner is not None
                self.assertEqual(owner.pid, os.getpid())
                self.assertEqual(owner.host, quarantine._our_host())
                quarantine._release_process_lock(manifest)
            self.assertFalse(hostlock.exists())

    def test_heartbeat_refreshes_the_hostlock_mtime(self) -> None:
        import os
        import time
        from unittest import mock

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("beat\n", encoding="utf-8")
            hostlock = Path(quarantine._hostlock_path(manifest))
            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="nfs"),
                mock.patch.object(quarantine, "HOSTLOCK_HEARTBEAT_S", 0.05),
            ):
                quarantine._acquire_process_lock(manifest, timeout=1)
                try:
                    old = time.time() - 100
                    os.utime(hostlock, (old, old))
                    deadline = time.monotonic() + 2
                    refreshed = False
                    while time.monotonic() < deadline:
                        if os.stat(hostlock).st_mtime >= old + 50:
                            refreshed = True
                            break
                        time.sleep(0.02)
                    self.assertTrue(refreshed)
                finally:
                    quarantine._release_process_lock(manifest)
            self.assertFalse(hostlock.exists())

    def test_linux_stat_start_time_ignores_spaces_in_comm(self) -> None:
        raw = b"42 (python (test)) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0\n"
        self.assertEqual(quarantine._parse_linux_stat_start(raw), "999")
        self.assertIsNone(quarantine._parse_linux_stat_start(b"1 (short) S 1\n"))

    def test_local_filesystem_does_not_create_a_hostlock(self) -> None:
        import contextlib
        import io
        from unittest import mock

        quarantine._remote_lock_warned.clear()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.jsonl"
            manifest.write_text("", encoding="utf-8")
            buf = io.StringIO()
            with (
                mock.patch.object(quarantine, "_lock_fstype", return_value="ext4"),
                contextlib.redirect_stderr(buf),
            ):
                quarantine._acquire_process_lock(manifest, timeout=1)
                quarantine._release_process_lock(manifest)
            self.assertEqual(buf.getvalue(), "")
            self.assertFalse(Path(quarantine._hostlock_path(manifest)).exists())

    def test_cancel_during_process_lock_wait_leaves_the_journal(self) -> None:
        import subprocess
        import textwrap
        import threading
        import time

        from sentinel.quarantine import JournalInterrupted, bind_journal_cancel, recover_journal

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            manifest = td_path / "manifest.jsonl"
            payload = '{"_status": "en cours", "id": "keep", "original": "/home/alice/notes.txt"}\n'
            manifest.write_text(payload, encoding="utf-8")
            ready = td_path / "ready"
            release = td_path / "release"
            script = textwrap.dedent(
                """
                import sys
                import time
                from pathlib import Path

                import sentinel.quarantine as quarantine

                manifest = Path(sys.argv[1])
                ready = Path(sys.argv[2])
                release = Path(sys.argv[3])
                with quarantine._journal_exclusive(manifest):
                    ready.write_text("holding", encoding="utf-8")
                    deadline = time.monotonic() + 30
                    while not release.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                """
            )
            proc = subprocess.Popen(
                [sys.executable, "-c", script, str(manifest), str(ready), str(release)],
                cwd=td,
                env=_subprocess_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            cancel = threading.Event()
            done = threading.Event()
            caught: list[BaseException] = []
            thread: threading.Thread | None = None

            def waiter() -> None:
                try:
                    with bind_journal_cancel(cancel):
                        recover_journal(manifest)
                except Exception as exc:
                    caught.append(exc)
                finally:
                    done.set()

            try:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    if proc.poll() is not None:
                        _out, err = proc.communicate()
                        self.fail(err)
                    if time.monotonic() > deadline:
                        self.fail("verrou non pris")
                    time.sleep(0.02)
                started = time.monotonic()
                thread = threading.Thread(target=waiter)
                thread.start()
                time.sleep(0.15)
                cancel.set()
                self.assertTrue(done.wait(2))
                elapsed = time.monotonic() - started
            finally:
                release.write_text("go", encoding="utf-8")
                if proc.poll() is None:
                    proc.wait(timeout=10)
                if proc.poll() is None:
                    proc.kill()
                proc.communicate()
            self.assertIsNotNone(thread)
            assert thread is not None
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(caught), 1)
            self.assertIsInstance(caught[0], JournalInterrupted)
            self.assertIn("interrompue", str(caught[0]))
            self.assertLess(elapsed, 1.5)
            self.assertEqual(manifest.read_text(encoding="utf-8"), payload)
            self.assertEqual(proc.returncode, 0)
            self.assertFalse(quarantine._journal_lock.locked())

    def test_cancel_during_thread_lock_wait_does_not_enter_the_section(self) -> None:
        import threading
        import time

        from sentinel.quarantine import JournalInterrupted, bind_journal_cancel

        release = threading.Event()
        held = threading.Event()

        def holder() -> None:
            with quarantine._journal_lock:
                held.set()
                release.wait(30)

        thread = threading.Thread(target=holder)
        thread.start()
        worker: threading.Thread | None = None
        try:
            with tempfile.TemporaryDirectory() as td:
                manifest = Path(td) / "manifest.jsonl"
                manifest.write_text("untouched\n", encoding="utf-8")
                cancel = threading.Event()
                seen: list[BaseException] = []

                def waiter() -> None:
                    try:
                        with (
                            bind_journal_cancel(cancel),
                            quarantine._journal_exclusive(manifest),
                        ):
                            seen.append(RuntimeError("section entrée"))
                    except Exception as exc:
                        seen.append(exc)

                self.assertTrue(held.wait(2))
                worker = threading.Thread(target=waiter)
                worker.start()
                time.sleep(0.1)
                started = time.monotonic()
                cancel.set()
                worker.join(2)
                elapsed = time.monotonic() - started
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(seen), 1)
                self.assertIsInstance(seen[0], JournalInterrupted)
                self.assertLess(elapsed, 1.5)
                self.assertEqual(manifest.read_text(encoding="utf-8"), "untouched\n")
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(quarantine._journal_lock.locked())

    def test_darwin_mount_table_picks_the_longest_network_mount(self) -> None:
        sample = (
            "/dev/disk1s1 on / (apfs, local, journaled)\n"
            "//alice@nas/share on /Volumes/share (smbfs, nodev, nosuid)\n"
            "nas:/export on /Volumes/share/docs (nfs, nodev)\n"
            "//alice@nas/space on /Volumes/my share (smbfs, nodev)\n"
        )
        mounts = quarantine._parse_mount_output(sample)
        self.assertEqual(
            quarantine._lock_fstype_from_mounts("/Volumes/share/docs/journal.lock", mounts),
            "nfs",
        )
        self.assertEqual(
            quarantine._lock_fstype_from_mounts("/Volumes/share/other.lock", mounts),
            "smbfs",
        )
        self.assertEqual(
            quarantine._lock_fstype_from_mounts("/Users/alice/journal.lock", mounts),
            "apfs",
        )
        self.assertEqual(
            quarantine._lock_fstype_from_mounts("/Volumes/my share/journal.lock", mounts),
            "smbfs",
        )
        self.assertIn("smbfs", quarantine._REMOTE_LOCK_FS)
        self.assertNotIn("apfs", quarantine._REMOTE_LOCK_FS)

    def test_windows_unc_and_remote_drive_are_network_filesystems(self) -> None:
        def drive_type(root: str) -> int | None:
            if root.upper().startswith("Z:"):
                return 4
            if root.upper().startswith("C:"):
                return 3
            return None

        self.assertEqual(
            quarantine._lock_fstype_windows(r"C:\Users\alice\journal.lock", drive_type),
            "local",
        )
        self.assertEqual(
            quarantine._lock_fstype_windows(r"Z:\share\journal.lock", drive_type),
            "smb",
        )
        self.assertEqual(
            quarantine._lock_fstype_windows(r"\\nas\share\journal.lock", drive_type),
            "smb",
        )
        self.assertIn("smb", quarantine._REMOTE_LOCK_FS)

    def test_lock_fstype_uses_the_longest_mount(self) -> None:
        import io
        import os
        from unittest import mock

        if not os.path.isfile("/proc/mounts"):
            self.skipTest("pas de /proc/mounts")
        sample = (
            "rootfs / rootfs rw 0 0\n"
            "/dev/sda1 / ext4 rw 0 0\n"
            "nas:/vol /mnt/share nfs4 rw 0 0\n"
            "//srv/docs /mnt/share/docs cifs rw 0 0\n"
            "//srv/space /mnt/my\\040share smb3 rw 0 0\n"
        )
        real_open = open

        def fake_open(path: str, *args: object, **kwargs: object) -> object:
            if path == "/proc/mounts":
                return io.StringIO(sample)
            return real_open(path, *args, **kwargs)

        with (
            mock.patch("builtins.open", fake_open),
            mock.patch("sentinel.quarantine.os.path.realpath", side_effect=lambda p: p),
        ):
            self.assertEqual(quarantine._lock_fstype("/mnt/share/docs/journal.lock"), "cifs")
            self.assertEqual(quarantine._lock_fstype("/mnt/share/other.lock"), "nfs4")
            self.assertEqual(quarantine._lock_fstype("/home/alice/journal.lock"), "ext4")
            self.assertEqual(quarantine._lock_fstype("/mnt/my share/journal.lock"), "smb3")


if __name__ == "__main__":
    unittest.main()
