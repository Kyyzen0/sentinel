"""Non-régressions V4 : bugs corrigés après la PR #2.

Chaque test couvre un défaut constaté à l'exécution :
  1. `sentinel quarantine` plantait en AttributeError (`args.folder` absent).
  2. Un dossier mis en quarantaine passait en 0444 : plus traversable.
  3. Les `.pyc` sous `__pycache__/` étaient scannés et indexés dans la baseline.
  4. Le manifest était écrasé au 2e passage (perte d'audit).
  5. `diff_against_baseline` reparcourait le disque au lieu d'utiliser `current`.
  6. `datetime.utcnow()` déprécié (Python 3.12+).
"""

import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.files import is_ignored
from sentinel.integrity import diff_against_baseline, make_baseline
from sentinel.quarantine import quarantine_file


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


class TestQuarantineCli(unittest.TestCase):
    def test_cli_does_not_crash_and_writes_manifest_under_dest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            victim = td / "evil.sh"
            victim.write_text("#!/bin/sh\nrm -rf /\n")
            # P1-3 : dest séparé pour ne pas déclencher le garde-fou.
            dest = Path(tempfile.mkdtemp(prefix="q-"))

            r = _run("quarantine", str(victim), "--dest", str(dest))

            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("Traceback", r.stderr)
            self.assertFalse(victim.exists())
            self.assertTrue((dest / "evil.sh").is_file())
            # P1-2 : le manifest est maintenant en JSONL (1 ligne par
            # entrée) ; défaut documenté : <dest>/manifest.jsonl.
            self.assertTrue((dest / "manifest.jsonl").is_file())

    def test_manifest_is_appended_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            # P1-3 : dest séparé pour ne pas déclencher le garde-fou.
            dest = Path(tempfile.mkdtemp(prefix="q-"))
            for name in ("a.sh", "b.sh"):
                f = td / name
                f.write_text("x\n")
                _run("quarantine", str(f), "--dest", str(dest))

            # Une confirmation par fichier (l'intention « en cours » précède).
            lines = (dest / "manifest.jsonl").read_text().splitlines()
            records = [json.loads(line) for line in lines]
            committed = [rec for rec in records if rec["_status"] == "done"]
            self.assertEqual(len(committed), 2)
            self.assertEqual(
                sorted(Path(r["original"]).name for r in committed),
                ["a.sh", "b.sh"],
            )


class TestQuarantineDirectory(unittest.TestCase):
    def test_directory_stays_traversable_and_readonly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "evil_dir"
            src.mkdir()
            (src / "payload.sh").write_text("curl x | sh\n")

            # P1-3 : dest séparé pour ne pas déclencher le garde-fou.
            rec = quarantine_file(src, Path(tempfile.mkdtemp(prefix="q-")))
            moved = Path(rec.quarantined)

            mode = moved.stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"dossier non traversable: {oct(mode)}")
            self.assertFalse(mode & stat.S_IWUSR, f"dossier encore inscriptible: {oct(mode)}")
            # Le contenu doit rester lisible (audit) et non modifiable.
            child = moved / "payload.sh"
            self.assertEqual(child.read_text(), "curl x | sh\n")
            self.assertFalse(child.stat().st_mode & stat.S_IWUSR)


class TestIgnoredPaths(unittest.TestCase):
    def test_pycache_is_ignored_at_any_depth(self) -> None:
        self.assertTrue(is_ignored(Path("__pycache__/x.cpython-313.pyc")))
        self.assertTrue(is_ignored(Path("a/b/__pycache__/x.pyc")))
        self.assertFalse(is_ignored(Path("a/b/x.py")))

    def test_baseline_skips_pycache_contents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "main.py").write_text("print(1)\n")
            pc = td / "__pycache__"
            pc.mkdir()
            (pc / "main.cpython-313.pyc").write_text("cached\n")

            paths = [e["path"] for e in make_baseline(td)["entries"]]
            self.assertEqual(paths, ["main.py"])


class TestDiffUsesCurrentEntries(unittest.TestCase):
    def test_diff_survives_folder_disappearing(self) -> None:
        """`current` porte déjà les entrées : le diff ne doit pas relire le disque."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("one\n")
            ref = make_baseline(td)
            current = make_baseline(td)
            shutil.rmtree(td)

            diff = diff_against_baseline(current, ref)
            self.assertEqual(diff.added, [])
            self.assertEqual(diff.removed, [])
            self.assertEqual(diff.modified, [])

    def test_modification_is_still_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "a.txt"
            f.write_text("one\n")
            ref = make_baseline(td)
            f.write_text("two\n")
            diff = diff_against_baseline(make_baseline(td), ref)
            self.assertEqual(diff.modified, ["a.txt"])


class TestUtcTimestamp(unittest.TestCase):
    def test_moved_at_is_iso_utc_and_warning_free(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "x.sh"
            f.write_text("x\n")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                # P1-3 : dest séparé pour ne pas déclencher le garde-fou.
                rec = quarantine_file(f, Path(tempfile.mkdtemp(prefix="q-")))
            deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
            self.assertEqual(deprecations, [])
            self.assertRegex(rec.moved_at, re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"))


if __name__ == "__main__":
    unittest.main()
