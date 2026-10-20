"""Tests pour la commande `watch` (polling fallback)."""

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.watch import (
    _diff_snapshots,
    _FileStamp,
    _snapshot,
    has_watchdog,
    watch_polling,
)


class TestSnapshot(unittest.TestCase):
    def test_snapshot_lists_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("hello")
            (td / "b.txt").write_text("world")
            sub = td / "sub"
            sub.mkdir()
            (sub / "c.txt").write_text("!")
            snap = _snapshot(td)
            self.assertIn("a.txt", snap)
            self.assertIn("b.txt", snap)
            self.assertIn("sub/c.txt", snap)
            self.assertEqual(snap["a.txt"].size, 5)

    def test_snapshot_skips_pycache(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "ok.txt").write_text("ok")
            pc = td / "__pycache__"
            pc.mkdir()
            (pc / "x.cpython-39.pyc").write_text("xyz")
            snap = _snapshot(td)
            self.assertIn("ok.txt", snap)
            self.assertFalse(any("__pycache__" in p for p in snap))


class TestDiff(unittest.TestCase):
    def test_added_removed_modified(self) -> None:
        a = _FileStamp("a", 1.0, 10)
        b = _FileStamp("b", 1.0, 10)
        prev = {"a": a, "b": b}
        a2 = _FileStamp("a", 1.0, 99)  # size change
        c = _FileStamp("c", 1.0, 10)
        cur = {"a": a2, "c": c}
        d = _diff_snapshots(prev, cur)
        self.assertEqual(d["added"], ["c"])
        self.assertEqual(d["removed"], ["b"])
        self.assertEqual(d["modified"], ["a"])

    def test_no_changes(self) -> None:
        a = _FileStamp("a", 1.0, 10)
        prev = {"a": a}
        cur = {"a": a}
        d = _diff_snapshots(prev, cur)
        self.assertFalse(any(d.values()))


class TestPollingCallback(unittest.TestCase):
    def test_callback_fires_on_modification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            target = td / "hello.txt"
            target.write_text("hello\n")

            events: list[dict] = []

            def cb(diff: dict) -> None:
                events.append(dict(diff))

            # Lance un thread qui modifie le fichier pendant la boucle polling.
            def modify_after_delay() -> None:
                time.sleep(0.1)
                target.write_text("hello world!\n")

            t = threading.Thread(target=modify_after_delay, daemon=True)
            t.start()
            watch_polling(td, interval=0.02, on_change=cb, max_iterations=15)
            t.join(timeout=2.0)

            self.assertTrue(events, f"aucun diff capturé: {events!r}")
            union_modified = [p for e in events for p in e.get("modified", [])]
            union_added = [p for e in events for p in e.get("added", [])]
            self.assertTrue(
                "hello.txt" in union_modified or "hello.txt" in union_added,
                f"hello.txt absent de {events!r}",
            )


class TestHasWatchdog(unittest.TestCase):
    def test_returns_bool(self) -> None:
        # Le simple fait que ça ne plante pas est le test.
        self.assertIsInstance(has_watchdog(), bool)


if __name__ == "__main__":
    unittest.main()
