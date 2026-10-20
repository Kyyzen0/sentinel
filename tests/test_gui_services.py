"""Services de l'interface, sans Qt.

La resignature, le dossier de données et la clé de session doivent se
comporter comme le CLI, y compris là où PySide6 n'est pas installé.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.gui import main as gui_main  # noqa: E402
from sentinel.gui import missing_gui_message  # noqa: E402
from sentinel.gui.locations import data_dir, data_dir_text  # noqa: E402
from sentinel.gui.services import (  # noqa: E402
    commit_resign,
    create_baseline,
    describe_baseline,
    load_baseline_for_scan,
)
from sentinel.gui.session import SessionKey  # noqa: E402


class TestResignService(unittest.TestCase):
    def test_unsigned_without_trust_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tree"
            root.mkdir()
            (root / "a.txt").write_text("ok\n", encoding="utf-8")
            out = Path(td) / "base.json"
            create_baseline(root, out, None)
            before = out.read_bytes()
            with self.assertRaises(ValueError) as ctx:
                commit_resign(out, "secret-key", trust_unsigned=False, backup=False)
            self.assertIn("trust-unsigned", str(ctx.exception))
            self.assertEqual(out.read_bytes(), before)

    def test_trust_marks_resigned_from_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tree"
            root.mkdir()
            (root / "a.txt").write_text("ok\n", encoding="utf-8")
            out = Path(td) / "base.json"
            create_baseline(root, out, None)
            commit_resign(out, "secret-key", trust_unsigned=True, backup=True)
            loaded = json.loads(out.read_text(encoding="utf-8"))
            self.assertIs(loaded["resigned_from_unsigned"], True)
            self.assertTrue((Path(str(out) + ".bak")).is_file())
            view = describe_baseline(out, "secret-key")
            self.assertTrue(view.present)
            self.assertTrue(view.signed)
            self.assertTrue(view.verified)
            self.assertTrue(view.resigned_from_unsigned)

    def test_bad_signature_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tree"
            root.mkdir()
            (root / "a.txt").write_text("ok\n", encoding="utf-8")
            out = Path(td) / "base.json"
            create_baseline(root, out, "secret-key")
            loaded = json.loads(out.read_text(encoding="utf-8"))
            loaded["root"] = str(root) + "-tampered"
            out.write_text(json.dumps(loaded), encoding="utf-8")
            before = out.read_bytes()
            with self.assertRaises(ValueError):
                commit_resign(out, "secret-key", trust_unsigned=True, backup=False)
            self.assertEqual(out.read_bytes(), before)


class TestSessionAndLocations(unittest.TestCase):
    def test_session_key_stays_in_memory(self) -> None:
        key = SessionKey()
        key.set("  super-secret  \n")
        self.assertEqual(key.value, "  super-secret  ")
        key.set("secret\r\n")
        self.assertEqual(key.value, "secret")
        key.clear()
        self.assertIsNone(key.value)
        key.set("")
        self.assertIsNone(key.value)

    def test_data_dirs_follow_the_os(self) -> None:
        self.assertEqual(
            data_dir_text(platform="linux", os_name="posix", home="/home/alice", environ={}),
            "/home/alice/.local/share/sentinel",
        )
        self.assertEqual(
            data_dir_text(
                platform="linux",
                os_name="posix",
                home="/home/alice",
                environ={"XDG_DATA_HOME": "/var/xdg"},
            ),
            "/var/xdg/sentinel",
        )
        self.assertEqual(
            data_dir_text(
                platform="win32",
                os_name="nt",
                home=r"C:\Users\alice",
                environ={"LOCALAPPDATA": r"C:\Users\alice\AppData\Local"},
            ),
            r"C:\Users\alice\AppData\Local\Sentinel",
        )
        self.assertEqual(
            data_dir_text(platform="win32", os_name="nt", home=r"C:\Users\alice", environ={}),
            r"C:\Users\alice\AppData\Local\Sentinel",
        )
        self.assertEqual(
            data_dir_text(platform="darwin", os_name="posix", home="/Users/alice", environ={}),
            "/Users/alice/Library/Application Support/Sentinel",
        )
        with tempfile.TemporaryDirectory() as td:
            old = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = td
            try:
                live = data_dir()
            finally:
                if old is None:
                    os.environ.pop("XDG_DATA_HOME", None)
                else:
                    os.environ["XDG_DATA_HOME"] = old
            self.assertTrue(live.is_dir())
            if sys.platform != "darwin" and os.name != "nt":
                self.assertEqual(live, Path(td) / "sentinel")


class TestScanBaselinePolicy(unittest.TestCase):
    def _unsigned(self, root: Path) -> Path:
        folder = root / "tree"
        folder.mkdir()
        (folder / "a.txt").write_text("a\n", encoding="utf-8")
        out = root / "base.json"
        create_baseline(folder, out, None)
        return out

    def test_require_signed_env_refuses_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = self._unsigned(Path(td))
            old = os.environ.get("SENTINEL_REQUIRE_SIGNED")
            os.environ["SENTINEL_REQUIRE_SIGNED"] = "1"
            try:
                loaded, error, _warning = load_baseline_for_scan(
                    out, None, require_signed=False, allow_unverified=False
                )
            finally:
                if old is None:
                    os.environ.pop("SENTINEL_REQUIRE_SIGNED", None)
                else:
                    os.environ["SENTINEL_REQUIRE_SIGNED"] = old
            self.assertIsNone(loaded)
            self.assertIn("non signée", error or "")

    def test_both_flags_are_a_conflict(self) -> None:
        loaded, error, _warning = load_baseline_for_scan(
            None, None, require_signed=True, allow_unverified=True
        )
        self.assertIsNone(loaded)
        self.assertIn("incompatibles", error or "")

    def test_unsigned_warning_matches_the_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = self._unsigned(Path(td))
            os.environ.pop("SENTINEL_REQUIRE_SIGNED", None)
            loaded, error, warning = load_baseline_for_scan(
                out, None, require_signed=False, allow_unverified=False
            )
            self.assertIsNone(error)
            self.assertIsNotNone(loaded)
            self.assertIn("non signée", warning or "")

    def test_self_check_does_not_need_a_display(self) -> None:
        import sentinel

        self.assertIn("sentinel[gui]", missing_gui_message())
        self.assertEqual(gui_main(["--self-check"]), 0)
        self.assertEqual(gui_main(["--version"]), 0)
        # Python 3.10 résout ``mock.patch("sentinel.quarantine...")`` par
        # accès d'attribut. Le retirer casse la suite.
        self.assertIsNotNone(sentinel.quarantine)
        self.assertIsNotNone(sentinel.integrity)


if __name__ == "__main__":
    unittest.main()
