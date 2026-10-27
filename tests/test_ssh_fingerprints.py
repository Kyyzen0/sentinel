import tempfile
import unittest
from pathlib import Path

from sentinel.integrity import make_baseline
from sentinel.scanner import scan_folder


class FingerprintBaselineTests(unittest.TestCase):
    def test_added_key_without_storing_file_content(self):
        for secret in (None, "test-secret"):
            with self.subTest(secret=secret), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                keys = root / "authorized_keys"
                keys.write_text("ssh-ed25519 AAAAold comment\n")
                baseline = make_baseline(root, encrypt_key=secret)
                entry = baseline["entries"][0]
                self.assertIsNone(entry["content"])
                self.assertEqual(len(entry["ssh_key_fingerprints"]), 1)
                unchanged = scan_folder(root, baseline=baseline, encrypt_key=secret)
                self.assertNotIn("SIG-0019", [finding.rule_id for finding in unchanged.findings])
                keys.write_text("ssh-ed25519 AAAAold comment\nssh-rsa AAAAnew another\n")
                report = scan_folder(root, baseline=baseline, encrypt_key=secret)
                self.assertIn("SIG-0019", [finding.rule_id for finding in report.findings])
