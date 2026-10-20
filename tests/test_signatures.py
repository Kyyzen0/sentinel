"""Tests par signature — vérifient que les 16 règles détectent bien leurs fixtures.

La fixture `tests/fixtures/sig/` est l'« oracle » : pour chaque règle, on
sait exactement combien de findings elle doit produire sur le jeu
complet, et sur quelles lignes. Ces tests figent ce comportement.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.scanner import scan_folder

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sig"


class _BaseScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan_folder(FIX)

    def _findings_for_rule(self, rule_id: str):
        return [f for f in self.report.findings if f.rule_id == rule_id]


class TestSig0001_2_3_4_5(TestCase := _BaseScan, unittest.TestCase):
    def test_sig0001_php_webshell(self):
        findings = self._findings_for_rule("SIG-0001")
        paths = {(f.path, f.line) for f in findings}
        self.assertIn(("bad_utf8.php", 1), paths)
        self.assertIn(("webshell.php", 2), paths)

    def test_sig0002_reverse_shell(self):
        findings = self._findings_for_rule("SIG-0002")
        self.assertEqual(
            {(f.path, f.line) for f in findings},
            {("reverse.sh", 1), ("reverse.sh", 2), ("reverse.sh", 3), ("reverse.sh", 4)},
        )

    def test_sig0003_download_then_exec(self):
        findings = self._findings_for_rule("SIG-0003")
        paths = {(f.path, f.line) for f in findings}
        # 2 entries dans crontab.txt + 3 dans download.sh
        self.assertIn(("crontab.txt", 1), paths)
        self.assertIn(("crontab.txt", 2), paths)
        self.assertIn(("download.sh", 1), paths)
        self.assertIn(("download.sh", 2), paths)
        self.assertIn(("download.sh", 3), paths)
        # FAUX POSITIFS à éviter :
        self.assertNotIn(("inject.sh", 4), paths)  # curl chaîné via &&
        self.assertNotIn((".bashrc", 1), paths)  # wget dans une sous-shell

    def test_sig0004_encoded_payload(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0004")}
        self.assertEqual(paths, {("encoded.txt", 1), ("encoded.txt", 2), ("encoded.txt", 3)})

    def test_sig0005_miner(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0005")}
        self.assertEqual(paths, {("miner.conf", 1), ("miner.conf", 2), ("miner.conf", 3)})


class TestSig0006_7_8_9(_BaseScan):
    def test_sig0006_cron_persistence(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0006")}
        self.assertEqual(paths, {("crontab.txt", 1), ("crontab.txt", 2)})

    def test_sig0007_ssh_authorized_keys(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0007")}
        self.assertEqual(paths, {("authorized_keys", 1), ("authorized_keys", 2)})

    def test_sig0008_private_keys(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0008")}
        # RSA + OpenSSH + EC + PKCS#8 (V2)
        self.assertIn(("id_rsa", 1), paths)
        self.assertIn(("openssh_key", 1), paths)
        self.assertIn(("ec_private.pem", 1), paths)
        self.assertIn(("pkcs8.pem", 1), paths)

    def test_sig0009_shell_injection(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0009")}
        self.assertEqual(paths, {("inject.sh", i) for i in range(1, 5)})


class TestSig0010_11_12_13_14_15_16(_BaseScan):
    def test_sig0010_attack_useragent(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0010")}
        self.assertEqual(paths, {("headers.txt", 2)})

    def test_sig0011_jsp_webshell(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0011")}
        self.assertEqual(paths, {("webshell.jsp", 1)})

    def test_sig0012_log4shell(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0012")}
        self.assertEqual(paths, {("jndi.txt", 1)})

    def test_sig0013_htaccess(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0013")}
        self.assertEqual(paths, {(".htaccess", 1), (".htaccess", 2)})

    def test_sig0014_bashrc_persistence(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0014")}
        self.assertEqual(paths, {(".bashrc", 1)})

    def test_sig0015_passwd_sudoers(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0015")}
        self.assertEqual(paths, {("passwd", 1), ("sudoers", 1)})

    def test_sig0016_ld_preload_tmp(self):
        paths = {(f.path, f.line) for f in self._findings_for_rule("SIG-0016")}
        self.assertEqual(paths, {("ld_preload.sh", 1)})


class TestOverallCounts(_BaseScan):
    def test_overall_counts_match_v2_demo(self):
        # Démo V2 : critical=12 high=20 medium=6 low=0 = 38 findings.
        self.assertEqual(self.report.severity_counts["critical"], 12)
        self.assertEqual(self.report.severity_counts["high"], 20)
        self.assertEqual(self.report.severity_counts["medium"], 6)
        self.assertEqual(self.report.severity_counts["low"], 0)
        self.assertEqual(self.report.overall_severity, "critical")


class TestHeuristicAnomaly(unittest.TestCase):
    def test_high_entropy_file_scores_above_60(self):
        from sentinel.anomaly import score_heuristic

        path = Path(__file__).resolve().parents[1] / "tests" / "high_entropy.txt"
        scores = score_heuristic([path])
        self.assertEqual(len(scores), 1)
        # Le fichier base64 déterministe doit obtenir un score élevé.
        self.assertGreater(
            scores[0].score,
            60.0,
            f"score d'anomalie trop bas pour high_entropy.txt: {scores[0].score}",
        )
        self.assertEqual(scores[0].method, "heuristic")


class TestIntegrity(unittest.TestCase):
    def test_baseline_then_detect_modification(self):
        import json
        import tempfile

        from sentinel.integrity import diff_against_baseline, make_baseline, write_baseline_to

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "data"
            target.mkdir()
            f = target / "hello.txt"
            f.write_text("hello\n")
            baseline_file = Path(td) / "baseline.json"
            write_baseline_to(target, baseline_file)
            ref = json.loads(baseline_file.read_text())

            # Modifier un fichier
            f.write_text("hello!\n")
            current = make_baseline(target)
            diff = diff_against_baseline(current, ref)
            self.assertEqual(diff.modified, ["hello.txt"])
            self.assertEqual(diff.added, [])
            self.assertEqual(diff.removed, [])

            # Ajouter un fichier
            (target / "new.txt").write_text("new\n")
            current = make_baseline(target)
            diff = diff_against_baseline(current, ref)
            self.assertIn("new.txt", diff.added)
            self.assertEqual(diff.modified, ["hello.txt"])

            # Supprimer un fichier
            f.unlink()
            current = make_baseline(target)
            diff = diff_against_baseline(current, ref)
            self.assertIn("hello.txt", diff.removed)


if __name__ == "__main__":
    unittest.main()
