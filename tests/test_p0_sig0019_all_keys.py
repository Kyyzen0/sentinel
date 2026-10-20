"""Tests P0-6 : SIG-0019 doit détecter TOUS types de clés SSH ajoutées
post-baseline, pas seulement ed25519.

Le bug : la V4 ne couvre que ed25519. Une clé ssh-rsa ajoutée n'est
vue que par SIG-0007 (« une clé existe »), pas comme ajout.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.models import RuleContext
from sentinel.signatures import Sig0019


class TestSig0019AllKeyTypes(unittest.TestCase):
    def _ctx(self, baseline_text: str) -> RuleContext:
        return RuleContext(baseline_text=baseline_text)

    def test_no_baseline_no_finding(self) -> None:
        """Sans baseline, on reste silencieux (mêmes contraintes que V4)."""
        findings = list(
            Sig0019().scan(
                "authorized_keys",
                "ssh-ed25519 AAAA new@host\n",
                context=RuleContext(baseline_text=None),
            )
        )
        self.assertEqual(findings, [])

    def test_ssh_rsa_key_added(self) -> None:
        """ssh-rsa ajoutée post-baseline : doit être détectée (avant V4 : raté)."""
        baseline = "ssh-rsa AAAA initial@host\n"
        current = baseline + "ssh-rsa BBBB new@evil\n"
        findings = list(Sig0019().scan("authorized_keys", current, context=self._ctx(baseline)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SIG-0019")

    def test_ecdsa_key_added(self) -> None:
        """ecdsa-sha2-nistp256 ajoutée post-baseline : doit être détectée."""
        baseline = "ssh-rsa AAAA initial@host\n"
        current = baseline + "ecdsa-sha2-nistp256 BBBB new@evil\n"
        findings = list(Sig0019().scan("authorized_keys", current, context=self._ctx(baseline)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SIG-0019")

    def test_ed25519_key_added_still_works(self) -> None:
        """Régression : ed25519 reste détectée."""
        baseline = "ssh-ed25519 AAAA initial@host\n"
        current = baseline + "ssh-ed25519 BBBB new@evil\n"
        findings = list(Sig0019().scan("authorized_keys", current, context=self._ctx(baseline)))
        self.assertEqual(len(findings), 1)

    def test_mixed_keys_added(self) -> None:
        """Plusieurs types ajoutés d'un coup : 1 finding par fichier,
        couvrant l'ensemble des ajouts. L'evidence pointe vers le type
        de la PREMIÈRE clé ajoutée."""
        baseline = "ssh-ed25519 AAAA old1@host\nssh-rsa CCCC old2@host\n"
        current = (
            baseline
            + "ssh-ed25519 DDDD new1@evil\n"
            + "ecdsa-sha2-nistp256 EEEE new2@evil\n"
            + "ssh-rsa FFFF new3@evil\n"
        )
        findings = list(Sig0019().scan("authorized_keys", current, context=self._ctx(baseline)))
        # 1 seul finding (déduplication : « authorized_keys a été augmenté »)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SIG-0019")
        # L'evidence mentionne le type de la première clé ajoutée.
        self.assertIn("ssh-ed25519", findings[0].evidence)

    def test_unchanged_no_finding(self) -> None:
        baseline = "ssh-rsa AAAA\nssh-ed25519 CCCC\n"
        findings = list(Sig0019().scan("authorized_keys", baseline, context=self._ctx(baseline)))
        self.assertEqual(findings, [])

    def test_key_removed_not_a_finding(self) -> None:
        """Retrait de clé : PAS un finding (le modèle c'est « ajout »,
        pas diff symétrique — un retrait est légitime côté utilisateur)."""
        baseline = "ssh-rsa AAAA old\nssh-rsa BBBB removed\n"
        current = "ssh-rsa AAAA old\n"
        findings = list(Sig0019().scan("authorized_keys", current, context=self._ctx(baseline)))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
