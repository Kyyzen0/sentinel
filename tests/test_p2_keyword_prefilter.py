"""Tests P2-3 : préfiltre par sous-chaîne avant les regex.

Le bug : pour chaque ligne × 19 règles × N patterns par règle, on
applique des regex coûteuses même si la ligne ne contient pas la
sous-chaîne évidente. Sur 1 M de lignes, c'est prohibitif.

Le fix : chaque Rule expose une méthode `quick_keywords()` qui
retourne l'ensemble des sous-chaînes qui, si absentes, permettent
de skip toutes les regex de la règle. Le scanner check d'abord le
keyword avant de tenter les regex.

Stratégie : on garde ça opt-in. Pour SIG-0001 par exemple, les
keywords sont {`eval`, `base64_decode`, `system`, `passthru`, `shell_exec`,
`exec`, `proc_open`}. Si aucun n'est présent dans la ligne, on skip
directement.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.signatures import ALL_RULES, Sig0001, Sig0002


class TestRuleQuickKeywords(unittest.TestCase):
    def test_sig0001_keywords(self) -> None:
        """SIG-0001 : keywords = fonctions PHP dangereuses."""
        kws = Sig0001().quick_keywords()
        self.assertIsNotNone(kws)
        # On attend au minimum eval, base64_decode, system.
        self.assertIn("eval", kws)
        self.assertIn("base64_decode", kws)
        self.assertIn("system", kws)

    def test_sig0002_keywords(self) -> None:
        """SIG-0002 : keywords = reverse-shell primitives."""
        kws = Sig0002().quick_keywords()
        self.assertIsNotNone(kws)
        self.assertIn("/dev/tcp/", kws)
        self.assertIn("ncat", kws)

    def test_all_rules_have_keywords(self) -> None:
        """Toutes les règles exposées via ALL_RULES ont un `quick_keywords()`."""
        for rule in ALL_RULES:
            self.assertTrue(
                hasattr(rule, "quick_keywords"),
                f"règle {rule.rule_id} ({type(rule).__name__}) n'a pas quick_keywords()",
            )
            kws = rule.quick_keywords()
            # Les keywords peuvent être None (règle full-regex sans
            # sous-chaîne évidente) ou un set non-vide.
            if kws is not None:
                self.assertGreater(len(kws), 0, f"{rule.rule_id} : keywords vides")


class TestRulePrefilter(unittest.TestCase):
    """Vérifie que les règles SKIPENT les lignes qui ne contiennent aucun
    de leurs keywords — implémentation réelle."""

    def test_sig0001_skips_lines_without_php_keywords(self) -> None:
        rule = Sig0001()
        # Ligne sans aucun keyword → scan doit retourner []
        findings = list(
            rule.scan(
                "test.php",
                "// This is a comment, no PHP execution here\n",
            )
        )
        self.assertEqual(findings, [])

    def test_sig0001_fires_on_eval(self) -> None:
        rule = Sig0001()
        findings = list(
            rule.scan(
                "shell.php",
                "<?php eval($_POST['x']); ?>\n",
            )
        )
        self.assertGreater(len(findings), 0)

    def test_sig0002_skips_lines_without_reverse_shell(self) -> None:
        rule = Sig0002()
        findings = list(
            rule.scan(
                "script.sh",
                "echo hello world\n",  # no reverse shell indicator
            )
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
