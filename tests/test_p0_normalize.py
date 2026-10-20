"""Tests P0-5 : couche de normalisation des payloads obfusqués.

Le bug : détection purement ligne-à-ligne. Concaténation de chaînes,
\\x-escapes, payloads sur plusieurs lignes, base64 maison : tout
passe à travers les règles.

Le fix : un module `sentinel/normalize.py` qui pré-traite le texte
AVANT les règles. Stratégie minimale mais efficace :
  1. Décodage des `\\xHH` (hex), `\\uHHHH` (unicode) et `\\OOO` (octal).
  2. Résolution des concaténations Python : `"abc" "def"` → `"abcdef"`.
  3. Décodage des littéraux base64 « évidents » (alphabet b64, ≥32 chars).

Le scanner applique la normalisation à chaque ligne AVANT de la passer
aux règles. Les numéros de ligne sont préservés (normalisation 1 ligne
→ 1 ligne).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.normalize import normalize_line, normalize_text


class TestNormalizeLine(unittest.TestCase):
    def test_passes_through_simple_text(self) -> None:
        self.assertEqual(normalize_line("hello world"), "hello world")

    def test_decodes_hex_escape(self) -> None:
        # \\x41 = 'A', \\x42 = 'B' → "AB"
        self.assertEqual(normalize_line("\\x41\\x42"), "AB")

    def test_decodes_unicode_escape(self) -> None:
        # \\u0041 = 'A'
        self.assertEqual(normalize_line("\\u0041BC"), "ABC")

    def test_decodes_octal_escape(self) -> None:
        # \\101 = 'A' (octal 101 = 65 = 'A')
        self.assertEqual(normalize_line("\\101BC"), "ABC")

    def test_resolves_python_string_concat(self) -> None:
        self.assertEqual(
            normalize_line('"hello " "world"'),
            '"hello world"',
        )

    def test_decodes_obvious_base64(self) -> None:
        # 'aGVsbG8gd29ybGQ=' est base64 de "hello world" — 16 chars,
        # en-dessous de notre seuil 32. On utilise un plus long payload
        # qui reste non-ambigu.
        # 'eval(base64_decode(...))' encode en base64 ≈ 88 chars.
        import base64

        b64 = base64.b64encode(b'eval(base64_decode($_POST["x"]))').decode()
        line_with_b64 = f"secret = '{b64}'"
        normalized = normalize_line(line_with_b64)
        # La version décodée doit apparaître dans la sortie.
        self.assertIn("eval(base64_decode", normalized)

    def test_ignores_short_base64(self) -> None:
        # Trop court pour être fiable (≤ 32 chars alphanum).
        self.assertEqual(normalize_line("aGVsbG8="), "aGVsbG8=")

    def test_ignores_non_b64_strings(self) -> None:
        # Que des caractères hors alphabet base64 → pas de décodage.
        self.assertEqual(normalize_line("hello world !@#"), "hello world !@#")


class TestNormalizeText(unittest.TestCase):
    def test_preserves_line_numbers(self) -> None:
        # normalize_text doit retourner une liste (1 par ligne) et chaque
        # ligne doit avoir la même position relative.
        text = "line 1\neval(\\x41)\nline 3"
        out = normalize_text(text)
        self.assertEqual(len(out), 3)
        # La ligne 2 doit être décodée ; les autres passent.
        self.assertEqual(out[1], "eval(A)")

    def test_empty_text(self) -> None:
        self.assertEqual(normalize_text(""), [""])

    def test_single_line(self) -> None:
        self.assertEqual(normalize_text("foo"), ["foo"])


class TestScannerAppliesNormalization(unittest.TestCase):
    def test_x_escaped_webshell_is_detected(self) -> None:
        """Un .php qui cache `eval(` via \\x-escape doit être détecté."""
        from sentinel.scanner import scan_folder

        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            f = td / "obfuscated.php"
            # 'eval(' = \x65\x76\x61\x6c\x28
            f.write_text('<?php\n$x = "\\x65\\x76\\x61\\x6c(base64_decode(...))";\n?>\n')
            report = scan_folder(td)
            rule_ids = {f_.rule_id for f_ in report.findings}
            self.assertIn(
                "SIG-0001",
                rule_ids,
                f"SIG-0001 doit fire sur un webshell obfusqué, mais on a eu {rule_ids}",
            )

    def test_concatenated_webshell_is_detected(self) -> None:
        """Un payload splitté en deux chaînes concaténées doit être détecté."""
        from sentinel.scanner import scan_folder

        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            f = td / "concat.php"
            f.write_text('<?php\n$x = "ev" "al(base64_decode($_POST["x"]))";\n?>\n')
            report = scan_folder(td)
            rule_ids = {f_.rule_id for f_ in report.findings}
            self.assertIn("SIG-0001", rule_ids)


if __name__ == "__main__":
    unittest.main()
