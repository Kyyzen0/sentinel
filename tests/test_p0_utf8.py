"""Tests P0-1 : looks_binary() ne doit pas rejeter les fichiers non-ASCII.

Le bug : l'ancien `looks_binary` comptait les octets > 0x7E comme
inhabituels, ce qui rejetait tout texte UTF-8 (chinois, arabe, emoji…),
qu'il soit légitime ou qu'il contienne du payload malveillant.

Le fix : test NUL d'abord (vrai binaire), puis décoder en UTF-8 et
compter les caractères non-imprimables (catégorie Unicode Cc) + caractères
de remplacement (`\ufffd`). Le ratio seuillé est 30 % sur la CHAÎNE
DÉCODÉE, pas sur les octets bruts.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.files import looks_binary, read_text_safely


class TestLooksBinaryAcceptsUtf8(unittest.TestCase):
    def test_chinese_text_is_not_binary(self) -> None:
        # Texte chinois pur : 100 % multi-byte, ne doit PAS être binaire.
        text = "你好世界，这是一段普通的中文文本，用于测试。" * 4
        self.assertFalse(looks_binary(text.encode("utf-8")))

    def test_japanese_text_is_not_binary(self) -> None:
        self.assertFalse(looks_binary("こんにちは世界".encode()))

    def test_emoji_text_is_not_binary(self) -> None:
        self.assertFalse(looks_binary("Hello 👋 World 🌍 🚀".encode()))

    def test_arabic_text_is_not_binary(self) -> None:
        self.assertFalse(looks_binary("مرحبا بالعالم".encode()))

    def test_accented_french_is_not_binary(self) -> None:
        # Texte latin étendu (Français/Européen).
        self.assertFalse(looks_binary("héllo àëîôû çœæ ÉÀ".encode()))

    def test_nul_byte_is_binary(self) -> None:
        # Un vrai binaire contient des NUL.
        self.assertTrue(looks_binary(b"hello\x00world"))

    def test_random_binary_blob_is_binary(self) -> None:
        # 256 octets pseudo-aléatoires : après décode UTF-8, beaucoup
        # de U+FFFD → binaire.
        import os

        self.assertTrue(looks_binary(os.urandom(256)))

    def test_real_php_webshell_in_chinese_is_not_binary(self) -> None:
        # Le cas du bug original : un .php en chinois contenant du code
        # malveillant doit être lu comme texte pour que SIG-0001 fire.
        text = (
            "<?php\n"
            "// 后门 webshell - 隐藏访问\n"
            "$_ = $_POST['cmd'];\n"
            "eval(base64_decode($_));\n"
            "?>\n"
        )
        self.assertFalse(looks_binary(text.encode("utf-8")))


class TestReadTextSafelyAcceptsUtf8(unittest.TestCase):
    def test_chinese_php_webshell_is_read(self) -> None:
        # Cas du bug : SIG-0001 doit pouvoir analyser un .php en chinois.
        with __import__("tempfile").TemporaryDirectory() as td:
            td_path = Path(td)
            f = td_path / "backdoor_zh.php"
            f.write_text(
                "<?php\n$x = $_POST['x'];\neval(base64_decode($x));\necho '中文后门';\n?>\n",
                encoding="utf-8",
            )
            text = read_text_safely(f)
            self.assertIsNotNone(
                text, "read_text_safely doit retourner le contenu d'un .php chinois"
            )
            self.assertIn("eval(base64_decode", text)

    def test_nul_heavy_file_returns_none(self) -> None:
        # Vrai binaire : doit toujours retourner None.
        with __import__("tempfile").TemporaryDirectory() as td:
            f = Path(td) / "blob.bin"
            f.write_bytes(b"\x00\x01\x02hello\x00world\x00")
            self.assertIsNone(read_text_safely(f))


if __name__ == "__main__":
    unittest.main()
