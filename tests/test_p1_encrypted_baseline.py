"""Tests P1-4 : baseline chiffrée par HMAC.

Le bug : la baseline JSON embarque le contenu UTF-8 des fichiers de
config sensibles (authorized_keys, /etc/passwd, /etc/shadow, .env...).
Stocké en clair sur disque, c'est une fuite latente : n'importe qui
qui accède au fichier de baseline peut lire les hashs de mots de
passe, les clés SSH autorisées, etc.

Le fix : option `--encrypt-key` sur `baseline` (et `scan` qui
l'accepte pour la comparaison). Au lieu de stocker `content`, on
stocke `hmac_sha256(key, content)`. Le contenu n'est jamais écrit sur
disque. La comparaison reste possible (HMAC vs HMAC).

Cas couverts :
  - baseline avec `--encrypt-key` ne contient PAS le mot "authorized_keys" en clair
  - sans `--encrypt-key`, comportement par défaut inchangé (content stocké)
  - scan avec la même clé détecte les modifications
  - scan sans clé après une baseline chiffrée → SIG-0019 dit "can't compare"
"""

import hashlib
import hmac
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.integrity import (
    _hmac_content,
    diff_against_baseline,
    load_baseline_text,
    make_baseline,
)


class TestHmacContent(unittest.TestCase):
    def test_hmac_deterministic(self) -> None:
        """Le HMAC est déterministe : même clé + même contenu = même HMAC."""
        a = _hmac_content("clé-top", b"hello")
        b = _hmac_content("clé-top", b"hello")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)  # SHA-256 hex = 64 chars

    def test_hmac_changes_with_content(self) -> None:
        a = _hmac_content("k", b"hello")
        b = _hmac_content("k", b"hellp")  # 1 bit de différence
        self.assertNotEqual(a, b)

    def test_hmac_changes_with_key(self) -> None:
        a = _hmac_content("k1", b"hello")
        b = _hmac_content("k2", b"hello")
        self.assertNotEqual(a, b)


class TestEncryptedBaseline(unittest.TestCase):
    def test_baseline_without_key_stores_content(self) -> None:
        """Comportement par défaut : `content` est stocké en clair."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "secret.txt"
            f.write_text("password=hunter2\n", newline="\n")
            bl = make_baseline(td)
            entry = bl["entries"][0]
            self.assertIn("content", entry)
            self.assertEqual(entry["content"], "password=hunter2\n")
            # P1-4 : sans clé, hmac_sha256 reste None (pas de HMAC stocké).
            self.assertIsNone(entry.get("hmac_sha256"))

    def test_baseline_with_key_stores_hmac_not_content(self) -> None:
        """Avec `--encrypt-key`, le contenu n'est PAS stocké en clair :
        on stocke uniquement le HMAC."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "authorized_keys"
            f.write_text("ssh-ed25519 AAAA...user@host\n", newline="\n")
            bl = make_baseline(td, encrypt_key="top-secret")
            entry = bl["entries"][0]

            # Pas de `content` en clair.
            self.assertIsNone(entry.get("content"))
            # HMAC présent et fait 64 chars.
            self.assertIsNotNone(entry.get("hmac_sha256"))
            self.assertEqual(len(entry["hmac_sha256"]), 64)
            # Le contenu de la baseline sérialisée ne fuite pas le mot
            # sensible (juste le HMAC).
            serialized = json.dumps(bl)
            self.assertNotIn("AAAA...user", serialized)
            self.assertNotIn("ssh-ed25519", serialized)
            self.assertNotIn("hunter2", serialized)
            # Le HMAC peut être vérifié offline par quelqu'un qui a la clé.
            expected = hmac.new(
                b"top-secret",
                b"ssh-ed25519 AAAA...user@host\n",
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(entry["hmac_sha256"], expected)

    def test_baseline_does_not_leak_via_hmac_serialization(self) -> None:
        """Le JSON de la baseline ne doit pas contenir le contenu des
        fichiers sensibles — uniquement les HMAC et les métadonnées."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "id_rsa"
            f.write_text("-----BEGIN RSA PRIVATE KEY-----\nFOO\n")
            bl = make_baseline(td, encrypt_key="k")
            text = json.dumps(bl)
            self.assertNotIn("FOO", text)
            self.assertNotIn("BEGIN RSA", text)
            self.assertNotIn("PRIVATE", text)

    def test_diff_with_key_uses_hmac(self) -> None:
        """Avec une clé, le diff de contenu utilise HMAC vs HMAC.
        Si on modifie le fichier, le HMAC change, le diff le voit."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "cfg"
            f.write_text("v1\n")
            bl = make_baseline(td, encrypt_key="k")

            # Modifie le fichier.
            f.write_text("v2\n")
            current = make_baseline(td, encrypt_key="k")
            diff = diff_against_baseline(current, bl)
            # Le fichier apparaît comme modified.
            self.assertIn("cfg", diff.modified)


class TestLoadBaselineTextWithKey(unittest.TestCase):
    def test_load_baseline_text_returns_none_for_hmac_only(self) -> None:
        """Une baseline chiffrée ne permet pas de récupérer le contenu
        en clair : load_baseline_text retourne None (SIG-0019 annoncera
        qu'elle ne peut pas comparer)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "secret.sh"
            f.write_text("evil\n")
            bl = make_baseline(td, encrypt_key="k")
            self.assertIsNone(load_baseline_text(bl, "secret.sh"))


if __name__ == "__main__":
    unittest.main()
