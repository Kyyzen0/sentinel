"""Tests P0-2 : load_baseline_text() doit retourner None (et pas comparer
au contenu actuel) quand la baseline ne contient pas le contenu historique.

Le bug : l'ancien code retombait sur une lecture disque, qui voit l'état
ACTUEL du fichier (pas celui au moment de la baseline). Une comparaison
« baseline == current » ne détectait alors aucun ajout.

Le fix : retourner None si le contenu n'est pas embarqué, et tracer les
fichiers concernés (via un log collectif au niveau du scan) pour que
l'utilisateur sache régénérer sa baseline.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.integrity import (
    _CONTENT_MAX,
    load_baseline_text,
)


class TestLoadBaselineTextPrefersEmbedded(unittest.TestCase):
    def test_returns_embedded_content_when_present(self) -> None:
        baseline = {
            "version": 2,
            "root": "/does/not/matter",
            "content_max_bytes": _CONTENT_MAX,
            "entries": [
                {"path": "a.txt", "sha256": "x", "size": 5, "mode": 0o644, "content": "hello"},
            ],
        }
        self.assertEqual(load_baseline_text(baseline, "a.txt"), "hello")

    def test_returns_none_when_content_field_missing_v1(self) -> None:
        """Baseline V1 : pas de champ `content` du tout. Retourner None,
        PAS lire le disque (sinon comparaison fichier-vs-lui-même)."""
        baseline = {
            "version": 1,
            "root": "/tmp/somewhere",
            "entries": [
                # V1 : pas de `content`.
                {"path": "a.txt", "sha256": "abc", "size": 5, "mode": 0o644},
            ],
        }
        # Le dossier référencé par `root` n'existe pas : on ne doit pas
        # y accéder du tout.
        result = load_baseline_text(baseline, "a.txt")
        self.assertIsNone(result)

    def test_returns_none_when_content_field_is_none_v2_large_file(self) -> None:
        """Baseline V2 avec un fichier > _CONTENT_MAX : `content` est None.
        On ne tombe pas sur le disque."""
        baseline = {
            "version": 2,
            "root": "/var/folders/somewhere",
            "content_max_bytes": _CONTENT_MAX,
            "entries": [
                {
                    "path": "big.log",
                    "sha256": "abc",
                    "size": 999_999,
                    "mode": 0o644,
                    "content": None,
                },
            ],
        }
        result = load_baseline_text(baseline, "big.log")
        self.assertIsNone(result)

    def test_returns_none_for_unknown_path(self) -> None:
        baseline = {"version": 2, "entries": []}
        self.assertIsNone(load_baseline_text(baseline, "missing.txt"))

    def test_does_not_read_disk_even_if_root_exists(self) -> None:
        """Le cas du bug : si `root` pointe vers un dossier DISQUE avec
        un fichier MODIFIÉ par rapport à la baseline, load_baseline_text
        NE DOIT PAS lire le contenu actuel — sinon SIG-0019 compare le
        fichier à lui-même et rate l'ajout."""
        with __import__("tempfile").TemporaryDirectory() as td:
            root = Path(td)
            ak = root / "authorized_keys"
            ak.write_text("ssh-ed25519 AAAA new@evil\n")  # état actuel, post-ajout

            baseline = {
                "version": 1,
                "root": str(root),
                "entries": [
                    # La baseline V1 a été prise AVANT l'ajout.
                    {"path": "authorized_keys", "sha256": "old_sha", "size": 10, "mode": 0o644},
                ],
            }
            result = load_baseline_text(baseline, "authorized_keys")
            # Doit retourner None, pas le contenu actuel.
            self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
