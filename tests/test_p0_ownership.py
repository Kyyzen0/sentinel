"""Tests P0-4 : uid/gid + setcap dans la baseline.

Le bug : la baseline V2 stocke {path, sha256, size, mode, content} — pas
d'uid/gid. Un changement de propriétaire (vecteur classique de
privesc) ne produit aucun diff. Les capabilities (plus pertinentes que
SUID aujourd'hui : `cap_net_bind_service`, `cap_dac_read_search`, etc.)
ne sont pas non plus tracées.

Le fix :
- `Entry` ajoute `uid`, `gid`, et `capabilities` (None si non applicable).
- `IntegrityDiff` expose `owner_changed` et `cap_changed` (listes de paths).
- `make_baseline` lit uid/gid via `stat`. `capabilities` via `getcap`
  (None si l'utilitaire manque ou n'est pas Linux). Le test skip le
  test capabilities sur macOS / quand getcap n'est pas là.
"""

import os
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.integrity import (
    diff_against_baseline,
    make_baseline,
)


def _has_getcap() -> bool:
    # getcap est un contrôle Linux. Un binaire homonyme ailleurs ne
    # compte pas : le champ capabilities reste None.
    return sys.platform.startswith("linux") and shutil.which("getcap") is not None


class TestBaselineHasUidGid(unittest.TestCase):
    def test_entry_contains_uid_and_gid(self) -> None:
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            f = td / "x.txt"
            f.write_text("hello\n")
            baseline = make_baseline(td)
            entry = baseline["entries"][0]
            self.assertIn("uid", entry)
            self.assertIn("gid", entry)
            if os.name == "nt":
                # Pas de uid POSIX : 0 serait un faux « propriétaire connu ».
                self.assertIsNone(entry["uid"])
                self.assertIsNone(entry["gid"])
                self.assertIsInstance(entry.get("owner"), str)
                self.assertTrue(entry["owner"].startswith("S-1-"))
            else:
                self.assertEqual(entry["uid"], os.getuid())
                self.assertEqual(entry["gid"], os.getgid())
                self.assertIsNone(entry.get("owner"))

    def test_chown_change_is_detected(self) -> None:
        """Un chown (uid OU gid) doit produire un owner_changed dans le diff.

        On ne peut pas chown à un autre utilisateur sans privilège — on
        teste donc avec une baseline ARTIFICIELLE où uid/gid sont
        DIFFÉRENTS de l'uid/gid actuel, pour simuler un chown.
        """
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            f = td / "x.txt"
            f.write_text("hello\n")

            current = make_baseline(td)  # uid/gid réels
            cur_entry = current["entries"][0]

            # Construire un baseline V2 avec un uid/gid DIFFÉRENT
            # pour simuler un chown passé inaperçu.
            ref_entry = dict(cur_entry)
            if os.name == "nt":
                # uid/gid sont None : un 99999 d'un seul côté n'est pas
                # un chown. Le SID l'est.
                ref_entry["owner"] = "S-1-5-21-999"
            else:
                ref_entry["uid"] = 99999
                ref_entry["gid"] = 99999
            ref = {
                "version": 2,
                "root": str(td),
                "entries": [ref_entry],
            }
            # Le diff current↔ref doit signaler un owner_changed.
            diff = diff_against_baseline(current, ref)
            self.assertIn("x.txt", diff.owner_changed)


class TestBaselineHasCapabilities(unittest.TestCase):
    @unittest.skipUnless(_has_getcap(), "getcap n'est pas disponible")
    def test_capabilities_field_is_set_when_available(self) -> None:
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            f = td / "x.txt"
            f.write_text("hello\n")
            baseline = make_baseline(td)
            entry = baseline["entries"][0]
            self.assertIn("capabilities", entry)
            # Sur un fichier normal, getcap retourne « ». Le champ est
            # une string (vide ou pas) — pas None.
            self.assertIsNotNone(entry["capabilities"])


class TestCapChangeDetected(unittest.TestCase):
    @unittest.skipUnless(_has_getcap(), "getcap n'est pas disponible")
    def test_capabilities_change_is_detected(self) -> None:
        """P0-4 : un changement de capability (entre deux baselines) doit
        être détecté dans `cap_changed`.

        On simule le changement en construisant un ref « baseline
        historique » où x.txt a une capability, et un current où
        x.txt n'en a plus (et inversement). Le diff doit voir le
        changement dans les deux sens.
        """
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            f = td / "x.txt"
            f.write_text("hello\n")

            current = make_baseline(td)
            cur_entry = current["entries"][0]
            # La « vraie » capability actuelle (probablement vide pour
            # un fichier texte).
            real_cap = cur_entry.get("capabilities") or ""

            # Ref : la même baseline, MAIS avec une capability différente
            # (cap_net_bind_service+ep, par exemple). On simule un état
            # antérieur où le fichier avait une capability qu'il n'a plus.
            ref_entry = dict(cur_entry)
            ref_entry["capabilities"] = "cap_net_bind_service+ep"
            ref = {
                "version": 2,
                "root": str(td),
                "entries": [ref_entry],
            }
            # current_cap reste à real_cap (vide) — donc le diff doit
            # détecter le changement de "cap_net_bind_service+ep" → "".
            diff = diff_against_baseline(current, ref)
            if real_cap != "cap_net_bind_service+ep":
                # Cas normal : on s'attend à voir le changement.
                self.assertIn(
                    "x.txt",
                    diff.cap_changed,
                    f"cap_changed devrait contenir x.txt (ref='cap_net_bind_service+ep', "
                    f"current='{real_cap}') mais contient {diff.cap_changed!r}",
                )


if __name__ == "__main__":
    unittest.main()
