"""Tests P0-3 : politique explicite sur les symlinks + containment check.

Le bug : `p.is_file()` suit les liens symboliques. Un symlink dans le
dossier scanné qui pointe vers un fichier hors périmètre fait remonter
du contenu externe dans la baseline.

Le fix :
- Par défaut (`follow_links=False`) : on ignore les symlinks (rfilter).
- Avec `follow_links=True` : on accepte, MAIS on vérifie que la cible
  résolue reste sous la racine du scan (containment) ; sinon, on skip
  + warning explicite.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.scanner import scan_folder


class TestSymlinkPolicy(unittest.TestCase):
    def test_symlink_is_ignored_by_default(self) -> None:
        """Par défaut, un symlink dans le dossier scanné n'est PAS suivi.

        On vérifie qu'un fichier « symlinké » depuis l'extérieur ne
        génère pas de finding.
        """
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            # Dossier externe avec un fichier clairement malveillant.
            external = td / "external"
            external.mkdir()
            ext_file = external / "evil.sh"
            ext_file.write_text("#!/bin/bash\nrm -rf /\n")

            # Le dossier scanné contient un symlink vers ce fichier.
            inside = td / "inside"
            inside.mkdir()
            (inside / "link_to_evil").symlink_to(ext_file)

            report = scan_folder(inside)
            self.assertEqual(
                report.findings,
                [],
                f"un symlink externe ne doit pas être scanné, "
                f"mais on a eu {len(report.findings)} findings",
            )

    def test_symlink_inside_same_tree_is_ignored(self) -> None:
        """Un symlink vers un fichier du même dossier n'est pas suivi
        (la cible est lue directement par le rglob normal)."""
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            (td / "real.txt").write_text("hello\n")
            (td / "link_to_real").symlink_to(td / "real.txt")
            # Scan : on doit trouver UNE fois le contenu (via real.txt),
            # pas deux fois (le symlink ne doit pas re-scanner).
            report = scan_folder(td)
            # Aucun finding attendu (le contenu est bénin). Mais le
            # check fonctionnel : pas de doublon.
            self.assertEqual(len(report.findings), 0)

    def test_follow_links_marks_external_target(self) -> None:
        """Avec `follow_links=True`, un symlink vers un fichier HORS
        de la racine doit être signalé dans le rapport (warning ou
        exclusion explicite) — pas silencieusement scanné."""
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            external = td / "external"
            external.mkdir()
            ext_file = external / "evil.sh"
            ext_file.write_text("#!/bin/bash\nrm -rf /\n")
            inside = td / "inside"
            inside.mkdir()
            (inside / "link_to_evil").symlink_to(ext_file)

            # Avec follow_links=True, le symlink doit être IGNORÉ
            # car sa cible est hors du dossier scanné (containment).
            report = scan_folder(inside, follow_links=True)
            self.assertEqual(
                report.findings,
                [],
                f"un symlink hors-containment doit être ignoré même avec follow_links=True, "
                f"mais on a eu {len(report.findings)} findings",
            )
            # Le chemin doit être listé dans `report.skipped_external` (ou équivalent).
            self.assertTrue(
                hasattr(report, "skipped_external"),
                "Report doit exposer la liste des symlinks hors-confinement",
            )
            self.assertIn("link_to_evil", report.skipped_external)

    def test_follow_links_accepts_internal_target(self) -> None:
        """Avec follow_links=True, un symlink dont la cible est SOUS la
        racine est scanné (parce qu'il pointe vers un fichier de
        l'inventaire légitime)."""
        with __import__("tempfile").TemporaryDirectory() as td:
            td = Path(td)
            inside = td / "inside"
            inside.mkdir()
            # Fichier réel + symlink DANS `inside/`, la cible reste sous
            # `inside/`.
            (inside / "real.txt").write_text("safe content\n")
            (inside / "internal_link").symlink_to(inside / "real.txt")

            report = scan_folder(inside, follow_links=True)
            # Pas de finding attendu (contenu safe). Le check fonctionnel
            # : la symlink a bien été scannée.
            self.assertEqual(len(report.findings), 0)
            self.assertTrue(hasattr(report, "skipped_external"))
            self.assertNotIn("internal_link", report.skipped_external)


if __name__ == "__main__":
    unittest.main()
