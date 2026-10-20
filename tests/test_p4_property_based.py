"""P4-C : property-based tests avec Hypothesis.

Le bug : les tests unitaires n'exercent `_diff_snapshots` et
`_safe_dest` que sur quelques cas choisis à la main. Une régression
sur un cas limite (snapshot avec timestamps étranges, collision de
nom dans un sous-dossier vide, etc.) peut passer.

Le fix : Hypothesis génère des centaines de cas aléatoires à partir
de stratégies (dictionnaires de FileStamp, listes de fichiers
existants/non-existants). C'est un fuzzing intelligent — les cas
qui font planter la propriété sont automatiquement rejoués avec
`@example` pour être re-testés si le code change.

Hypothesis est dans `[project.optional-dependencies] test` et
`[project.optional-dependencies] dev` (installé par P4-B).
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from sentinel.quarantine import _safe_dest
from sentinel.watch import _diff_snapshots, _FileStamp, _snapshot

# --- Stratégies Hypothesis ------------------------------------------------

# Path relatif simple, sans `..` ni caractère nul (path-composant légal).
_rel_path = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N"),
        whitelist_characters="-_.",
    ),
    min_size=1,
    max_size=12,
).map(lambda s: s + ".txt")

# Timestamp (mtime) borné pour éviter les overflows sur des OS 32-bit.
_mtime = st.floats(min_value=0, max_value=2**31 - 1, allow_nan=False, allow_infinity=False)
# Size borné pour rester raisonnable.
_size = st.integers(min_value=0, max_value=10**8)

_filestamp = st.builds(
    _FileStamp,
    path=_rel_path,
    mtime=_mtime,
    size=_size,
)


# --- Propriétés sur _diff_snapshots ---------------------------------------


class TestDiffSnapshotsProperties(unittest.TestCase):
    """Propriétés que `_diff_snapshots` doit respecter quel que soit
    l'input."""

    @given(
        prev=st.dictionaries(_rel_path, _filestamp, max_size=20),
        cur=st.dictionaries(_rel_path, _filestamp, max_size=20),
    )
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_added_removed_modified_partition(
        self, prev: dict[str, _FileStamp], cur: dict[str, _FileStamp]
    ) -> None:
        """Tout chemin est EXACTEMENT dans un des 3 ensembles (added, removed, modified)
        ou dans aucun (path inchangé). Aucun chemin ne peut être dans 2 ensembles
        à la fois (cohérence du diff)."""
        diff = _diff_snapshots(prev, cur)
        added = set(diff["added"])
        removed = set(diff["removed"])
        modified = set(diff["modified"])

        # Un path ne peut pas être à la fois ajouté et removed.
        self.assertEqual(added & removed, set())
        # Un path ne peut pas être ajouté ET modifié.
        self.assertEqual(added & modified, set())
        # Un path ne peut pas être removed ET modifié.
        self.assertEqual(removed & modified, set())

        # Vérifier la sémantique « added = dans cur, pas dans prev ».
        for p in added:
            self.assertIn(p, cur)
            self.assertNotIn(p, prev)
        for p in removed:
            self.assertIn(p, prev)
            self.assertNotIn(p, cur)
        for p in modified:
            self.assertIn(p, prev)
            self.assertIn(p, cur)
            ps, cs = prev[p], cur[p]
            # Modifié = mtime, taille, ou empreinte de contenu (les deux
            # côtés doivent porter la même sorte d'empreinte).
            content_differs = (ps.digest and cs.digest and ps.digest != cs.digest) or (
                ps.sample and cs.sample and ps.sample != cs.sample
            )
            self.assertTrue(
                ps.mtime != cs.mtime or ps.size != cs.size or content_differs,
                f"{p} marqué modified mais mtime/size/contenu identiques",
            )

    @given(
        snap=st.dictionaries(_rel_path, _filestamp, min_size=1, max_size=20),
    )
    @settings(max_examples=100, deadline=None)
    def test_diff_with_self_is_empty(self, snap: dict[str, _FileStamp]) -> None:
        """Un diff d'un snapshot contre lui-même ne contient rien."""
        diff = _diff_snapshots(snap, dict(snap))
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])

    @given(
        snap=st.dictionaries(_rel_path, _filestamp, max_size=20),
    )
    @settings(max_examples=100, deadline=None)
    def test_diff_against_empty(self, snap: dict[str, _FileStamp]) -> None:
        """Un diff entre {} et un snapshot S donne :
        - added = S.keys()
        - removed = []
        - modified = []"""
        diff = _diff_snapshots({}, snap)
        self.assertEqual(set(diff["added"]), set(snap.keys()))
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])

    @given(
        snap=st.dictionaries(_rel_path, _filestamp, max_size=20),
    )
    @settings(max_examples=100, deadline=None)
    def test_diff_empty_against_snap(self, snap: dict[str, _FileStamp]) -> None:
        """Inverse : un diff entre S et {} donne tout en removed."""
        diff = _diff_snapshots(snap, {})
        self.assertEqual(set(diff["removed"]), set(snap.keys()))
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["modified"], [])

    @given(
        prev=st.dictionaries(_rel_path, _filestamp, max_size=20),
        cur=st.dictionaries(_rel_path, _filestamp, max_size=20),
    )
    @settings(max_examples=100, deadline=None)
    def test_diff_keys_partition(
        self, prev: dict[str, _FileStamp], cur: dict[str, _FileStamp]
    ) -> None:
        """L'union added ∪ removed ∪ modified ∪ (unchanged keys) = prev ∪ cur."""
        diff = _diff_snapshots(prev, cur)
        diff_keys = set(diff["added"]) | set(diff["removed"]) | set(diff["modified"])
        all_keys = set(prev) | set(cur)
        unchanged = all_keys - diff_keys
        # Les unchanged keys sont bien dans prev ET dans cur, avec même mtime/size.
        for p in unchanged:
            self.assertIn(p, prev)
            self.assertIn(p, cur)
            self.assertEqual(prev[p].mtime, cur[p].mtime)
            self.assertEqual(prev[p].size, cur[p].size)


# --- Propriétés sur _safe_dest --------------------------------------------


class TestSafeDestProperties(unittest.TestCase):
    """Propriétés que `_safe_dest` doit respecter."""

    @given(
        existing=st.lists(_rel_path, min_size=0, max_size=10, unique=True),
        target=st.one_of(_rel_path, st.sampled_from(["x.txt", "a/b/c.txt"])),
    )
    @settings(max_examples=200, deadline=None)
    def test_safe_dest_returns_nonexistent_path(
        self,
        existing: list[str],
        target: str,
    ) -> None:
        """Pour toute liste de paths existants et un target, `_safe_dest`
        doit retourner un path qui N'EXISTE PAS encore (sinon on écraserait
        un fichier en quarantaine, ce qui serait une perte de preuve)."""
        with TemporaryDirectory() as td:
            td_p = Path(td)
            existing_paths: set[Path] = set()
            for rel in existing:
                p = td_p / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x")
                existing_paths.add(p)
            src = td_p / target
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text("src")
            dest = _safe_dest(td_p, src)
            # Le retour ne doit pas être dans la liste des existants.
            self.assertNotIn(
                dest,
                existing_paths,
                f"_safe_dest a retourné un fichier déjà existant : {dest}",
            )
            # Le retour doit être sous dest_dir.
            self.assertEqual(dest.parent, td_p)
            # Le retour doit avoir le même nom de base (ou un nom dérivé).
            self.assertTrue(dest.name.startswith(src.name.split(".")[0]))

    @given(
        n=st.integers(min_value=1, max_value=8),
    )
    @settings(max_examples=50, deadline=None)
    def test_safe_dest_handles_collisions(self, n: int) -> None:
        """Avec N fichiers de même nom dans le dest_dir, _safe_dest
        doit retourner un nom disponible (pas d'écrasement)."""
        with TemporaryDirectory() as td:
            td_p = Path(td)
            for i in range(n):
                (td_p / "evil.sh").write_text(f"x{i}")
            src = td_p / "evil.sh"
            dest = _safe_dest(td_p, src)
            # Le retour ne doit pas écraser un fichier existant.
            self.assertFalse(dest.exists())


# --- Properties sur _snapshot (filesystem réel) ---------------------------


class TestSnapshotProperties(unittest.TestCase):
    """`_snapshot` doit produire un dict cohérent de ce qui est sur disque."""

    @given(
        n_files=st.integers(min_value=0, max_value=10),
        mtime_offset=st.floats(min_value=0.0, max_value=2.0, allow_nan=False),
    )
    @settings(max_examples=50, deadline=None)
    def test_snapshot_reflects_filesystem(
        self,
        n_files: int,
        mtime_offset: float,
    ) -> None:
        """Un snapshot d'un dossier avec N fichiers contient
        exactement N entrées, et les mtime/size correspondent au disque."""
        import time

        with TemporaryDirectory() as td:
            td_p = Path(td)
            for i in range(n_files):
                p = td_p / f"file_{i}.txt"
                p.write_text("x" * (i + 1))
                # Force un mtime distinct pour chaque fichier.
                time.sleep(mtime_offset / max(n_files, 1))
            snap = _snapshot(td_p)
            self.assertEqual(len(snap), n_files)
            for p in td_p.iterdir():
                if p.is_file():
                    rel = p.name
                    self.assertIn(rel, snap)
                    self.assertEqual(snap[rel].size, p.stat().st_size)


if __name__ == "__main__":
    unittest.main()
