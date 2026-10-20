#!/usr/bin/env python3
"""Étend le trainset V3 à partir de fichiers Python locaux (stdlib + site-packages).

But : avoir « quelques centaines » de fichiers normaux pour stabiliser
l'autoencodeur (au lieu des 6 fichiers de `tests/fixtures/benign/`).

Ce script n'installe RIEN et n'accède PAS au réseau : il échantillonne
le Python disponible sur la machine de l'utilisateur. La sélection est
filtrée par taille et dédupliquée par contenu (SHA-256).

Usage :
  python3 tools/expand_trainset.py --limit 250 --out tests/fixtures/benign_large

Pour entraîner ensuite le nouveau modèle :
  python3 -m sentinel train tests/fixtures/benign_large --out model_large.json \\
    --epochs 200 --lr 0.005
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

# Sources par défaut : la stdlib Python 3.x accessible.
# On évite /Library/Frameworks/Python.framework (qui n'existe pas ici) et
# on prend la lib de Xcode CLT + le repo pip wheels.
DEFAULT_SOURCES = [
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages",
]


def is_probably_benign(path: Path) -> bool:
    """Filtre grossier : pas de __pycache__, pas un fichier de test,
    pas un fichier trop petit ou trop gros, extension .py."""
    if not path.suffix == ".py":
        return False
    if any(p == "__pycache__" or p.startswith("test_") or p == "tests" for p in path.parts):
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size < 200 or size > 8_000:
        return False
    return True


def collect_files(sources: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in sources:
        root = Path(root)
        if not root.is_dir():
            continue
        for p in root.rglob("*.py"):
            if is_probably_benign(p):
                out.append(p)
    return out


def dedupe_by_content(files: list[Path]) -> list[Path]:
    """Garde un fichier par SHA-256. Évite les doublons wheels / stubs."""
    seen: set[str] = set()
    out: list[Path] = []
    for p in files:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        h = hashlib.sha256(data).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append(p)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--sources",
        nargs="+",
        type=Path,
        default=DEFAULT_SOURCES,
        help="dossiers sources à échantillonner",
    )
    p.add_argument(
        "--limit", type=int, default=250, help="nombre maximum de fichiers à copier (défaut 250)"
    )
    p.add_argument("--out", type=Path, required=True, help="dossier de sortie (sera créé)")
    args = p.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)

    print(f"Sources : {args.sources}", file=sys.stderr)
    raw = collect_files(args.sources)
    print(f"Bruts : {len(raw)} fichiers", file=sys.stderr)
    dedup = dedupe_by_content(raw)
    print(f"Après déduplication : {len(dedup)}", file=sys.stderr)

    # Trie pour la reproductibilité puis tronque.
    dedup.sort()
    pick = dedup[: args.limit]

    n_copied = 0
    for i, src in enumerate(pick, 1):
        # Préfixe par un index pour garantir l'unicité.
        dst = args.out / f"{i:04d}_{src.name}"
        if dst.exists():
            continue
        try:
            dst.write_bytes(src.read_bytes())
        except OSError as exc:
            print(f"  skip {src}: {exc}", file=sys.stderr)
            continue
        n_copied += 1

    print(f"Copiés : {n_copied} → {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
