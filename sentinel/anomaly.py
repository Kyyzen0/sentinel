"""Score d'anomalie par fichier.

Deux backends :

V2 — `score_heuristic` (zéro dépendance, stdlib uniquement)
    Combine quatre features par fichier en un score 0..100 :
      - entropie de Shannon (8 = max, 4 ≈ texte anglais)
      - longueur max d'une ligne (normalisée par 800 caractères)
      - ratio de caractères non-imprimables (0..1)
      - ratio de « métacaractères shell » `|`, `&`, `;`, `` ` ``, `\\` (0..1)
    Pondération : 50 % entropie, 30 % longueur de ligne, 10 % non-imprimables,
    10 % métacaractères. Cap à [0, 100].

V3 — `score_autoencoder` (autoencodeur en Python pur, voir `sentinel/neural.py`)
    Apprend à reconstruire le vecteur de features des fichiers « normaux ».
    Le score d'anomalie est l'erreur quadratique moyenne de reconstruction,
    normalisée en 0..100.
"""

from __future__ import annotations

import json
import math
import sys
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from .files import is_ignored, read_text_safely
from .models import AnomalyScore

# Caractères « métacaractères shell » retenus. Volontairement minimal pour
# rester générique ; sans --neural, c'est un signal et non une vérité.
_SHELL_METACHARS = "|&;`\\$<>(){}"


def _shannon_entropy(data: str) -> float:
    """Entropie de Shannon (base 2) en bits par caractère.

    P2-4 : `collections.Counter` (implémenté en C) plutôt qu'un dict
    Python manuel — sur 200 000 caractères par fichier, l'écart est
    significatif.
    """
    if not data:
        return 0.0
    from collections import Counter

    n = len(data)
    h = 0.0
    for c in Counter(data).values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _file_features(text: str) -> tuple[float, int, float, float, float]:
    """Retourne (entropy, max_line_len, nonprintable_ratio, shell_metachar_ratio, avg_line_len)."""
    if not text:
        return 0.0, 0, 0.0, 0.0, 0.0
    lines = text.splitlines() or [""]
    max_line_len = max(len(line) for line in lines)
    avg_line_len = sum(len(line) for line in lines) / len(lines)

    # Le coût de re-compter pour 1M de caractères serait prohibitif ; on
    # s'arrête après MAX_BYTES caractères.
    MAX_BYTES = 200_000
    sample = text[:MAX_BYTES] if len(text) > MAX_BYTES else text

    nonprintable = 0
    shellmetas = 0
    n = len(sample)
    for ch in sample:
        if ord(ch) < 0x20 and ch not in ("\t", "\n", "\r"):
            nonprintable += 1
        if ch in _SHELL_METACHARS:
            shellmetas += 1
    return (
        _shannon_entropy(sample),
        max_line_len,
        nonprintable / max(1, n),
        shellmetas / max(1, n),
        avg_line_len,
    )


def _score_from_features(
    entropy: float,
    max_line_len: int,
    nonprintable_ratio: float,
    shell_metachar_ratio: float,
) -> float:
    norm_entropy = min(1.0, max(0.0, entropy) / 8.0)
    norm_line = min(1.0, max_line_len / 800.0)
    raw = (
        0.50 * norm_entropy
        + 0.30 * norm_line
        + 0.10 * nonprintable_ratio
        + 0.10 * shell_metachar_ratio
    )
    return max(0.0, min(100.0, 100.0 * raw))


def _relpath(path: Path, root: Path | None) -> str:
    """Chemin POSIX relatif à la racine scannée, sinon le chemin tel quel."""
    if root is not None:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def score_heuristic(
    files: Iterable[Path],
    root: Path | None = None,
    text_cache: dict[Path, str | None] | None = None,
) -> list[AnomalyScore]:
    """Score d'anomalie heuristique (V2).

    P2-1 : si `text_cache` est fourni, on l'utilise pour éviter de
    re-lire le fichier (le scanner passe le cache alimenté par la rule
    loop). Les fichiers absents du cache (binary, illisible) sont lus
    une seule fois ici.
    """
    out: list[AnomalyScore] = []
    for path in files:
        if not path.is_file() or is_ignored(path):
            continue
        if text_cache is not None and path in text_cache:
            text = text_cache[path]
        else:
            text = read_text_safely(path)
            if text_cache is not None:
                text_cache[path] = text
        if text is None:
            continue
        entropy, max_line_len, noprint, shellmeta, avg_line = _file_features(text)
        score = _score_from_features(entropy, max_line_len, noprint, shellmeta)
        rel = _relpath(path, root)
        out.append(
            AnomalyScore(
                path=rel,
                score=score,
                entropy=entropy,
                max_line_len=max_line_len,
                nonprintable_ratio=noprint,
                shell_metachar_ratio=shellmeta,
                avg_line_len=avg_line,
                method="heuristic",
            )
        )
    return out


def _load_scorer(model_path: Path | None):
    """Charge un modèle, ou None si absent / illisible (repli heuristique)."""
    from .neural import AutoencoderScorer

    if model_path is None:
        return None
    if not model_path.is_file():
        print(
            f"Modèle introuvable ({model_path}), repli sur l'heuristique.",
            file=sys.stderr,
        )
        return None
    try:
        return AutoencoderScorer.load(model_path)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        print(
            f"Modèle illisible ({model_path}), repli sur l'heuristique.",
            file=sys.stderr,
        )
        return None


def score_autoencoder(
    files: Iterable[Path],
    model_path: Path | None = None,
    root: Path | None = None,
) -> list[AnomalyScore]:
    """V3 : utilise un autoencodeur neuronal. Voir sentinel/neural.py."""
    scorer = _load_scorer(model_path)
    if scorer is None:
        scores = score_heuristic(files, root=root)
        return [replace(s, method="autoencoder:untrained") for s in scores]
    return scorer.score_files(list(files), root=root)
