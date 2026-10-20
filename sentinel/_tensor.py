"""Module utilitaire — opération sur des vecteurs et matrices en Python pur.

Pas de dépendance externe. C'est le « Tensor lite » de Sentinel : juste de quoi
faire un autoencodeur de 8 features. Pas optimisé — la cible est la clarté,
pas la performance (l'entraînement se fait sur quelques dizaines à quelques
centaines de fichiers).
"""

from __future__ import annotations

import math
import random

# --- Activations ----------------------------------------------------------


def relu(x: float) -> float:
    return x if x > 0 else 0.0


def relu_deriv(x: float) -> float:
    return 1.0 if x > 0 else 0.0


def tanh(x: float) -> float:
    # Stable pour les grandes valeurs.
    if x > 20:
        return 1.0
    if x < -20:
        return -1.0
    e = math.exp(-2 * x)
    return (1 - e) / (1 + e)


def tanh_deriv(y: float) -> float:
    # Dérivée de tanh appliquée à la sortie y déjà calculée.
    return 1.0 - y * y


# --- Vecteurs / matrices --------------------------------------------------


Vec = list[float]
Mat = list[list[float]]


def zeros(n: int) -> Vec:
    return [0.0] * n


def zeros_mat(rows: int, cols: int) -> Mat:
    return [[0.0] * cols for _ in range(rows)]


def rand_mat(rows: int, cols: int, scale: float = 0.1, rng: random.Random | None = None) -> Mat:
    rng = rng or random.Random()
    # He / Xavier-lite : scale = sqrt(2/fan_in) — adapté à ReLU.
    s = scale / math.sqrt(max(1.0, cols))
    return [[rng.uniform(-s, s) for _ in range(cols)] for _ in range(rows)]


def mat_vec(M: Mat, v: Vec) -> Vec:
    """Produit matrice × vecteur."""
    out = [0.0] * len(M)
    for i, row in enumerate(M):
        acc = 0.0
        for j, x in enumerate(v):
            acc += row[j] * x
        out[i] = acc
    return out


def add_vec(a: Vec, b: Vec) -> Vec:
    return [x + y for x, y in zip(a, b)]


def sub_vec(a: Vec, b: Vec) -> Vec:
    return [x - y for x, y in zip(a, b)]


def scale_vec(a: Vec, s: float) -> Vec:
    return [x * s for x in a]


def hadamard(a: Vec, b: Vec) -> Vec:
    return [x * y for x, y in zip(a, b)]


def mean_sq(a: Vec, b: Vec) -> float:
    """MSE entre deux vecteurs (même taille)."""
    if not a:
        return 0.0
    s = 0.0
    for x, y in zip(a, b):
        d = x - y
        s += d * d
    return s / len(a)


def shape(M: Mat) -> tuple[int, int]:
    return len(M), len(M[0]) if M else 0
