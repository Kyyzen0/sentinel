"""V3 — autoencodeur neuronal pour score d'anomalie (Python pur, stdlib only).

But : apprendre, sur un corpus de fichiers « normaux », à reconstruire un
vecteur de 8 features statistiques par fichier. Sur des fichiers anormaux
la reconstruction sera mauvaise — l'erreur quadratique moyenne devient le
score d'anomalie (0..100).

Architecture : 8 → 6 → 4 → 6 → 8
- Encoder : ReLU
- Bottleneck : Tanh (sortie ∈ [-1, 1])
- Decoder : ReLU
- Sortie : identité (linéaire)

Optimiseur : Adam (β1=0.9, β2=0.999, ε=1e-8) — léger surcoût en lignes
mais convergence rapide sur petits jeux.

Sans dépendance externe : juste `random`, `math`, et notre mini-tensor.
"""

from __future__ import annotations

import json
import math
import random
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ._tensor import (
    Mat,
    Vec,
    add_vec,
    mat_vec,
    mean_sq,
    rand_mat,
    relu,
    relu_deriv,
    scale_vec,
    sub_vec,
    tanh,
    tanh_deriv,
    zeros,
    zeros_mat,
)
from .anomaly import _file_features, _relpath
from .files import is_ignored, read_text_safely
from .models import AnomalyScore

# --- Extraction de features (16 → 8) -------------------------------------


N_FEATURES = 8


def _features_for_text(text: str) -> Vec:
    """Calcule le vecteur de 8 features. Toutes dans [0, 1] ou presque.

    On distingue :
      0. log10(taille)  — 0..1  (texte ≈ 1kB → ~3, soit 3/6)
      1. entropie de Shannon / 8  — 0..1
      2. max_line_len / 500  — 0..quelques unités (cap 1)
      3. avg_line_len / 100  — 0..quelques unités
      4. nonprintable_ratio  — 0..1
      5. shell_metachar_ratio  — 0..1
      6. digit_ratio  — 0..1 (combien de chiffres)
      7. uppercase_ratio  — 0..1 (combien de majuscules ASCII)
    """
    if not text:
        return [0.0] * N_FEATURES
    entropy, max_line_len, noprint, shellmeta, avg_line_len = _file_features(text)
    size = len(text)
    log_size = math.log10(max(1, size))
    digits = sum(1 for c in text if c.isdigit())
    upper = sum(1 for c in text if "A" <= c <= "Z")
    n = len(text)
    return [
        min(1.0, log_size / 6.0),
        min(1.0, max(0.0, entropy) / 8.0),
        min(1.0, max_line_len / 500.0),
        min(1.0, avg_line_len / 100.0),
        min(1.0, noprint),
        min(1.0, shellmeta),
        min(1.0, digits / max(1, n)),
        min(1.0, upper / max(1, n)),
    ]


# --- Modèle --------------------------------------------------------------


@dataclass
class _AEWeights:
    W1: Mat  # 6 × 8
    b1: Vec  # 6
    W2: Mat  # 4 × 6
    b2: Vec  # 4
    W3: Mat  # 6 × 4
    b3: Vec  # 6
    W4: Mat  # 8 × 6
    b4: Vec  # 8

    def to_dict(self) -> dict:
        return {
            "W1": self.W1,
            "b1": self.b1,
            "W2": self.W2,
            "b2": self.b2,
            "W3": self.W3,
            "b3": self.b3,
            "W4": self.W4,
            "b4": self.b4,
        }

    @classmethod
    def from_dict(cls, d: dict) -> _AEWeights:
        return cls(
            W1=d["W1"],
            b1=d["b1"],
            W2=d["W2"],
            b2=d["b2"],
            W3=d["W3"],
            b3=d["b3"],
            W4=d["W4"],
            b4=d["b4"],
        )


@dataclass
class _AdamState:
    mW1: Mat
    vW1: Mat
    mW2: Mat
    vW2: Mat
    mW3: Mat
    vW3: Mat
    mW4: Mat
    vW4: Mat
    mb1: Vec
    vb1: Vec
    mb2: Vec
    vb2: Vec
    mb3: Vec
    vb3: Vec
    mb4: Vec
    vb4: Vec
    t: int = 0


class Autoencoder:
    """Autoencodeur 8 → 6 → 4 → 6 → 8, activations ReLU/Tanh/ident."""

    def __init__(self, rng: random.Random | None = None):
        self.rng = rng or random.Random(0xC0FFEE)
        self.W = _AEWeights(
            W1=rand_mat(6, 8, scale=1.0, rng=self.rng),
            b1=zeros(6),
            W2=rand_mat(4, 6, scale=1.0, rng=self.rng),
            b2=zeros(4),
            W3=rand_mat(6, 4, scale=1.0, rng=self.rng),
            b3=zeros(6),
            W4=rand_mat(8, 6, scale=1.0, rng=self.rng),
            b4=zeros(8),
        )
        self.adam = _AdamState(
            mW1=zeros_mat(6, 8),
            vW1=zeros_mat(6, 8),
            mW2=zeros_mat(4, 6),
            vW2=zeros_mat(4, 6),
            mW3=zeros_mat(6, 4),
            vW3=zeros_mat(6, 4),
            mW4=zeros_mat(8, 6),
            vW4=zeros_mat(8, 6),
            mb1=zeros(6),
            vb1=zeros(6),
            mb2=zeros(4),
            vb2=zeros(4),
            mb3=zeros(6),
            vb3=zeros(6),
            mb4=zeros(8),
            vb4=zeros(8),
        )

    # --- Forward + stockage pour backprop -----------------------------

    def forward(self, x: Vec) -> tuple[Vec, tuple]:
        """Retourne (x_hat, cache) où cache contient les activations/z pour BP."""
        z1_pre = add_vec(mat_vec(self.W.W1, x), self.W.b1)
        h1 = [relu(v) for v in z1_pre]
        z2_pre = add_vec(mat_vec(self.W.W2, h1), self.W.b2)
        h2 = [tanh(v) for v in z2_pre]
        z3_pre = add_vec(mat_vec(self.W.W3, h2), self.W.b3)
        h3 = [relu(v) for v in z3_pre]
        z4_pre = add_vec(mat_vec(self.W.W4, h3), self.W.b4)
        # Sortie linéaire (identité) — pas d'activation finale.
        x_hat = list(z4_pre)
        cache = (x, z1_pre, h1, z2_pre, h2, z3_pre, h3, z4_pre, x_hat)
        return x_hat, cache

    # --- Backprop : gradient MSE / N ---------------------------------

    def backward(self, cache: tuple) -> _AEWeights:
        x, z1, h1, z2, h2, z3, h3, z4, x_hat = cache
        N = len(x)
        # dL/dx_hat (MSE = mean((x-x_hat)^2)) → 2/N * (x_hat - x)
        d_xhat = scale_vec(sub_vec(x_hat, x), 2.0 / N)

        # Couche 4 : linéaire
        d_z4 = d_xhat  # pas d'activation (identité)
        d_W4 = _outer(d_z4, h3)
        d_b4 = list(d_z4)
        d_h3 = _matT_vec(self.W.W4, d_z4)

        # Couche 3 : ReLU → dérivé sur z3
        d_z3 = [d_h3[i] * relu_deriv(z3[i]) for i in range(len(z3))]
        d_W3 = _outer(d_z3, h2)
        d_b3 = list(d_z3)
        d_h2 = _matT_vec(self.W.W3, d_z3)

        # Couche 2 : tanh → dérivé sur h2 (la sortie tanh)
        d_z2 = [d_h2[i] * tanh_deriv(h2[i]) for i in range(len(h2))]
        d_W2 = _outer(d_z2, h1)
        d_b2 = list(d_z2)
        d_h1 = _matT_vec(self.W.W2, d_z2)

        # Couche 1 : ReLU
        d_z1 = [d_h1[i] * relu_deriv(z1[i]) for i in range(len(z1))]
        d_W1 = _outer(d_z1, x)
        d_b1 = list(d_z1)

        g = _AEWeights(d_W1, d_b1, d_W2, d_b2, d_W3, d_b3, d_W4, d_b4)
        return g

    # --- Adam -------------------------------------------------------

    def adam_step(
        self,
        g: _AEWeights,
        lr: float = 1e-3,
        beta1: float = 0.9,
        beta2: float = 0.999,
        eps: float = 1e-8,
    ) -> None:
        s = self.adam
        s.t += 1
        t = s.t
        _adam_update(self.W.W1, g.W1, s.mW1, s.vW1, t, lr, beta1, beta2, eps)
        _adam_update(self.W.W2, g.W2, s.mW2, s.vW2, t, lr, beta1, beta2, eps)
        _adam_update(self.W.W3, g.W3, s.mW3, s.vW3, t, lr, beta1, beta2, eps)
        _adam_update(self.W.W4, g.W4, s.mW4, s.vW4, t, lr, beta1, beta2, eps)
        _adam_update_vec(self.W.b1, g.b1, s.mb1, s.vb1, t, lr, beta1, beta2, eps)
        _adam_update_vec(self.W.b2, g.b2, s.mb2, s.vb2, t, lr, beta1, beta2, eps)
        _adam_update_vec(self.W.b3, g.b3, s.mb3, s.vb3, t, lr, beta1, beta2, eps)
        _adam_update_vec(self.W.b4, g.b4, s.mb4, s.vb4, t, lr, beta1, beta2, eps)


def _outer(a: Vec, b: Vec) -> Mat:
    return [[a[i] * b[j] for j in range(len(b))] for i in range(len(a))]


def _matT_vec(M: Mat, v: Vec) -> Vec:
    """Produit matrice transposée × vecteur."""
    cols = len(M[0]) if M else 0
    out = [0.0] * cols
    for i, row in enumerate(M):
        for j, x in enumerate(row):
            out[j] += x * v[i]
    return out


def _adam_update(
    W: Mat, dW: Mat, mW: Mat, vW: Mat, t: int, lr: float, beta1: float, beta2: float, eps: float
) -> None:
    for i in range(len(W)):
        for j in range(len(W[0])):
            g = dW[i][j]
            mW[i][j] = beta1 * mW[i][j] + (1 - beta1) * g
            vW[i][j] = beta2 * vW[i][j] + (1 - beta2) * g * g
            m_hat = mW[i][j] / (1 - beta1**t)
            v_hat = vW[i][j] / (1 - beta2**t)
            W[i][j] -= lr * m_hat / (math.sqrt(v_hat) + eps)


def _adam_update_vec(
    b: Vec, db: Vec, mb: Vec, vb: Vec, t: int, lr: float, beta1: float, beta2: float, eps: float
) -> None:
    for i in range(len(b)):
        g = db[i]
        mb[i] = beta1 * mb[i] + (1 - beta1) * g
        vb[i] = beta2 * vb[i] + (1 - beta2) * g * g
        m_hat = mb[i] / (1 - beta1**t)
        v_hat = vb[i] / (1 - beta2**t)
        b[i] -= lr * m_hat / (math.sqrt(v_hat) + eps)


# --- Entrraînement et scoring ---------------------------------------------


def _training_path_allowed(path: Path, *, follow_links: bool, root: Path | None) -> bool:
    """Même politique que le scan.

    Symlink ignoré par défaut. Avec ``follow_links``, la cible résolue
    doit rester sous ``root`` (ou sous le parent du lien si ``root``
    n'est pas connu). On ne suit pas un lien vers l'extérieur du corpus :
    ``read_text_safely`` n'est pas appelé.
    """
    from .platform import is_link

    if is_link(path):
        if not follow_links:
            return False
        try:
            target = path.resolve()
        except OSError:
            return False
        anchor = root if root is not None else path.parent
        try:
            target.relative_to(anchor.resolve())
        except ValueError:
            return False
    try:
        return path.is_file()
    except OSError:
        return False


class AutoencoderScorer:
    """Façade publique : entraînement, persistance, scoring."""

    def __init__(self, model: Autoencoder | None = None, max_score: float = 1.0):
        self.model = model or Autoencoder()
        self.max_score = max_score  # valeur de mse × 100 = score 100 (référence)
        self.n_samples = 0

    # --- Train ------------------------------------------------------

    def train(
        self,
        training_files: Iterable[Path],
        epochs: int = 60,
        lr: float = 1e-3,
        verbose: bool = False,
        *,
        follow_links: bool = False,
        root: Path | None = None,
    ) -> list[float]:
        xs: list[Vec] = []
        for p in training_files:
            if not _training_path_allowed(p, follow_links=follow_links, root=root):
                continue
            text = read_text_safely(p)
            if text is None:
                continue
            xs.append(_features_for_text(text))
        self.n_samples = len(xs)
        if not xs:
            return []

        losses: list[float] = []
        for epoch in range(1, epochs + 1):
            self.model.rng.shuffle(xs)
            total = 0.0
            for x in xs:
                x_hat, cache = self.model.forward(x)
                loss = mean_sq(x, x_hat)
                total += loss
                g = self.model.backward(cache)
                self.model.adam_step(g, lr=lr)
            avg = total / max(1, len(xs))
            losses.append(avg)
            if verbose and (epoch % 10 == 0 or epoch == 1):
                print(f"  epoch {epoch:>3}  loss={avg:.6f}")

        # Calibrage du score : on passe une dernière passe sur le trainset
        # pour mesurer la MAUVAISE reconstruction maximale parmi les fichiers
        # « normaux ». max_score = 5× cette borne — un outlier typique aura
        # une perte au moins 5× supérieure et saturera le score.
        worst_train = 0.0
        for x in xs:
            x_hat, _ = self.model.forward(x)
            worst_train = max(worst_train, mean_sq(x, x_hat))
        if verbose:
            print(f"  pire perte trainset final = {worst_train:.6f}")
        self.max_score = max(1e-5, worst_train * 5.0)
        return losses

    # --- Score ------------------------------------------------------

    def score(self, text: str) -> tuple[float, float]:
        x = _features_for_text(text)
        x_hat, _ = self.model.forward(x)
        mse = mean_sq(x, x_hat)
        score = max(0.0, min(100.0, 100.0 * mse / max(1e-12, self.max_score)))
        return score, mse

    def score_files(self, files: list[Path], root: Path | None = None) -> list[AnomalyScore]:
        out: list[AnomalyScore] = []
        for p in files:
            if not p.is_file() or is_ignored(p):
                continue
            text = read_text_safely(p)
            if text is None:
                continue
            score, _ = self.score(text)
            entropy, max_line_len, noprint, shellmeta, avg_line = _file_features(text)
            out.append(
                AnomalyScore(
                    path=_relpath(p, root),
                    score=score,
                    entropy=entropy,
                    max_line_len=max_line_len,
                    nonprintable_ratio=noprint,
                    shell_metachar_ratio=shellmeta,
                    avg_line_len=avg_line,
                    method="autoencoder",
                )
            )
        return out

    # --- Persistance ------------------------------------------------

    def save(self, path: Path) -> None:
        payload = {
            "version": 1,
            "max_score": self.max_score,
            "weights": self.model.W.to_dict(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))

    @classmethod
    def load(cls, path: Path) -> AutoencoderScorer:
        data = json.loads(path.read_text())
        w = _AEWeights.from_dict(data["weights"])
        ae = Autoencoder()
        ae.W = w
        return cls(model=ae, max_score=float(data.get("max_score", 1.0)))
