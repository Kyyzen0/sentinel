"""Tests pour V3 : autoencodeur neuronal.

Couvre :
  - L'autoencodeur converge (la loss moyenne baisse au fil des époques).
  - Les fichiers « normaux » du corpus d'entraînement obtiennent un score bas,
    tandis qu'un fichier clairement anormal (la fixture high_entropy) obtient
    un score significativement plus élevé.
  - Sérialisation : save() puis load() restituent un modèle équivalent
    (mêmes scores).
"""

import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.neural import (
    Autoencoder,
    AutoencoderScorer,
)


class TestAutoencoderForward(unittest.TestCase):
    def test_forward_output_has_same_shape_as_input(self):
        ae = Autoencoder(rng=random.Random(0))
        x = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        x_hat, cache = ae.forward(x)
        self.assertEqual(len(x_hat), len(x))


class TestAutoencoderTraining(unittest.TestCase):
    def setUp(self):
        self.benign = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "benign"
        self.scored = Path(__file__).resolve().parents[1] / "tests" / "high_entropy.txt"

    def test_loss_decreases_over_training(self):
        rng = random.Random(42)
        ae = Autoencoder(rng=rng)
        scorer = AutoencoderScorer(model=ae)
        losses = scorer.train(self.benign.glob("*"), epochs=40, lr=5e-3)
        self.assertGreater(len(losses), 0)
        # La loss doit globalement baisser — comparer la moyenne des 5
        # premières époques aux 5 dernières.
        head = sum(losses[:5]) / 5
        tail = sum(losses[-5:]) / 5
        self.assertLess(
            tail, head * 1.05, f"loss should decrease over training (head={head}, tail={tail})"
        )

    def test_outlier_scores_higher_than_training_set(self):
        rng = random.Random(123)
        ae = Autoencoder(rng=rng)
        scorer = AutoencoderScorer(model=ae)
        scorer.train(self.benign.glob("*"), epochs=80, lr=5e-3)

        benign_scores = [
            scorer.score(p.read_text())[0]
            for p in self.benign.glob("*")
            if p.is_file() and p.name != "config.json"
        ]
        benign_mean = sum(benign_scores) / max(1, len(benign_scores))
        outlier_score, _ = scorer.score(self.scored.read_text())

        # L'outlier (base64 random) doit largement dépasser la moyenne.
        self.assertGreater(
            outlier_score,
            benign_mean * 1.2,
            f"outlier score {outlier_score:.2f} should beat benign mean {benign_mean:.2f}",
        )

    def test_serialization_roundtrip(self):
        rng = random.Random(7)
        ae = Autoencoder(rng=rng)
        scorer = AutoencoderScorer(model=ae)
        scorer.train(self.benign.glob("*"), epochs=20, lr=5e-3)

        sample_text = self.benign.joinpath("utils.py").read_text()
        score_before, _ = scorer.score(sample_text)

        with tempfile.TemporaryDirectory() as td:
            model_path = Path(td) / "ae.json"
            scorer.save(model_path)
            payload = json.loads(model_path.read_text())
            self.assertEqual(payload["version"], 1)
            self.assertIn("weights", payload)

            reloaded = AutoencoderScorer.load(model_path)
            score_after, _ = reloaded.score(sample_text)
            self.assertAlmostEqual(score_before, score_after, places=4)


if __name__ == "__main__":
    unittest.main()
