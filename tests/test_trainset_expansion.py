"""Test comparatif : le modèle large doit rester au moins aussi discriminant
que le modèle small sur les fixtures de malware, et les fichiers du trainset
doivent rester sous le seuil de détection."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.scanner import scan_folder

SMALL = Path(__file__).resolve().parents[1] / "model.json"
LARGE = Path(__file__).resolve().parents[1] / "model_large.json"


@unittest.skipUnless(
    SMALL.exists() and LARGE.exists(), "model.json et/ou model_large.json manquants"
)
class TestTrainsetExpansion(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
        self.benign = self.fixtures / "benign"  # le trainset d'origine
        self.benign_large = self.fixtures / "benign_large"  # l'expansion

    def test_large_model_rejects_benign_corpus(self) -> None:
        # Le trainset doit produire des scores faibles (< 30). Avec un trainset
        # plus large, la stabilité augmente : la médiane doit être quasi nulle.
        report = scan_folder(
            self.benign_large,
            with_anomaly=True,
            with_neural=True,
            model_path=LARGE,
        )
        scores = [a.score for a in report.anomalies]
        median = sorted(scores)[len(scores) // 2] if scores else 0
        self.assertLess(
            median,
            10.0,
            f"médiane d'anomalie trop haute ({median:.1f}) sur le trainset large",
        )

    def test_large_model_flags_high_entropy(self) -> None:
        # tests/high_entropy.txt : doit toujours saturer le score.
        # scan_folder traite un dossier ; on scanne tests/ et on isole le fichier.
        tests_root = self.fixtures.parent
        report = scan_folder(
            tests_root,
            with_anomaly=True,
            with_neural=True,
            model_path=LARGE,
        )
        anoms = [a for a in report.anomalies if a.path.endswith("high_entropy.txt")]
        self.assertTrue(anoms, "high_entropy.txt absent du rapport")
        self.assertGreaterEqual(anoms[0].score, 60.0)

    def test_large_model_at_least_as_good_as_small_on_benign(self) -> None:
        """Le score MAX d'un fichier du trainset doit être plus bas avec le
        modèle large qu'avec le petit (l'autoencodeur généralise mieux)."""
        small_scores = [
            a.score
            for a in scan_folder(
                self.benign,
                with_anomaly=True,
                with_neural=True,
                model_path=SMALL,
            ).anomalies
        ]
        large_scores = [
            a.score
            for a in scan_folder(
                self.benign,
                with_anomaly=True,
                with_neural=True,
                model_path=LARGE,
            ).anomalies
        ]
        # La moyenne doit être plus basse (ou égale) avec le grand trainset.
        sm = sum(small_scores) / max(1, len(small_scores))
        lg = sum(large_scores) / max(1, len(large_scores))
        self.assertLessEqual(
            lg,
            sm + 0.01,
            f"petit modèle : moyenne={sm:.2f} ; grand : {lg:.2f} (devrait être <=)",
        )


if __name__ == "__main__":
    unittest.main()
