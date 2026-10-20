"""Tests P3-1 : `.sentinelignore`, `--min-severity`, `--only`.

C'est la 1ère cause d'abandon d'un scanner interne : trop de bruit, pas
de moyen d'ignorer proprement.

Cas couverts :
  - `.sentinelignore` filtre par rule_id
  - `.sentinelignore` filtre par path (glob)
  - `--min-severity high` enlève medium/low
  - `--only SIG-0019` ne garde que les findings de SIG-0019
  - Les findings filtrés sont comptés dans `ignored_findings` (audit)
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.models import Finding, Report
from sentinel.sentinelignore import (
    apply_ignore,
    parse_ignore_file,
)


def _make_report() -> Report:
    """Construit un rapport jouet avec 5 findings de règles différentes."""
    r = Report()
    r.findings = [
        Finding(
            rule_id="SIG-0001",
            severity="critical",
            path="webshell.php",
            line=1,
            message="m",
            evidence="e",
        ),
        Finding(
            rule_id="SIG-0002",
            severity="high",
            path="tests/reverse.sh",
            line=1,
            message="m",
            evidence="e",
        ),
        Finding(
            rule_id="SIG-0007",
            severity="high",
            path="vendor/lib.php",
            line=1,
            message="m",
            evidence="e",
        ),
        Finding(
            rule_id="SIG-0009",
            severity="medium",
            path="scripts/run.sh",
            line=1,
            message="m",
            evidence="e",
        ),
        Finding(
            rule_id="SIG-0019",
            severity="high",
            path="authorized_keys",
            line=1,
            message="m",
            evidence="e",
        ),
    ]
    return r


class TestParseIgnoreFile(unittest.TestCase):
    def test_parses_simple_rule(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / ".sentinelignore"
            f.write_text("# commentaire\nSIG-0007 anywhere demo signatures 2025-01-10\n")
            ig = parse_ignore_file(f)
            self.assertEqual(len(ig.rules), 1)
            r = ig.rules[0]
            self.assertEqual(r.rule_id, "SIG-0007")
            self.assertEqual(r.path_pattern, "anywhere")
            self.assertEqual(r.reason, "demo signatures")
            self.assertEqual(r.date, "2025-01-10")

    def test_skips_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / ".sentinelignore"
            f.write_text("SIG-0001 anywhere reason date\nMALFORMED\n")
            ig = parse_ignore_file(f)
            self.assertEqual(len(ig.rules), 1)
            self.assertEqual(len(ig.skipped), 1)
            self.assertIn("MALFORMED", ig.skipped[0])


class TestMinSeverity(unittest.TestCase):
    def test_min_severity_filters(self) -> None:
        r = _make_report()
        # Ne garder que high+critical.
        new = apply_ignore(r, ignore_file=Path("/nonexistent"), min_severity="high")
        severities = {f.severity for f in new.findings}
        self.assertTrue(severities.issubset({"high", "critical"}))
        # SIG-0009 (medium) doit être filtré.
        self.assertEqual(
            len([f for f in r.findings if f.severity == "medium"]),
            1,  # SIG-0009 medium
        )
        # Le medium a été déplacé dans ignored_findings.
        self.assertGreaterEqual(len(new.ignored_findings), 1)


class TestOnly(unittest.TestCase):
    def test_only_keeps_matching_rule(self) -> None:
        r = _make_report()
        new = apply_ignore(r, ignore_file=Path("/nonexistent"), only="SIG-0019")
        self.assertEqual(len(new.findings), 1)
        self.assertEqual(new.findings[0].rule_id, "SIG-0019")


class TestSentinelIgnore(unittest.TestCase):
    def test_filter_by_rule_id(self) -> None:
        r = _make_report()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ig = td / ".sentinelignore"
            ig.write_text("SIG-0007 anywhere vendor legacy 2025-01-01\n")
            new = apply_ignore(r, ignore_file=ig)
            rule_ids = {f.rule_id for f in new.findings}
            self.assertNotIn("SIG-0007", rule_ids)
            self.assertIn("SIG-0001", rule_ids)

    def test_directory_prefix_matches_children(self) -> None:
        """`tests/` doit couvrir `tests/reverse.sh`, pas seulement le glob `tests/*`."""
        r = _make_report()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ig = td / ".sentinelignore"
            ig.write_text("SIG-0002 tests/ test fixtures 2025-01-01\n")
            new = apply_ignore(r, ignore_file=ig)
            rule_paths = [(f.rule_id, f.path) for f in new.findings]
            self.assertNotIn(("SIG-0002", "tests/reverse.sh"), rule_paths)
            self.assertIn(("SIG-0001", "webshell.php"), rule_paths)

    def test_filter_by_glob_path(self) -> None:
        r = _make_report()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ig = td / ".sentinelignore"
            ig.write_text("SIG-0002 tests/* test fixtures 2025-01-01\n")
            new = apply_ignore(r, ignore_file=ig)
            # SIG-0002 sur tests/reverse.sh doit être filtré.
            rule_paths = [(f.rule_id, f.path) for f in new.findings]
            self.assertNotIn(("SIG-0002", "tests/reverse.sh"), rule_paths)

    def test_no_ignore_file_does_not_filter(self) -> None:
        r = _make_report()
        new = apply_ignore(r, ignore_file=Path("/nonexistent.ignore"))
        self.assertEqual(len(new.findings), 5)


class TestSarifExport(unittest.TestCase):
    def test_sarif_is_valid(self) -> None:
        from sentinel.reporting import render_sarif

        r = _make_report()
        sarif = json.loads(render_sarif(r))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "sentinel")
        # Au moins 4 règles uniques (SIG-0001, 0002, 0007, 0009 ; SIG-0019 aussi).
        self.assertGreaterEqual(len(run["tool"]["driver"]["rules"]), 4)
        self.assertEqual(len(run["results"]), 5)
        # Chaque result a un fingerprint.
        for res in run["results"]:
            self.assertIn("partialFingerprints", res)
            self.assertIn("sentinelFingerprint/v1", res["partialFingerprints"])


if __name__ == "__main__":
    unittest.main()
