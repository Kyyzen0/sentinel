"""Tests P1-3 : garde-fous sur les chemins de quarantaine.

Le bug :
  - `--dest` à l'intérieur du dossier scanné : la quarantaine apparaît
    dans le scan suivant (récursion), pollue la baseline, etc.
  - Quarantaine sur `/`, `~`, ou tout chemin « sensible » (qui pourrait
    détruire des fichiers système) sans confirmation explicite.

Le fix :
  - Si `dest` est dans le dossier scanné (sauf le défaut
    `.sentinel-quarantine` à côté d'un fichier) : refuse (exit 2)
    sans `--force`.
  - `/`, `$HOME`, `~/.ssh`, `~/.gnupg` : refus définitif, même avec
    `--force`.
  - `~/.config` et les répertoires système : refus sans `--force`.
  - Le défaut `.sentinel-quarantine` (y compris sous `$HOME`) est autorisé.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def _has_method(name: str) -> bool:
    """Vérifie qu'une méthode existe sur `quarantine_paths` ou `quarantine_file`."""
    from sentinel import quarantine

    return hasattr(quarantine, name)


class TestQuarantinePathGuards(unittest.TestCase):
    def test_dest_inside_scanned_folder_is_refused(self) -> None:
        """--dest = sous-dossier du dossier scanné : refusé sans --force."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            target = td / "evil.sh"
            target.write_text("rm -rf /\n")
            inside_dest = td / "quarantine_sub"  # SOUS le dossier scanné
            inside_dest.mkdir()
            r = _run_cli("quarantine", str(target), "--dest", str(inside_dest))
            self.assertEqual(
                r.returncode,
                2,
                f"dest sous le dossier scanné doit être refusé (exit 2), "
                f"got {r.returncode}\nstderr: {r.stderr}",
            )
            # Le message doit mentionner le risque (capture/périmètre/boucle).
            msg = r.stderr.lower()
            self.assertTrue(
                "scanner" in msg or "périmètre" in msg or "boucle" in msg,
                f"l'erreur doit expliquer le risque: {r.stderr!r}",
            )
            # Le fichier source ne doit PAS avoir été bougé.
            self.assertTrue(target.exists(), "le fichier source a été déplacé malgré le refus")

    def test_dest_at_root_is_refused(self) -> None:
        """--dest = '/' : refusé (quarantaine sur la racine du système)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            target = td / "evil.sh"
            target.write_text("rm -rf /\n")
            r = _run_cli("quarantine", str(target), "--dest", "/")
            self.assertEqual(
                r.returncode,
                2,
                f"dest=/ doit être refusé, got {r.returncode}\nstderr: {r.stderr}",
            )
            self.assertTrue(target.exists(), "le fichier a été déplacé malgré le refus")

    def test_dest_inside_home_is_refused(self) -> None:
        """~/.config sous $HOME : refusé sans --force (liste souple).

        Un enfant quelconque de $HOME (l'ancien `.sentinel-test-…`) ne
        l'est plus : seul l'ensemble explicite l'est. Le test utilise un
        HOME temporaire pour ne pas toucher au vrai compte.
        """
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fake_home = td / "home"
            fake_home.mkdir()
            target = td / "evil.sh"
            target.write_text("rm -rf /\n")
            test_dest = fake_home / ".config" / "q"
            env = {**os.environ, "HOME": str(fake_home), "USERPROFILE": str(fake_home)}
            r = _run_cli("quarantine", str(target), "--dest", str(test_dest), env=env)
            self.assertEqual(
                r.returncode,
                2,
                f"dest={test_dest} (~/.config) doit être refusé, got {r.returncode}\n"
                f"stderr: {r.stderr}",
            )
            self.assertTrue(target.exists())
            self.assertFalse(test_dest.exists())

    def test_dest_in_unrelated_tempdir_works(self) -> None:
        """Un --dest dans un /tmp/<id> NON-PISTÉ est autorisé (pas sensible)."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            target = td / "evil.sh"
            target.write_text("rm -rf /\n")
            qdir = Path(tempfile.mkdtemp(prefix="q-"))  # /tmp/q-XXXX
            r = _run_cli("quarantine", str(target), "--dest", str(qdir))
            self.assertEqual(
                r.returncode,
                0,
                f"un /tmp/q-XXXX doit fonctionner, got {r.returncode}\nstderr: {r.stderr}",
            )
            self.assertFalse(target.exists())

    def test_force_overrides_home(self) -> None:
        """Avec --force, dest sous $HOME est autorisé.

        Le test créait auparavant un dossier dans le VRAI $HOME de
        l'utilisateur puis le supprimait : sale, et bloqué par les
        garde-fous de suppression des environnements sandboxés. On
        substitue un HOME temporaire au sous-processus — `expanduser("~")`
        le respecte sur POSIX.
        """
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fake_home = td / "home"
            fake_home.mkdir()
            target = td / "evil.sh"
            target.write_text("rm -rf /\n")
            test_dest = fake_home / ".sentinel-test-force"
            test_dest.mkdir()

            env = {**os.environ, "HOME": str(fake_home), "USERPROFILE": str(fake_home)}
            r = _run_cli("quarantine", str(target), "--dest", str(test_dest), "--force", env=env)
            self.assertEqual(
                r.returncode,
                0,
                f"--force doit autoriser, got {r.returncode}\nstderr: {r.stderr}",
            )
            self.assertFalse(target.exists(), "le fichier aurait dû être déplacé")


class TestSourceAndSharedDest(unittest.TestCase):
    def test_ssh_source_and_parent_are_refused(self) -> None:
        from sentinel.quarantine import quarantine_paths

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "users" / "alice"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True)
            (ssh / "id").write_text("key\n")
            (home / ".config").mkdir()
            (home / ".config" / "a").write_text("x\n")
            old_home = os.environ.get("HOME")
            old_profile = os.environ.get("USERPROFILE")
            os.environ["HOME"] = str(home)
            os.environ["USERPROFILE"] = str(home)
            dest = Path(tempfile.mkdtemp(prefix="q-"))
            try:
                records, failures = quarantine_paths([ssh], dest, dest / "m.jsonl")
                self.assertEqual(records, [])
                self.assertIn("critique", failures[0][1])
                self.assertTrue((ssh / "id").exists())

                parent = root / "users"
                records, failures = quarantine_paths([parent], dest, dest / "m.jsonl", force=True)
                self.assertEqual(records, [])
                self.assertIn("critique", failures[0][1])
                self.assertTrue((ssh / "id").exists())

                config = home / ".config"
                records, failures = quarantine_paths([config], dest, dest / "m.jsonl")
                self.assertEqual(records, [])
                self.assertIn("sensible", failures[0][1])
                self.assertTrue((config / "a").exists())
            finally:
                if old_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old_home
                if old_profile is None:
                    os.environ.pop("USERPROFILE", None)
                else:
                    os.environ["USERPROFILE"] = old_profile

    @unittest.skipUnless(os.name != "nt", "mode Unix")
    def test_sticky_dest_is_not_chmodded(self) -> None:
        from sentinel.quarantine import quarantine_paths

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "evil.sh"
            src.write_text("echo\n")
            dest = root / "shared"
            dest.mkdir()
            dest.chmod(0o1777)
            before = stat.S_IMODE(dest.stat().st_mode)
            records, failures = quarantine_paths([src], dest, dest / "m.jsonl", force=True)
            self.assertEqual(records, [])
            self.assertIn("partagé", failures[0][1])
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), before)
            self.assertTrue(src.exists())

    @unittest.skipUnless(os.name != "nt", "mode Unix")
    def test_existing_private_dir_keeps_its_mode(self) -> None:
        from sentinel.quarantine import quarantine_paths

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src" / "evil.sh"
            src.parent.mkdir()
            src.write_text("echo\n")
            dest = root / "keep"
            dest.mkdir()
            dest.chmod(0o764)
            before = stat.S_IMODE(dest.stat().st_mode)
            records, failures = quarantine_paths([src], dest, dest / "m.jsonl")
            self.assertEqual(failures, [])
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), before)
            self.assertFalse(src.exists())


if __name__ == "__main__":
    unittest.main()
