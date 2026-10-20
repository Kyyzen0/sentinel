"""Signature macOS : construction des commandes, arguments, secrets.

Aucun ``codesign`` réel. Le sous-processus est un faux qui enregistre
les argv. Les tests tournent sur Linux comme sur macOS.
"""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sign = _load("_sentinel_macos_sign", REPO / "packaging" / "macos_sign.py")
build = _load("_sentinel_packaging_build", REPO / "packaging" / "build.py")

IDENTITY = "Developer ID Application: Votre Nom (AB12CD34EF)"
PASSWORD = "abcd-efgh-ijkl-mnop"
MACH_O = b"\xcf\xfa\xed\xfe" + b"\x00" * 4


def _write_macho(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(MACH_O)


def _make_app(root: Path) -> Path:
    app = root / "dist" / "Sentinel.app"
    exe = app / "Contents" / "MacOS" / "sentinel"
    _write_macho(exe)
    helper = app / "Contents" / "MacOS" / "helper.dylib"
    _write_macho(helper)
    inner = app / "Contents" / "Frameworks" / "QtCore.framework" / "Versions" / "A" / "QtCore"
    _write_macho(inner)
    readme = app / "Contents" / "Resources" / "readme.txt"
    readme.parent.mkdir(parents=True, exist_ok=True)
    readme.write_text("pas un binaire\n", encoding="utf-8")
    # cafebabe + version Java 21 (majeure 65) : ce n'est pas un Mach-O fat.
    java = app / "Contents" / "Resources" / "Fake.class"
    java.write_bytes(b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (65).to_bytes(2, "big"))
    plist = app / "Contents" / "Info.plist"
    plist.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>sentinel</string>
<key>CFBundleIdentifier</key><string>dev.sentinel.desktop</string>
</dict></plist>
""",
        encoding="utf-8",
    )
    framework = app / "Contents" / "Frameworks" / "QtCore.framework"
    try:
        os.symlink("Versions/Current/QtCore", framework / "QtCore")
        os.symlink("A", framework / "Versions" / "Current")
    except OSError:
        pass
    return app


class ScriptedRun:
    def __init__(self, handler):
        self.handler = handler
        self.calls: list[list[str]] = []

    def __call__(self, args, *, timeout=None, echo=True, secrets=()):
        self.calls.append(list(args))
        return self.handler(list(args), timeout=timeout, echo=echo, secrets=secrets)


def _ok(args, **_kwargs):
    if args[:3] == ["xcrun", "notarytool", "submit"]:
        return sign.CommandResult(
            0,
            "id: 12345678-1234-1234-1234-1234567890ab\nstatus: Accepted\n",
            "",
        )
    if args[:2] == ["codesign", "--display"]:
        return sign.CommandResult(
            0,
            "",
            "Identifier=dev.sentinel.desktop\nAuthority=Developer ID Application: Test (TEAMID1234)\n"
            "Timestamp=19 Oct 2026\nTeamIdentifier=TEAMID1234\n",
        )
    if args[:2] == ["spctl", "-a"]:
        return sign.CommandResult(0, "", f"{args[-1]}: accepted\nsource=Notarized Developer ID\n")
    if args[:1] == ["ditto"]:
        Path(args[-1]).write_bytes(b"PK")
        return sign.CommandResult(0, "", "")
    if args[:2] == ["hdiutil", "create"]:
        Path(args[-1]).write_bytes(b"dmg")
        return sign.CommandResult(0, "", "")
    return sign.CommandResult(0, "", "")


class MachOTests(unittest.TestCase):
    def test_thin_and_fat_magics(self) -> None:
        self.assertTrue(sign.is_macho_bytes(MACH_O))
        self.assertTrue(sign.is_macho_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 4))
        self.assertTrue(sign.is_macho_bytes(b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big")))
        self.assertTrue(sign.is_macho_bytes(b"\xbe\xba\xfe\xca" + (2).to_bytes(4, "little")))
        self.assertTrue(sign.is_macho_bytes(b"\xca\xfe\xba\xbf" + b"\x00" * 4))

    def test_java_class_and_text_are_not_macho(self) -> None:
        java = b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (65).to_bytes(2, "big")
        self.assertFalse(sign.is_macho_bytes(java))
        self.assertFalse(sign.is_macho_bytes(b"\xca\xfe\xba\xbe"))
        self.assertFalse(sign.is_macho_bytes(b"hello"))
        self.assertFalse(sign.is_macho_bytes(b""))


class PlanTests(unittest.TestCase):
    def test_inside_out_entitlements_and_skipped_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app(Path(tmp))
            targets = sign.plan_signing(app)
            paths = [target.path for target in targets]
            inner = (
                app / "Contents" / "Frameworks" / "QtCore.framework" / "Versions" / "A" / "QtCore"
            )
            framework = app / "Contents" / "Frameworks" / "QtCore.framework"
            helper = app / "Contents" / "MacOS" / "helper.dylib"
            main = app / "Contents" / "MacOS" / "sentinel"
            self.assertLess(paths.index(inner), paths.index(framework))
            self.assertLess(paths.index(helper), paths.index(main))
            self.assertLess(paths.index(main), paths.index(app))
            self.assertEqual(paths[-1], app)
            self.assertEqual(paths.count(inner), 1)
            names = {path.name for path in paths}
            self.assertNotIn("readme.txt", names)
            self.assertNotIn("Fake.class", names)
            for target in targets:
                if target.path in {app, main}:
                    self.assertTrue(target.entitlements)
                else:
                    self.assertFalse(target.entitlements)
            normalized = [str(path).replace("\\", "/") for path in paths]
            framework_s = str(framework).replace("\\", "/")
            self.assertNotIn(f"{framework_s}/QtCore", normalized)
            self.assertFalse(any("Versions/Current" in path for path in normalized))

    def test_nested_app_gets_the_same_entitlements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app(Path(tmp))
            nested = app / "Contents" / "Frameworks" / "Helper.app"
            nested_exe = nested / "Contents" / "MacOS" / "helper"
            _write_macho(nested_exe)
            plist = nested / "Contents" / "Info.plist"
            plist.parent.mkdir(parents=True, exist_ok=True)
            plist.write_text(
                """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>helper</string>
</dict></plist>
""",
                encoding="utf-8",
            )
            ordered = sign.plan_signing(app)
            targets = {target.path: target.entitlements for target in ordered}
            paths = [target.path for target in ordered]
            self.assertTrue(targets[nested])
            self.assertTrue(targets[nested_exe])
            self.assertLess(paths.index(nested_exe), paths.index(nested))
            helper = app / "Contents" / "MacOS" / "helper.dylib"
            self.assertIn(helper, targets)
            self.assertFalse(targets[helper])

    def test_rejects_path_as_bundle_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app(Path(tmp))
            plist = app / "Contents" / "Info.plist"
            plist.write_text(
                plist.read_text(encoding="utf-8").replace(">sentinel<", ">../evil<"),
                encoding="utf-8",
            )
            with self.assertRaises(sign.MacSignError) as raised:
                sign.plan_signing(app)
            self.assertIn("CFBundleExecutable", str(raised.exception))

    def test_commands_have_runtime_timestamp_and_no_deep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app(Path(tmp))
            entitlements = sign.entitlements_path()
            for target in sign.plan_signing(app):
                command = sign.codesign_command(
                    IDENTITY,
                    target.path,
                    entitlements if target.entitlements else None,
                )
                self.assertNotIn("--deep", command)
                self.assertIn("--timestamp", command)
                self.assertEqual(command[command.index("--options") + 1], "runtime")
                self.assertIn("--all-architectures", command)
                self.assertEqual(command[command.index("--sign") + 1], IDENTITY)
                if target.entitlements:
                    self.assertIn("--entitlements", command)
                    self.assertTrue(
                        command[command.index("--entitlements") + 1].endswith("entitlements.plist")
                    )
                else:
                    self.assertNotIn("--entitlements", command)
                self.assertEqual(command[-1], str(target.path))
                self.assertFalse(any(" " in part and part != IDENTITY for part in command))


class ResolveTests(unittest.TestCase):
    def test_identity_env_and_cli(self) -> None:
        self.assertIsNone(sign.resolve_identity(None, {"SENTINEL_CODESIGN_IDENTITY": IDENTITY}))
        self.assertEqual(
            sign.resolve_identity("", {"SENTINEL_CODESIGN_IDENTITY": f"  {IDENTITY}  "}), IDENTITY
        )
        self.assertEqual(
            sign.resolve_identity(f"  {IDENTITY} ", {"SENTINEL_CODESIGN_IDENTITY": "autre"}),
            IDENTITY,
        )
        with self.assertRaises(sign.MacSignError) as raised:
            sign.resolve_identity("   ", {})
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("security find-identity -v -p codesigning", str(raised.exception))

    def test_notary_profile_default_and_env(self) -> None:
        auth = sign.resolve_notary(None, {})
        self.assertEqual(auth.kind, "profile")
        self.assertEqual(auth.profile, "sentinel-notary")
        self.assertEqual(auth.secrets(), ())
        custom = sign.resolve_notary(None, {"SENTINEL_NOTARY_PROFILE": "  atelier  "})
        self.assertEqual(custom.profile, "atelier")
        explicit = sign.resolve_notary("  mon-profil ", {"SENTINEL_NOTARY_PROFILE": "autre"})
        self.assertEqual(explicit.profile, "mon-profil")

    def test_apple_env_does_not_read_the_app_password(self) -> None:
        env = {
            "APPLE_ID": "alice@example.com",
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_APP_PASSWORD": PASSWORD,
        }
        auth = sign.resolve_notary(None, env)
        self.assertEqual(auth.kind, "apple_id")
        self.assertEqual(auth.apple_id, "alice@example.com")
        self.assertEqual(auth.team_id, "TEAMID1234")
        self.assertEqual(auth.password, "")
        self.assertEqual(auth.secrets(), ())
        self.assertNotIn(PASSWORD, repr(auth))
        self.assertNotIn("********", repr(auth))
        stored = sign.store_credentials_argv(
            "sentinel-notary",
            auth.apple_id,
            auth.team_id,
            "/tmp/sentinel-signing.keychain-db",
        )
        self.assertNotIn("--password", stored)
        self.assertNotIn(PASSWORD, stored)
        self.assertNotIn("@env:", " ".join(stored))
        self.assertIn("--apple-id", stored)
        self.assertIn("--team-id", stored)
        self.assertIn("--keychain", stored)
        self.assertNotIn("-p", stored)
        default_keychain = sign.store_credentials_argv(
            "sentinel-notary",
            auth.apple_id,
            auth.team_id,
        )
        self.assertNotIn("--keychain", default_keychain)
        self.assertNotIn("--password", default_keychain)
        with self.assertRaises(sign.MacSignError):
            sign.notary_submit_command(Path("Sentinel.zip"), auth)

    def test_api_key_beats_apple_id_and_stays_off_the_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "AuthKey.p8"
            body = "-----BEGIN PRIVATE KEY-----\nsecret-p8-material\n-----END PRIVATE KEY-----\n"
            key.write_text(body, encoding="utf-8")
            env = {
                "APPLE_API_KEY": str(key),
                "APPLE_API_KEY_ID": "KEYID12345",
                "APPLE_API_ISSUER": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "APPLE_ID": "alice@example.com",
                "APPLE_TEAM_ID": "TEAMID1234",
                "APPLE_APP_PASSWORD": PASSWORD,
            }
            auth = sign.resolve_notary(None, env)
            self.assertEqual(auth.kind, "api_key")
            self.assertEqual(auth.password, "")
            calls: list[list[str]] = []

            def handler(args, **_kwargs):
                calls.append(list(args))
                if args[:3] == ["xcrun", "notarytool", "submit"]:
                    return sign.CommandResult(0, "status: Accepted\n", "")
                return sign.CommandResult(0, "", "")

            with redirect_stdout(io.StringIO()):
                sign.submit_and_wait(Path("Sentinel.zip"), auth, handler)
            self.assertEqual(len(calls), 1)
            submit = calls[0]
            self.assertEqual(submit[submit.index("--key") + 1], str(key))
            self.assertEqual(submit[submit.index("--key-id") + 1], "KEYID12345")
            self.assertEqual(submit[submit.index("--issuer") + 1], env["APPLE_API_ISSUER"])
            self.assertNotIn("--password", submit)
            self.assertNotIn("store-credentials", submit)
            blob = " ".join(submit)
            self.assertNotIn(PASSWORD, blob)
            self.assertNotIn("secret-p8-material", blob)
            self.assertNotIn("@env:", blob)
            profile = sign.resolve_notary("sentinel-notary", env)
            self.assertEqual(profile.kind, "profile")

    def test_explicit_profile_beats_apple_env(self) -> None:
        env = {
            "APPLE_ID": "alice@example.com",
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_APP_PASSWORD": PASSWORD,
        }
        auth = sign.resolve_notary("sentinel-notary", env)
        self.assertEqual(auth.kind, "profile")
        self.assertEqual(auth.password, "")
        command = sign.notary_submit_command(Path("a.dmg"), auth)
        self.assertEqual(command[command.index("--keychain-profile") + 1], "sentinel-notary")
        self.assertNotIn("--password", command)
        self.assertNotIn(PASSWORD, command)

    def test_partial_apple_env_names_the_missing_variables(self) -> None:
        with self.assertRaises(sign.MacSignError) as raised:
            sign.resolve_notary(None, {"APPLE_ID": "secret-apple-id@example.com"})
        message = str(raised.exception)
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("APPLE_TEAM_ID", message)
        self.assertNotIn("APPLE_APP_PASSWORD", message)
        self.assertNotIn("secret-apple-id@example.com", message)
        ignored = sign.resolve_notary(None, {"APPLE_APP_PASSWORD": PASSWORD})
        self.assertEqual(ignored.kind, "profile")
        self.assertEqual(ignored.password, "")
        with self.assertRaises(sign.MacSignError) as api_raised:
            sign.resolve_notary(None, {"APPLE_API_KEY_ID": "KEYID12345"})
        api_message = str(api_raised.exception)
        self.assertIn("APPLE_API_KEY", api_message)
        self.assertIn("APPLE_API_ISSUER", api_message)
        self.assertNotIn("KEYID12345", api_message)

    def test_empty_secret_does_not_shred_text(self) -> None:
        self.assertEqual(sign.redact("mot de passe", ["", ""]), "mot de passe")

    def test_keychain_lookup_never_prints_the_password(self) -> None:
        command = sign.notary_profile_keychain_command("sentinel-notary")
        self.assertNotIn("-g", command)
        self.assertNotIn("-w", command)
        self.assertIn("com.apple.gke.notary.tool.saved-creds.sentinel-notary", command)
        history = sign.notary_history_command("sentinel-notary")
        self.assertEqual(history[:3], ["xcrun", "notarytool", "history"])
        self.assertIn("--keychain-profile", history)


class NotarizeFlowTests(unittest.TestCase):
    def test_refusal_fetches_the_log_and_redacts_the_password(self) -> None:
        auth = sign.NotaryAuth(
            kind="apple_id",
            apple_id="alice@example.com",
            team_id="TEAMID1234",
            password=PASSWORD,
        )
        calls: list[list[str]] = []

        def handler(args, **_kwargs):
            calls.append(args)
            if "submit" in args:
                return sign.CommandResult(
                    1,
                    f"id: 12345678-1234-1234-1234-1234567890ab\nstatus: Invalid\npassword {PASSWORD}\n",
                    "",
                )
            if "log" in args:
                return sign.CommandResult(
                    0,
                    '{"status":"Invalid","issues":[{"message":"signature invalid"}]}',
                    PASSWORD,
                )
            return sign.CommandResult(0, "", "")

        with redirect_stdout(io.StringIO()), self.assertRaises(sign.MacSignError) as raised:
            sign.submit_and_wait(
                Path("Sentinel.zip"),
                auth,
                handler,
                env={"SENTINEL_NOTARY_KEYCHAIN": "/tmp/sentinel-signing.keychain-db"},
            )
        message = str(raised.exception)
        self.assertIn("12345678-1234-1234-1234-1234567890ab", message)
        self.assertIn("signature invalid", message)
        self.assertNotIn(PASSWORD, message)
        self.assertNotIn("Notarisation acceptée", message)
        for call in calls:
            joined = " ".join(call)
            self.assertNotIn("@env:", joined)
            self.assertNotIn("--password", call)
            self.assertNotIn(PASSWORD, call)
            self.assertFalse(any(PASSWORD in arg for arg in call))
        store = calls[0]
        self.assertEqual(store[2], "store-credentials")
        self.assertNotIn("--password", store)
        self.assertIn("--apple-id", store)
        self.assertIn("--keychain", store)
        submit = calls[1]
        self.assertEqual(submit[2], "submit")
        self.assertNotIn("--password", submit)
        self.assertIn("--keychain-profile", submit)
        self.assertEqual(calls[2][2], "log")
        self.assertEqual(calls[2][3], "12345678-1234-1234-1234-1234567890ab")
        self.assertNotIn("--password", calls[2])

    def test_apple_id_is_not_blocked_by_a_ci_environment(self) -> None:
        """La signature ne se fait pas dans CI : le garde-fou n'existe plus."""
        auth = sign.NotaryAuth(
            kind="apple_id",
            apple_id="alice@example.com",
            team_id="TEAMID1234",
        )
        calls: list[list[str]] = []

        def handler(args, **_kwargs):
            calls.append(list(args))
            if args[:3] == ["xcrun", "notarytool", "submit"]:
                return sign.CommandResult(0, "status: Accepted\n", "")
            return sign.CommandResult(0, "", "")

        with redirect_stdout(io.StringIO()):
            sign.submit_and_wait(
                Path("Sentinel.zip"),
                auth,
                handler,
                env={"GITHUB_ACTIONS": "true", "APPLE_APP_PASSWORD": PASSWORD},
            )
        self.assertTrue(calls)
        self.assertEqual(calls[0][2], "store-credentials")
        self.assertNotIn("--password", calls[0])
        self.assertNotIn(PASSWORD, calls[0])
        self.assertFalse(any(call[:2] == ["security", "create-keychain"] for call in calls))
        self.assertFalse(any(call[:2] == ["security", "unlock-keychain"] for call in calls))
        self.assertNotIn("-p", calls[0])

    def test_without_a_terminal_the_user_is_told_to_run_store_credentials(self) -> None:
        auth = sign.NotaryAuth(
            kind="apple_id",
            apple_id="alice@example.com",
            team_id="TEAMID1234",
        )

        def boom(*_args, **_kwargs):
            raise AssertionError("notarytool ne doit pas être lancé sans Terminal")

        original = sign.subprocess.run
        sign.subprocess.run = boom
        try:
            with (
                unittest.mock.patch.object(sign.sys.stdin, "isatty", return_value=False),
                unittest.mock.patch.object(sign.sys.stdout, "isatty", return_value=False),
                redirect_stdout(io.StringIO()),
                self.assertRaises(sign.MacSignError) as raised,
            ):
                sign.submit_and_wait(Path("Sentinel.zip"), auth, sign.run_command)
        finally:
            sign.subprocess.run = original
        message = str(raised.exception)
        self.assertIn("store-credentials", message)
        self.assertIn("Terminal", message)
        self.assertNotIn(PASSWORD, message)
        commands = [
            line.strip() for line in message.splitlines() if line.strip().startswith("xcrun ")
        ]
        self.assertTrue(commands)
        for command in commands:
            self.assertNotIn("--password", command)

    def test_only_accepted_status_passes(self) -> None:
        auth = sign.NotaryAuth(kind="profile", profile="sentinel-notary")
        submission = "12345678-1234-1234-1234-1234567890ab"

        def run_status(stdout: str, returncode: int = 0) -> None:
            def handler(args, **_kwargs):
                if "log" in args:
                    return sign.CommandResult(0, "journal", "")
                return sign.CommandResult(returncode, stdout, "")

            sign.submit_and_wait(Path("Sentinel.zip"), auth, handler)

        accepted = f"id: {submission}\nCurrent status: In Progress\nstatus: Accepted\n"
        with redirect_stdout(io.StringIO()) as buffer:
            run_status(accepted, 0)
        self.assertIn("Notarisation acceptée", buffer.getvalue())

        for label, stdout, returncode in (
            ("in progress", f"id: {submission}\nstatus: In Progress\n", 0),
            ("invalid", f"id: {submission}\nstatus: Invalid\n", 0),
            ("rejected", f"id: {submission}\nstatus: Rejected\n", 1),
            ("absent", f"id: {submission}\n", 0),
            ("empty", "", 0),
            ("accepted but failed", f"id: {submission}\nstatus: Accepted\n", 1),
        ):
            with self.subTest(status=label):
                buffer = io.StringIO()
                with redirect_stdout(buffer), self.assertRaises(sign.MacSignError) as raised:
                    run_status(stdout, returncode)
                self.assertNotIn("Notarisation acceptée", buffer.getvalue())
                self.assertIn("n'est pas acceptée", str(raised.exception))

    def test_refused_without_id_does_not_call_log(self) -> None:
        auth = sign.NotaryAuth(kind="profile", profile="sentinel-notary")
        calls: list[list[str]] = []

        def handler(args, **_kwargs):
            calls.append(args)
            return sign.CommandResult(1, "Error: missing credentials\n", "")

        with redirect_stdout(io.StringIO()), self.assertRaises(sign.MacSignError) as raised:
            sign.submit_and_wait(Path("Sentinel.zip"), auth, handler)
        self.assertIn("pas d'identifiant", str(raised.exception).lower())
        self.assertEqual(len(calls), 1)


class DoctorTests(unittest.TestCase):
    def _tools_ok(self) -> dict[str, str | None]:
        return {
            "codesign": "/usr/bin/codesign",
            "notarytool": "/usr/bin/notarytool",
            "stapler": "/usr/bin/stapler",
        }

    def test_missing_tools_name_the_install_command(self) -> None:
        report = sign.build_doctor_report(
            xcode=sign.CommandResult(
                1, "", "xcode-select: error: unable to get active developer directory"
            ),
            tool_paths={"codesign": None, "notarytool": None, "stapler": None},
            identity_output="     0 valid identities found\n",
            identity_returncode=0,
            requested_identity=None,
            profile_arg=None,
            env={},
            keychain_item=sign.CommandResult(
                44, "", "The specified item could not be found in the keychain."
            ),
            history=sign.CommandResult(
                69, "", "Error: No Keychain password item found for profile: sentinel-notary"
            ),
        )
        text = sign.render_doctor(report)
        self.assertIn("[MANQUE] Outils Apple", text)
        self.assertIn("xcode-select --install", text)
        self.assertIn("sudo xcode-select -s /Applications/Xcode.app/Contents/Developer", text)
        self.assertIn("[MANQUE] Certificat Developer ID Application", text)
        self.assertIn("Developer ID Application", text)
        self.assertIn("security find-identity -v -p codesigning", text)
        self.assertIn("xcrun notarytool store-credentials sentinel-notary", text)
        self.assertFalse(report.ok)

    def test_development_cert_is_not_enough(self) -> None:
        output = '  1) ABCDEF "Apple Development: Votre Nom (TEAMID1234)"\n     1 valid identities found\n'
        report = sign.build_doctor_report(
            xcode=sign.CommandResult(0, "/Library/Developer/CommandLineTools\n", ""),
            tool_paths=self._tools_ok(),
            identity_output=output,
            identity_returncode=0,
            requested_identity=None,
            profile_arg=None,
            env={},
            keychain_item=sign.CommandResult(0, "keychain: login.keychain-db\n", ""),
            history=None,
        )
        text = sign.render_doctor(report)
        self.assertIn("[MANQUE] Certificat Developer ID Application", text)
        self.assertIn("Apple Development", text)
        self.assertIn("Manage Certificates", text)
        self.assertFalse(report.ok)

    def test_ready_machine_prints_the_exact_command(self) -> None:
        output = f'  1) ABCDEF "{IDENTITY}"\n     1 valid identities found\n'
        report = sign.build_doctor_report(
            xcode=sign.CommandResult(0, "/Applications/Xcode.app/Contents/Developer\n", ""),
            tool_paths=self._tools_ok(),
            identity_output=output,
            identity_returncode=0,
            requested_identity=None,
            profile_arg=None,
            env={},
            keychain_item=None,
            history=sign.CommandResult(0, "history\n", ""),
        )
        text = sign.render_doctor(report)
        self.assertTrue(report.ok)
        self.assertIn("[OK] Outils Apple", text)
        self.assertIn("[OK] Certificat Developer ID Application", text)
        self.assertIn("[OK] Profil notaire", text)
        self.assertIn(f'python packaging/build.py --sign "{IDENTITY}" --notarize', text)

    def test_apple_env_is_enough_and_password_is_not_printed(self) -> None:
        env = {
            "APPLE_ID": "alice@example.com",
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_APP_PASSWORD": PASSWORD,
        }
        report = sign.build_doctor_report(
            xcode=sign.CommandResult(0, "/Library/Developer/CommandLineTools\n", ""),
            tool_paths=self._tools_ok(),
            identity_output=f'  1) ABC "{IDENTITY}"\n',
            identity_returncode=0,
            requested_identity=None,
            profile_arg=None,
            env=env,
            keychain_item=None,
            history=None,
        )
        text = sign.render_doctor(report)
        self.assertTrue(report.ok)
        self.assertIn("n'est pas lu dans l'environnement", text)
        self.assertIn("une fois", text)
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn("alice@example.com", text)

    def test_run_doctor_does_not_pass_the_password_to_a_command(self) -> None:
        env = {
            "APPLE_ID": "alice@example.com",
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_APP_PASSWORD": PASSWORD,
        }
        scripted = ScriptedRun(
            lambda args, **_kwargs: sign.CommandResult(
                0,
                f'  1) ABC "{IDENTITY}"\n'
                if args[:2] == ["security", "find-identity"]
                else "/Applications/Xcode.app\n",
                "",
            )
        )
        with redirect_stdout(io.StringIO()) as buffer:
            code = sign.run_doctor(
                platform="darwin",
                env=env,
                sign_arg=None,
                profile_arg=None,
                run=scripted,
                tool_paths=self._tools_ok(),
            )
        self.assertEqual(code, 0)
        self.assertNotIn(PASSWORD, buffer.getvalue())
        flat = " ".join(" ".join(call) for call in scripted.calls)
        self.assertNotIn(PASSWORD, flat)
        self.assertNotIn("notarytool", flat)
        self.assertIn("find-identity", flat)

    def test_run_doctor_off_macos(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = sign.run_doctor(
                platform="linux", env={}, sign_arg=None, profile_arg=None, run=lambda *a, **k: None
            )
        self.assertEqual(code, 1)
        text = buffer.getvalue()
        self.assertIn("exige macOS", text)
        self.assertIn("n'est pas un Mac", text)
        self.assertNotIn("python packaging/build.py", text)
        self.assertNotIn("--sign", text)
        self.assertNotIn("--dmg", text)
        self.assertNotIn("--check", text)


class BuildCliTests(unittest.TestCase):
    def test_parse_sign_optional_value(self) -> None:
        self.assertIsNone(build.parse_args([]).sign)
        self.assertEqual(build.parse_args(["--sign"]).sign, "")
        self.assertEqual(build.parse_args(["--sign", IDENTITY, "--notarize"]).sign, IDENTITY)
        self.assertTrue(build.parse_args(["--sign", "--notarize", "--dmg"]).notarize)
        self.assertTrue(build.parse_args(["--sign", "--notarize", "--dmg"]).dmg)
        self.assertEqual(build.parse_args(["--sign", "--notarize"]).sign, "")
        self.assertEqual(
            build.parse_args(["--keychain-profile", "atelier"]).keychain_profile, "atelier"
        )

    def test_sign_on_linux_does_not_build(self) -> None:
        def boom(_args: list[str]) -> None:
            raise AssertionError("PyInstaller ne doit pas démarrer hors macOS")

        err = io.StringIO()
        with redirect_stderr(err):
            code = build.main(
                ["--sign", IDENTITY],
                platform="linux",
                env={},
                pyinstaller=boom,
            )
        self.assertEqual(code, 2)
        self.assertIn("macOS", err.getvalue())

    def test_check_does_not_build(self) -> None:
        def boom(_args: list[str]) -> None:
            raise AssertionError("PyInstaller ne doit pas démarrer pour --check")

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = build.main(["--check"], platform="linux", env={}, pyinstaller=boom)
        self.assertEqual(code, 1)
        self.assertIn("macOS", buffer.getvalue())

    def test_missing_identity_and_partial_env(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            code = build.main(["--sign"], platform="darwin", env={}, pyinstaller=lambda _a: None)
        self.assertEqual(code, 2)
        self.assertIn("SENTINEL_CODESIGN_IDENTITY", err.getvalue())

        err = io.StringIO()
        with redirect_stderr(err):
            code = build.main(
                ["--sign", IDENTITY, "--notarize"],
                platform="darwin",
                env={"APPLE_ID": "secret-apple-id@example.com"},
                pyinstaller=lambda _a: None,
            )
        self.assertEqual(code, 2)
        text = err.getvalue()
        self.assertIn("APPLE_TEAM_ID", text)
        self.assertNotIn("secret-apple-id@example.com", text)

    def test_build_without_sign_only_runs_pyinstaller(self) -> None:
        called: list[list[str]] = []

        def pyinstaller(args: list[str]) -> None:
            called.append(args)

        def runner(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("pas de signature sans --sign")

        code = build.main(
            [],
            platform="darwin",
            env={"APPLE_ID": "alice@example.com", "APPLE_APP_PASSWORD": PASSWORD},
            runner=runner,
            pyinstaller=pyinstaller,
            root=Path("/tmp/sentinel-unsigned"),
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(called), 1)
        self.assertTrue(any(arg.endswith("sentinel.spec") for arg in called[0]))

    def test_notarize_without_sign_is_refused(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            code = build.main(
                ["--notarize"], platform="darwin", env={}, pyinstaller=lambda _a: None
            )
        self.assertEqual(code, 2)
        self.assertIn("--sign", err.getvalue())

    def test_end_to_end_signs_notarizes_and_keeps_the_password_out_of_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripted = ScriptedRun(_ok)

            def pyinstaller(_args: list[str]) -> None:
                _make_app(root)

            out = io.StringIO()
            err = io.StringIO()
            env = {
                "APPLE_ID": "alice@example.com",
                "APPLE_TEAM_ID": "TEAMID1234",
                "APPLE_APP_PASSWORD": PASSWORD,
            }
            with redirect_stdout(out), redirect_stderr(err):
                code = build.main(
                    ["--sign", "--notarize"],
                    platform="darwin",
                    env={**env, "SENTINEL_CODESIGN_IDENTITY": IDENTITY},
                    runner=scripted,
                    pyinstaller=pyinstaller,
                    root=root,
                )
            self.assertEqual(code, 0, err.getvalue())
            combined = out.getvalue() + err.getvalue()
            self.assertNotIn(PASSWORD, combined)
            self.assertIn("Notarisation acceptée", combined)
            self.assertIn("codesign --verify --strict", combined)
            self.assertIn("source=Notarized Developer ID", combined)
            flat = scripted.calls
            codesigns = [call for call in flat if call[:1] == ["codesign"] and "--sign" in call]
            self.assertGreaterEqual(len(codesigns), 2)
            self.assertTrue(all("--deep" not in call for call in flat))
            self.assertTrue(
                any(call[:2] == ["codesign", "--verify"] and "--strict" in call for call in flat)
            )
            submits = [call for call in flat if call[:3] == ["xcrun", "notarytool", "submit"]]
            stores = [
                call for call in flat if call[:3] == ["xcrun", "notarytool", "store-credentials"]
            ]
            self.assertEqual(len(submits), 1)
            self.assertEqual(len(stores), 1)
            self.assertIn("--wait", submits[0])
            self.assertNotIn("--password", submits[0])
            self.assertNotIn(PASSWORD, submits[0])
            self.assertIn("--keychain-profile", submits[0])
            self.assertNotIn("--keychain", submits[0])
            self.assertNotIn("--password", stores[0])
            self.assertNotIn(PASSWORD, stores[0])
            self.assertIn("--apple-id", stores[0])
            self.assertNotIn("@env:", " ".join(" ".join(call) for call in flat))
            for call in flat:
                self.assertNotIn("--password", call)
                self.assertNotIn(PASSWORD, call)
                self.assertFalse(any(PASSWORD in arg for arg in call))
            self.assertFalse(any(call[:2] == ["security", "create-keychain"] for call in flat))
            self.assertFalse(any(call[:2] == ["security", "unlock-keychain"] for call in flat))
            self.assertTrue(any(call[:1] == ["ditto"] for call in flat))
            self.assertTrue(any(call[:3] == ["xcrun", "stapler", "staple"] for call in flat))
            gates = [call for call in flat if call[:2] == ["spctl", "-a"]]
            self.assertEqual(gates, [sign.spctl_app_command(root / "dist" / "Sentinel.app")])
            self.assertTrue((root / "dist" / "Sentinel.zip").is_file())

    def test_dmg_is_notarized_instead_of_the_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripted = ScriptedRun(_ok)

            def pyinstaller(_args: list[str]) -> None:
                _make_app(root)

            out = io.StringIO()
            with redirect_stdout(out):
                code = build.main(
                    [
                        "--sign",
                        IDENTITY,
                        "--notarize",
                        "--dmg",
                        "--keychain-profile",
                        "sentinel-notary",
                    ],
                    platform="darwin",
                    env={"APPLE_APP_PASSWORD": PASSWORD},
                    runner=scripted,
                    pyinstaller=pyinstaller,
                    root=root,
                )
            self.assertEqual(code, 0, out.getvalue())
            self.assertNotIn(PASSWORD, out.getvalue())
            submits = [
                call for call in scripted.calls if call[:3] == ["xcrun", "notarytool", "submit"]
            ]
            self.assertEqual(len(submits), 1)
            self.assertTrue(submits[0][3].endswith("Sentinel.dmg"))
            self.assertIn("--keychain-profile", submits[0])
            self.assertNotIn("--password", submits[0])
            self.assertNotIn(PASSWORD, submits[0])
            for call in scripted.calls:
                self.assertNotIn(PASSWORD, call)
            gates = [call for call in scripted.calls if call[:2] == ["spctl", "-a"]]
            self.assertTrue(gates)
            self.assertIn("--context", gates[0])
            self.assertIn("context:primary-signature", gates[0])
            self.assertEqual(gates[0][gates[0].index("-t") + 1], "open")
            self.assertEqual(
                gates[0],
                sign.spctl_open_command(root / "dist" / "Sentinel.dmg"),
            )
            self.assertTrue(any(call[:2] == ["hdiutil", "create"] for call in scripted.calls))
            dmg_signs = [
                call
                for call in scripted.calls
                if call[:1] == ["codesign"]
                and "--sign" in call
                and call[-1].endswith("Sentinel.dmg")
            ]
            self.assertEqual(len(dmg_signs), 1)
            self.assertNotIn("--options", dmg_signs[0])
            self.assertNotIn("--deep", dmg_signs[0])


class SubprocessWrapperTests(unittest.TestCase):
    def test_run_command_does_not_use_a_shell_and_redacts(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

            class Completed:
                returncode = 0
                stdout = f"ok {PASSWORD}"
                stderr = ""

            return Completed()

        original = sign.subprocess.run
        sign.subprocess.run = fake_run
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                result = sign.run_command(
                    ["xcrun", "notarytool", "submit", "--password", PASSWORD],
                    echo=True,
                    secrets=[PASSWORD],
                )
        finally:
            sign.subprocess.run = original
        self.assertIs(captured["kwargs"].get("shell", False), False)  # type: ignore[union-attr]
        self.assertIs(captured["kwargs"].get("stdin"), subprocess.DEVNULL)  # type: ignore[union-attr]
        self.assertEqual(captured["kwargs"].get("encoding"), "utf-8")  # type: ignore[union-attr]
        self.assertEqual(captured["kwargs"].get("errors"), "replace")  # type: ignore[union-attr]
        self.assertNotIn(PASSWORD, buffer.getvalue())
        self.assertIn(PASSWORD, result.stdout)
        self.assertNotIn(PASSWORD, sign.redact(result.stdout, [PASSWORD]))


class EntitlementsTests(unittest.TestCase):
    def test_plist_only_allows_unsigned_executable_memory(self) -> None:
        import plistlib

        with sign.entitlements_path().open("rb") as handle:
            data = plistlib.load(handle)
        self.assertEqual(
            list(data),
            ["com.apple.security.cs.allow-unsigned-executable-memory"],
        )
        self.assertIs(data["com.apple.security.cs.allow-unsigned-executable-memory"], True)


class DittoAndSpctlTests(unittest.TestCase):
    def test_archive_and_gatekeeper_commands(self) -> None:
        app = Path("/tmp/Sentinel.app")
        archive = Path("/tmp/Sentinel.zip")
        self.assertEqual(
            sign.ditto_zip_command(app, archive),
            ["ditto", "-c", "-k", "--keepParent", str(app), str(archive)],
        )
        self.assertEqual(
            sign.spctl_app_command(app),
            ["spctl", "-a", "-vv", "-t", "exec", str(app)],
        )
        dmg = Path("/tmp/Sentinel.dmg")
        self.assertEqual(
            sign.spctl_open_command(dmg),
            [
                "spctl",
                "-a",
                "-vv",
                "-t",
                "open",
                "--context",
                "context:primary-signature",
                str(dmg),
            ],
        )
        image = sign.codesign_disk_image_command(IDENTITY, dmg)
        self.assertNotIn("--options", image)
        self.assertNotIn("--deep", image)
        self.assertIn("--timestamp", image)


class PathShadowTests(unittest.TestCase):
    def test_packaging_dir_is_not_inserted_on_sys_path(self) -> None:
        # ``packaging/`` n'est pas un paquet : la bibliothèque PyPI du même
        # nom doit rester importable. Le chargement se fait par chemin.
        self.assertNotIn(str(REPO / "packaging"), sys.path)
        self.assertFalse((REPO / "packaging" / "__init__.py").exists())
