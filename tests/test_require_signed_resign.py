"""Politique --require-signed et resignature d'une baseline existante.

Le défaut historique reste l'avertissement : une baseline dépouillée de
``signature``, ``encrypted``, ``key_check`` et ``key_hint`` est
indiscernable d'une baseline ancienne. Le refus est opt-in.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.integrity import (  # noqa: E402
    REQUIRE_SIGNED_ENV,
    baseline_canonical,
    baseline_signature_status,
    env_requires_signed,
)
from sentinel.keys import ENV_NAME  # noqa: E402


def _run(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.pop(ENV_NAME, None)
    merged.pop(REQUIRE_SIGNED_ENV, None)
    if env:
        merged.update(env)
    # stdin sur /dev/null : isatty() est faux, le test « non-TTY » est stable.
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=merged,
        stdin=subprocess.DEVNULL,
    )


def _key_file(directory: Path, secret: str = "signing-key") -> Path:
    path = directory / "secret.key"
    path.write_text(secret + "\n")
    from tests.osutil import seal_private

    seal_private(path)
    return path


def _tree(root: Path, names: tuple[str, ...] = ("a.txt",)) -> tuple[Path, Path]:
    tree = root / "tree"
    tree.mkdir()
    for name in names:
        (tree / name).write_text(f"contenu-{name}\n")
    out = root / "base.json"
    return tree, out


class TestEnvRequiresSigned(unittest.TestCase):
    def test_only_one_true_yes_are_truthy(self) -> None:
        self.assertTrue(env_requires_signed({REQUIRE_SIGNED_ENV: "1"}))
        self.assertTrue(env_requires_signed({REQUIRE_SIGNED_ENV: "TRUE"}))
        self.assertTrue(env_requires_signed({REQUIRE_SIGNED_ENV: " Yes "}))
        for raw in ("", "0", "false", "no", "on", "2", "oui", "enabled"):
            self.assertFalse(env_requires_signed({REQUIRE_SIGNED_ENV: raw}), raw)
        self.assertFalse(env_requires_signed({}))


class TestRequireSigned(unittest.TestCase):
    def test_default_unsigned_stays_a_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            scanned = _run(["scan", str(tree), "--baseline", str(out)])
            self.assertNotEqual(scanned.returncode, 2, scanned.stderr)
            self.assertIn("non signée", scanned.stderr)
            self.assertNotIn("refusée", scanned.stderr)
            self.assertIn("SENTINEL", scanned.stdout)

    def test_stripped_signed_baseline_matches_legacy_until_required(self) -> None:
        """Retirer signature et marqueurs de clé ramène au chemin « non signée »."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)
            document = json.loads(out.read_text())
            for field in ("signature", "signature_alg", "encrypted", "key_check", "key_hint"):
                document.pop(field, None)
            out.write_text(json.dumps(document))
            self.assertEqual(baseline_signature_status(document, None)[0], "unsigned")

            warned = _run(["scan", str(tree), "--baseline", str(out)])
            self.assertNotEqual(warned.returncode, 2, warned.stderr)
            self.assertIn("non signée", warned.stderr)

            flagged = _run(["scan", str(tree), "--baseline", str(out), "--require-signed"])
            self.assertEqual(flagged.returncode, 2, flagged.stderr)
            self.assertIn("refusée", flagged.stderr)
            self.assertNotIn("SENTINEL", flagged.stdout)

            via_env = _run(
                ["scan", str(tree), "--baseline", str(out)],
                env={REQUIRE_SIGNED_ENV: "yes"},
            )
            self.assertEqual(via_env.returncode, 2, via_env.stderr)
            self.assertIn("refusée", via_env.stderr)

            not_truthy = _run(
                ["scan", str(tree), "--baseline", str(out)],
                env={REQUIRE_SIGNED_ENV: "on"},
            )
            self.assertNotEqual(not_truthy.returncode, 2, not_truthy.stderr)

    def test_flag_and_env_apply_to_watch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            watch_args = [
                "watch",
                str(tree),
                "--baseline",
                str(out),
                "--interval",
                "0.05",
                "--debounce",
                "0",
                "--max-iterations",
                "1",
            ]
            flagged = _run([*watch_args, "--require-signed"])
            self.assertEqual(flagged.returncode, 2, flagged.stderr)
            self.assertIn("refusée", flagged.stderr)

            via_env = _run(watch_args, env={REQUIRE_SIGNED_ENV: "1"})
            self.assertEqual(via_env.returncode, 2, via_env.stderr)
            self.assertIn("refusée", via_env.stderr)

    def test_explicit_flags_conflict_even_if_the_baseline_would_verify(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)
            scanned = _run(
                [
                    "scan",
                    str(tree),
                    "--baseline",
                    str(out),
                    "--key-file",
                    str(key),
                    "--require-signed",
                    "--allow-unverified-baseline",
                ]
            )
            self.assertEqual(scanned.returncode, 2, scanned.stderr)
            self.assertIn("incompatibles", scanned.stderr)
            self.assertNotIn("SENTINEL", scanned.stdout)

            watched = _run(
                [
                    "watch",
                    str(tree),
                    "--require-signed",
                    "--allow-unverified-baseline",
                    "--max-iterations",
                    "1",
                ]
            )
            self.assertEqual(watched.returncode, 2, watched.stderr)
            self.assertIn("incompatibles", watched.stderr)

    def test_env_wins_over_allow_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)

            allowed = _run(
                ["scan", str(tree), "--baseline", str(out), "--allow-unverified-baseline"]
            )
            self.assertNotEqual(allowed.returncode, 2, allowed.stderr)
            self.assertIn("non vérifiée", allowed.stderr)

            forced = _run(
                ["scan", str(tree), "--baseline", str(out), "--allow-unverified-baseline"],
                env={REQUIRE_SIGNED_ENV: "true"},
            )
            self.assertEqual(forced.returncode, 2, forced.stderr)
            self.assertIn("ignoré", forced.stderr)
            self.assertIn("ne l'emporte pas", forced.stderr)
            self.assertNotIn("SENTINEL", forced.stdout)

            unsigned = root / "legacy.json"
            legacy = _run(["baseline", str(tree), "--out", str(unsigned)])
            self.assertEqual(legacy.returncode, 0, legacy.stderr)
            forced_unsigned = _run(
                [
                    "scan",
                    str(tree),
                    "--baseline",
                    str(unsigned),
                    "--allow-unverified-baseline",
                ],
                env={REQUIRE_SIGNED_ENV: "Yes"},
            )
            self.assertEqual(forced_unsigned.returncode, 2, forced_unsigned.stderr)
            self.assertIn("ignoré", forced_unsigned.stderr)
            self.assertIn("refusée", forced_unsigned.stderr)

    def test_valid_signature_still_scans_when_required(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)
            scanned = _run(
                [
                    "scan",
                    str(tree),
                    "--baseline",
                    str(out),
                    "--key-file",
                    str(key),
                    "--require-signed",
                ],
                env={REQUIRE_SIGNED_ENV: "1"},
            )
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            self.assertIn("SENTINEL", scanned.stdout)

    def test_require_signed_without_baseline_does_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, _out = _tree(root)
            scanned = _run(["scan", str(tree), "--require-signed"])
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            self.assertIn("SENTINEL", scanned.stdout)

    def test_unreadable_baseline_is_exit_2_only_when_required(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, _out = _tree(root)
            missing = root / "missing.json"
            loose = _run(["scan", str(tree), "--baseline", str(missing)])
            self.assertNotEqual(loose.returncode, 2, loose.stderr)
            strict = _run(["scan", str(tree), "--baseline", str(missing), "--require-signed"])
            self.assertEqual(strict.returncode, 2, strict.stderr)
            self.assertIn("illisible", strict.stderr)


class TestResign(unittest.TestCase):
    def test_resign_without_key_refuses_and_keeps_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            before = out.read_bytes()
            resigned = _run(["baseline", "--resign", str(out), "--yes"])
            self.assertEqual(resigned.returncode, 2, resigned.stderr)
            self.assertIn("clé", resigned.stderr)
            self.assertEqual(out.read_bytes(), before)
            self.assertNotIn("signature", json.loads(out.read_text()))

    def test_resign_shows_diffs_and_does_not_rewrite_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root, ("a.txt", "b.txt", "d.txt"))
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            original = json.loads(out.read_text())
            old_sha = next(e["sha256"] for e in original["entries"] if e["path"] == "a.txt")
            old_content = next(e["content"] for e in original["entries"] if e["path"] == "a.txt")

            (tree / "a.txt").write_text("contenu-changé\n")
            (tree / "b.txt").unlink()
            (tree / "c.txt").write_text("nouveau\n")
            mode_path = tree / "d.txt"
            # Windows ignore le bit d'exécution : on bascule l'écriture,
            # qui change vraiment l'attribut lecture seule.
            flip = stat.S_IWUSR if os.name == "nt" else stat.S_IXUSR
            mode_path.chmod(stat.S_IMODE(mode_path.stat().st_mode) ^ flip)

            key = _key_file(root)
            out.chmod(0o600)
            resigned = _run(
                [
                    "baseline",
                    "--resign",
                    str(out),
                    "--key-file",
                    str(key),
                    "--yes",
                    "--trust-unsigned",
                    "--backup",
                ]
            )
            self.assertEqual(resigned.returncode, 0, resigned.stderr)
            self.assertRegex(resigned.stderr, r"ajoutés\s+: c\.txt")
            self.assertRegex(resigned.stderr, r"supprimés\s+: b\.txt")
            self.assertRegex(resigned.stderr, r"modifiés\s+: a\.txt")
            self.assertRegex(resigned.stderr, r"mode\s+: d\.txt")
            self.assertRegex(resigned.stderr, r"propriétaire\s+: \(aucun\)")
            self.assertIn("capabilities", resigned.stderr)

            signed = json.loads(out.read_text())
            self.assertEqual(baseline_signature_status(signed, "signing-key")[0], "ok")
            self.assertNotIn("encrypted", signed)
            self.assertEqual(
                next(e["sha256"] for e in signed["entries"] if e["path"] == "a.txt"),
                old_sha,
            )
            self.assertEqual(
                next(e["content"] for e in signed["entries"] if e["path"] == "a.txt"),
                old_content,
            )
            self.assertNotIn("contenu-changé", out.read_text())
            if os.name == "nt":
                # 0600 contient l'écriture propriétaire : Windows ne
                # retient que ce bit et rapporte 0666.
                self.assertTrue(out.stat().st_mode & stat.S_IWUSR)
            else:
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(list(out.parent.glob(f".{out.name}.*.tmp")), [])
            backup = out.with_name(out.name + ".bak")
            self.assertTrue(backup.is_file())
            self.assertNotIn("signature", json.loads(backup.read_text()))

    def test_non_tty_without_yes_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            before = out.read_bytes()
            key = _key_file(root)
            resigned = _run(
                [
                    "baseline",
                    "--resign",
                    str(out),
                    "--key-file",
                    str(key),
                    "--trust-unsigned",
                ]
            )
            self.assertEqual(resigned.returncode, 2, resigned.stderr)
            self.assertIn("TTY", resigned.stderr)
            self.assertIn("--yes", resigned.stderr)
            self.assertIn("Comparaison avec les fichiers", resigned.stderr)
            self.assertEqual(out.read_bytes(), before)

    def test_yes_signs_and_the_result_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            (tree / "plain.txt").write_text("clair-visible\n")
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            resigned = _run(
                ["baseline", "--resign", str(out), "--yes", "--trust-unsigned"],
                env={ENV_NAME: "from-env"},
            )
            self.assertEqual(resigned.returncode, 0, resigned.stderr)
            self.assertNotIn("déprécié", resigned.stderr)
            self.assertRegex(resigned.stderr, r"modifiés\s+: \(aucun\)")
            document = json.loads(out.read_text())
            self.assertEqual(baseline_signature_status(document, "from-env")[0], "ok")
            self.assertEqual(document["signature_alg"], "HMAC-SHA256")
            self.assertIn("clair-visible", out.read_text())
            self.assertNotIn("from-env", out.read_text())
            self.assertNotIn("encrypted", document)

            checked = _run(
                ["scan", str(tree), "--baseline", str(out), "--require-signed"],
                env={ENV_NAME: "from-env"},
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_encrypt_key_is_accepted_with_the_deprecation_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            resigned = _run(
                [
                    "baseline",
                    "--resign",
                    str(out),
                    "--yes",
                    "--trust-unsigned",
                    "--encrypt-key",
                    "cli-secret",
                ]
            )
            self.assertEqual(resigned.returncode, 0, resigned.stderr)
            self.assertIn("déprécié", resigned.stderr)
            document = json.loads(out.read_text())
            self.assertEqual(baseline_signature_status(document, "cli-secret")[0], "ok")
            self.assertNotIn("cli-secret", out.read_text())

    def test_tampered_signed_baseline_is_refused_even_with_yes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)
            forged = json.loads(out.read_text())
            forged["entries"][0]["sha256"] = "ab" * 32
            out.write_text(json.dumps(forged))
            before = out.read_bytes()
            self.assertEqual(baseline_signature_status(forged, "signing-key")[0], "mismatch")

            resigned = _run(["baseline", "--resign", str(out), "--key-file", str(key), "--yes"])
            self.assertEqual(resigned.returncode, 2, resigned.stderr)
            self.assertIn("invalide", resigned.stderr)
            self.assertIn("refusée", resigned.stderr)
            self.assertNotIn("Baseline signée", resigned.stderr)
            self.assertEqual(out.read_bytes(), before)

    def test_tty_decline_keeps_the_file_and_oui_signs_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            key = _key_file(root)
            before = out.read_bytes()
            from sentinel.__main__ import main

            declined = io.StringIO()
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch("sentinel.__main__.stdin_is_terminal", return_value=True),
                mock.patch("sentinel.__main__.sys.stdin.isatty", return_value=True),
                mock.patch("sentinel.__main__.sys.stdin.readline", return_value="n\n"),
                contextlib.redirect_stderr(declined),
            ):
                os.environ.pop(ENV_NAME, None)
                os.environ.pop(REQUIRE_SIGNED_ENV, None)
                code = main(
                    [
                        "baseline",
                        "--resign",
                        str(out),
                        "--key-file",
                        str(key),
                        "--trust-unsigned",
                    ]
                )
            self.assertEqual(code, 2, declined.getvalue())
            self.assertIn("[y/N]", declined.getvalue())
            self.assertIn("confiance initiale", declined.getvalue())
            self.assertIn("connu sain", declined.getvalue())
            self.assertIn("annulée", declined.getvalue())
            self.assertEqual(out.read_bytes(), before)

            accepted = io.StringIO()
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch("sentinel.__main__.stdin_is_terminal", return_value=True),
                mock.patch("sentinel.__main__.sys.stdin.isatty", return_value=True),
                mock.patch("sentinel.__main__.sys.stdin.readline", return_value="oui\n"),
                contextlib.redirect_stderr(accepted),
            ):
                os.environ.pop(ENV_NAME, None)
                os.environ.pop(REQUIRE_SIGNED_ENV, None)
                code = main(
                    [
                        "baseline",
                        "--resign",
                        str(out),
                        "--key-file",
                        str(key),
                        "--trust-unsigned",
                    ]
                )
            self.assertEqual(code, 0, accepted.getvalue())
            self.assertEqual(
                baseline_signature_status(json.loads(out.read_text()), "signing-key")[0],
                "ok",
            )

    def test_signed_resign_does_not_require_trust_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)
            resigned = _run(["baseline", "--resign", str(out), "--key-file", str(key), "--yes"])
            self.assertEqual(resigned.returncode, 0, resigned.stderr)
            self.assertIn("vérifiée", resigned.stderr)
            self.assertNotIn("confiance initiale", resigned.stderr)
            document = json.loads(out.read_text())
            self.assertNotIn("resigned_from_unsigned", document)
            self.assertEqual(baseline_signature_status(document, "signing-key")[0], "ok")

    def test_laundered_unsigned_baseline_needs_trust_and_keeps_provenance(self) -> None:
        """Hash recopié dans une baseline dépouillée : --yes seul ne signe pas.

        Avec --trust-unsigned, la resignature réussit (aucun écart : le JSON
        colle à l'arbre déjà modifié). La marque est dans le payload signé.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            key = _key_file(root)
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key)])
            self.assertEqual(created.returncode, 0, created.stderr)

            target = tree / "a.txt"
            # Même taille : seul le hash change, le diff d'intégrité reste vide.
            target.write_text("contenu-b.txt\n")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            forged = json.loads(out.read_text())
            entry = next(e for e in forged["entries"] if e["path"] == "a.txt")
            entry["sha256"] = digest
            for field in ("signature", "signature_alg", "encrypted", "key_check", "key_hint"):
                forged.pop(field, None)
            out.write_text(json.dumps(forged))
            before = out.read_bytes()

            refused = _run(["baseline", "--resign", str(out), "--key-file", str(key), "--yes"])
            self.assertEqual(refused.returncode, 2, refused.stderr)
            self.assertIn("--trust-unsigned", refused.stderr)
            self.assertIn("ne suffit pas", refused.stderr)
            self.assertIn("confiance initiale", refused.stderr)
            self.assertIn("connu sain", refused.stderr)
            self.assertEqual(out.read_bytes(), before)
            self.assertNotIn("signature", json.loads(out.read_text()))

            accepted = _run(
                [
                    "baseline",
                    "--resign",
                    str(out),
                    "--key-file",
                    str(key),
                    "--yes",
                    "--trust-unsigned",
                ]
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("confiance initiale", accepted.stderr)
            self.assertIn("aucun écart", accepted.stderr)
            self.assertIn("fichiers actuels", accepted.stderr)
            self.assertIn("connu sain", accepted.stderr)
            self.assertRegex(accepted.stderr, r"modifiés\s+: \(aucun\)")

            document = json.loads(out.read_text())
            self.assertIs(document["resigned_from_unsigned"], True)
            self.assertRegex(document["resigned_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            self.assertEqual(baseline_signature_status(document, "signing-key")[0], "ok")
            canon = baseline_canonical(document).decode()
            self.assertIn('"resigned_from_unsigned":true', canon)
            self.assertIn(f'"resigned_at":"{document["resigned_at"]}"', canon)

            scanned = _run(
                [
                    "scan",
                    str(tree),
                    "--baseline",
                    str(out),
                    "--key-file",
                    str(key),
                    "--require-signed",
                ]
            )
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            self.assertIn("resignée depuis un document non signé", scanned.stderr)
            self.assertIn(document["resigned_at"], scanned.stderr)

            # Une seconde resignature, signature déjà vérifiée, ne réclame pas
            # --trust-unsigned et ne retire pas la marque.
            again = _run(["baseline", "--resign", str(out), "--key-file", str(key), "--yes"])
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertNotIn("--trust-unsigned", again.stderr)
            kept = json.loads(out.read_text())
            self.assertIs(kept["resigned_from_unsigned"], True)
            self.assertEqual(kept["resigned_at"], document["resigned_at"])
            self.assertEqual(baseline_signature_status(kept, "signing-key")[0], "ok")

            tweaked = json.loads(out.read_text())
            tweaked["resigned_from_unsigned"] = False
            self.assertEqual(baseline_signature_status(tweaked, "signing-key")[0], "mismatch")
            tweaked = json.loads(out.read_text())
            tweaked["resigned_at"] = "1999-01-01T00:00:00Z"
            self.assertEqual(baseline_signature_status(tweaked, "signing-key")[0], "mismatch")

            out.write_text(json.dumps(tweaked))
            broken = _run(
                [
                    "scan",
                    str(tree),
                    "--baseline",
                    str(out),
                    "--key-file",
                    str(key),
                    "--require-signed",
                ]
            )
            self.assertEqual(broken.returncode, 2, broken.stderr)
            self.assertIn("invalide", broken.stderr)

    def test_resign_rejects_out_or_a_positional_folder(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, out = _tree(root)
            created = _run(["baseline", str(tree), "--out", str(out)])
            self.assertEqual(created.returncode, 0, created.stderr)
            both = _run(["baseline", str(tree), "--resign", str(out), "--yes"])
            self.assertEqual(both.returncode, 2, both.stderr)
            self.assertIn("--out", both.stderr)
            orphan = _run(["baseline", str(tree), "--yes"])
            self.assertEqual(orphan.returncode, 2, orphan.stderr)
            self.assertIn("--resign", orphan.stderr)


if __name__ == "__main__":
    unittest.main()
