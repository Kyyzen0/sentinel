"""Régressions : clé hors de la ligne de commande, clair sensible, HMAC
de la baseline, watch (dossier illisible + gros fichier), train et symlinks.
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
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.integrity import (  # noqa: E402
    baseline_canonical,
    baseline_signature_status,
    make_baseline,
)
from sentinel.keys import ENV_NAME, read_key_file, resolve_key  # noqa: E402
from sentinel.neural import AutoencoderScorer  # noqa: E402
from sentinel.watch import (  # noqa: E402
    _WATCH_FULL_HASH_MAX,
    _diff_snapshots,
    _sample_digest,
    _snapshot,
    watch_polling,
)

# Marqueur assemblé pour ne pas déposer une clé PEM contiguë dans le dépôt.
_PEM = (
    "-----BEGIN "
    + "RSA PRIVATE KEY-----\nFAKE-KEY-MATERIAL-sentinel\n-----END "
    + "RSA PRIVATE KEY-----\n"
)


def _run(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.pop(ENV_NAME, None)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=merged,
    )


class TestKeySources(unittest.TestCase):
    def test_encrypt_key_still_works_and_warns(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("hello\n")
            out = root / "b.json"
            r = _run(["baseline", str(root), "--out", str(out), "--encrypt-key", "s3cret-cli"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("déprécié", r.stderr)
            self.assertIn("SENTINEL_KEY", r.stderr)
            self.assertIn("--key-file", r.stderr)
            data = json.loads(out.read_text())
            self.assertTrue(data["encrypted"])
            self.assertEqual(data["signature_alg"], "HMAC-SHA256")
            self.assertNotIn("s3cret-cli", out.read_text())
            self.assertNotIn("hello", out.read_text())

    def test_env_and_key_file_sign_without_putting_the_key_in_argv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("hello\n")
            out = root / "b.json"
            r = _run(
                ["baseline", str(root), "--out", str(out)],
                env={ENV_NAME: "from-env"},
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("déprécié", r.stderr)
            self.assertEqual(
                baseline_signature_status(json.loads(out.read_text()), "from-env")[0], "ok"
            )

            key_path = root / "secret.key"
            key_path.write_text("from-file\n")
            from tests.osutil import seal_private

            seal_private(key_path)
            out2 = root / "c.json"
            r2 = _run(["baseline", str(root), "--out", str(out2), "--key-file", str(key_path)])
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertEqual(
                baseline_signature_status(json.loads(out2.read_text()), "from-file")[0], "ok"
            )
            self.assertNotIn("from-file", out2.read_text())

    def test_group_or_world_readable_key_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("x\n")
            key_path = root / "secret.key"
            key_path.write_text("secret\n")
            from tests.osutil import loosen_private

            loosen_private(key_path, 0o644)
            out = root / "b.json"
            r = _run(["baseline", str(root), "--out", str(out), "--key-file", str(key_path)])
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("lisible", r.stderr)
            self.assertFalse(out.exists())
            loosen_private(key_path, 0o640)
            r2 = _run(["baseline", str(root), "--out", str(out), "--key-file", str(key_path)])
            self.assertEqual(r2.returncode, 2, r2.stderr)

    def test_conflicting_sources_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("x\n")
            r = _run(
                ["baseline", str(root), "--out", str(root / "b.json"), "--encrypt-key", "a"],
                env={ENV_NAME: "b"},
            )
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn(ENV_NAME, r.stderr)

    def test_read_key_file_strips_a_single_trailing_newline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "k"
            path.write_text("abc\n")
            from tests.osutil import seal_private

            seal_private(path)
            self.assertEqual(read_key_file(path), "abc")
            key, warnings = resolve_key(encrypt_key=None, key_file=None, environ={})
            self.assertIsNone(key)
            self.assertEqual(warnings, ())


class TestSensitivePlaintextBaseline(unittest.TestCase):
    def test_fake_private_key_is_not_embedded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "notes.txt").write_text(_PEM)
            (root / "id_rsa").write_text(_PEM)
            (root / ".env").write_text("API_TOKEN=supersecretvalue\n")
            (root / "ordinary.txt").write_text("hello ordinary\n", newline="\n")
            bl = make_baseline(root)
            blob = json.dumps(bl)
            self.assertNotIn("FAKE-KEY-MATERIAL-sentinel", blob)
            self.assertNotIn("RSA PRIVATE KEY", blob)
            self.assertNotIn("supersecretvalue", blob)
            by_path = {e["path"]: e for e in bl["entries"]}
            for name in ("notes.txt", "id_rsa", ".env"):
                self.assertIsNone(by_path[name]["content"], name)
                self.assertEqual(by_path[name]["content_redacted"], "sensitive", name)
                self.assertTrue(by_path[name]["sha256"], name)
            self.assertEqual(by_path["ordinary.txt"]["content"], "hello ordinary\n")

    def test_scan_announces_sig0019_for_redacted_authorized_keys(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "authorized_keys").write_text("ssh-ed25519 AAAA one\n")
            bl = make_baseline(root)
            self.assertNotIn("ssh-ed25519", json.dumps(bl))
            (root / "authorized_keys").write_text("ssh-ed25519 AAAA one\nssh-ed25519 BBBB two\n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                from sentinel.scanner import scan_folder

                report = scan_folder(root, baseline=bl)
            rules = {f.rule_id for f in report.findings}
            self.assertIn("SIG-0007", rules)
            self.assertNotIn("SIG-0019", rules)
            self.assertIn("SIG-0019", err.getvalue())
            self.assertIn("sensible", err.getvalue())


class TestBaselineSignature(unittest.TestCase):
    def test_legacy_baseline_without_signature_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("hello\n")
            bl = make_baseline(root)
            self.assertNotIn("signature", bl)
            status, message = baseline_signature_status(bl, None)
            self.assertEqual(status, "unsigned")
            self.assertIn("non signée", message)
            out = root / "b.json"
            out.write_text(json.dumps(bl))
            r = _run(["scan", str(root), "--baseline", str(out), "--format", "json"])
            self.assertNotEqual(r.returncode, 2, r.stderr)
            self.assertIn("non signée", r.stderr)

    def test_copied_hash_does_not_scan_clean_when_key_is_set(self) -> None:
        """Modifier un fichier et recopier son nouveau sha256 dans la baseline
        doit échouer la signature HMAC : le scan ne sort pas 0."""
        with tempfile.TemporaryDirectory() as td:
            outside = Path(td)
            tree = outside / "tree"
            tree.mkdir()
            target = tree / "a.txt"
            target.write_text("version-1\n")
            key_path = outside / "k"
            key_path.write_text("signing-key\n")
            from tests.osutil import seal_private

            seal_private(key_path)
            out = outside / "base.json"
            created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key_path)])
            self.assertEqual(created.returncode, 0, created.stderr)

            target.write_text("version-2\n")
            fresh = make_baseline(tree, encrypt_key="signing-key")
            forged = json.loads(out.read_text())
            # L'attaquant aligne les hashes sur le fichier modifié et garde
            # l'ancienne signature : il n'a pas la clé pour la recalculer.
            forged["entries"] = fresh["entries"]
            out.write_text(json.dumps(forged))
            status, _message = baseline_signature_status(forged, "signing-key")
            self.assertEqual(status, "mismatch")

            scanned = _run(["scan", str(tree), "--baseline", str(out), "--key-file", str(key_path)])
            self.assertNotEqual(scanned.returncode, 0, scanned.stderr)
            self.assertEqual(scanned.returncode, 2, scanned.stderr)
            self.assertIn("Signature", scanned.stderr)
            self.assertIn("invalide", scanned.stderr)

    def test_roundtrip_signature_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "café.txt").write_text("hello\n")
            bl = make_baseline(root, encrypt_key="k")
            loaded = json.loads(json.dumps(bl))
            self.assertEqual(baseline_signature_status(loaded, "k")[0], "ok")
            self.assertEqual(baseline_signature_status(loaded, None)[0], "unverified")

    def _signed_tree(self, root: Path) -> tuple[Path, Path, Path]:
        """Arbre + baseline signée. Retourne ``(tree, key_file, baseline)``."""
        tree = root / "tree"
        tree.mkdir()
        (tree / "a.txt").write_text("version-1\n")
        key_path = root / "k"
        key_path.write_text("signing-key\n")
        from tests.osutil import seal_private

        seal_private(key_path)
        out = root / "base.json"
        created = _run(["baseline", str(tree), "--out", str(out), "--key-file", str(key_path)])
        self.assertEqual(created.returncode, 0, created.stderr)
        return tree, key_path, out

    def _tamper_entries(self, tree: Path, out: Path) -> None:
        """Aligne les entrées sur le fichier modifié, garde le reste."""
        (tree / "a.txt").write_text("version-2\n")
        fresh = make_baseline(tree, encrypt_key="signing-key")
        forged = json.loads(out.read_text())
        forged["entries"] = fresh["entries"]
        out.write_text(json.dumps(forged))

    def test_signed_tampered_baseline_without_key_fails_closed(self) -> None:
        """Sans clé, une baseline signée puis retouchée ne doit pas sortir 0."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, _key_path, out = self._signed_tree(root)
            self._tamper_entries(tree, out)

            scanned = _run(["scan", str(tree), "--baseline", str(out), "--format", "json"])
            self.assertEqual(scanned.returncode, 2, scanned.stderr)
            self.assertIn("impossible", scanned.stderr)
            self.assertIn("--allow-unverified-baseline", scanned.stderr)

            allowed = _run(
                [
                    "scan",
                    str(tree),
                    "--baseline",
                    str(out),
                    "--allow-unverified-baseline",
                    "--format",
                    "json",
                ]
            )
            self.assertNotEqual(allowed.returncode, 2, allowed.stderr)
            self.assertIn("non vérifiée", allowed.stderr)
            self.assertNotIn("impossible", allowed.stderr)

            watched = _run(
                [
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
            )
            self.assertEqual(watched.returncode, 2, watched.stderr)
            self.assertIn("impossible", watched.stderr)

            watched_ok = _run(
                [
                    "watch",
                    str(tree),
                    "--baseline",
                    str(out),
                    "--allow-unverified-baseline",
                    "--interval",
                    "0.05",
                    "--debounce",
                    "0",
                    "--max-iterations",
                    "1",
                ]
            )
            self.assertNotEqual(watched_ok.returncode, 2, watched_ok.stderr)
            self.assertIn("non vérifiée", watched_ok.stderr)

    def test_stripped_signature_is_refused_when_key_markers_remain(self) -> None:
        """Tamper + recopier le hash + retirer la signature ne sort pas 0."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree, key_path, out = self._signed_tree(root)
            original = json.loads(out.read_text())
            canon = baseline_canonical(original).decode()
            self.assertIn("key_check", canon)
            self.assertIn('"encrypted":true', canon)

            swapped = json.loads(json.dumps(original))
            swapped["key_check"] = "ab" * 32
            self.assertEqual(baseline_signature_status(swapped, "signing-key")[0], "mismatch")
            swapped_flag = json.loads(json.dumps(original))
            swapped_flag["encrypted"] = False
            self.assertEqual(baseline_signature_status(swapped_flag, "signing-key")[0], "mismatch")

            self._tamper_entries(tree, out)
            forged = json.loads(out.read_text())
            forged.pop("signature", None)
            forged.pop("signature_alg", None)
            self.assertIn("key_check", forged)
            out.write_text(json.dumps(forged))
            self.assertEqual(
                baseline_signature_status(forged, "signing-key")[0], "unsigned_refused"
            )
            self.assertEqual(baseline_signature_status(forged, None)[0], "unsigned_refused")

            with_key = _run(
                ["scan", str(tree), "--baseline", str(out), "--key-file", str(key_path)]
            )
            self.assertEqual(with_key.returncode, 2, with_key.stderr)
            self.assertIn("non signée", with_key.stderr)
            self.assertIn("retirée", with_key.stderr)

            without_key = _run(["scan", str(tree), "--baseline", str(out)])
            self.assertEqual(without_key.returncode, 2, without_key.stderr)
            self.assertIn("key_check", without_key.stderr)

    def test_unsigned_baseline_with_a_supplied_key_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("hello\n")
            bl = make_baseline(root)
            self.assertNotIn("signature", bl)
            self.assertNotIn("key_check", bl)
            out = root / "b.json"
            out.write_text(json.dumps(bl))
            key_path = root / "k"
            key_path.write_text("signing-key\n")
            from tests.osutil import seal_private

            seal_private(key_path)
            scanned = _run(["scan", str(root), "--baseline", str(out), "--key-file", str(key_path)])
            self.assertEqual(scanned.returncode, 2, scanned.stderr)
            self.assertIn("non signée", scanned.stderr)


class TestWatchHardening(unittest.TestCase):
    def test_unreadable_dir_appearing_is_reported(self) -> None:
        from tests.osutil import allow_read, deny_read, is_privileged

        if is_privileged():
            self.skipTest("root lit les modes 000")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a\n")
            seen: list[dict] = []
            bucket: list[str] = []
            held: dict[str, int] = {}

            def _sleep(_interval: float) -> None:
                locked = root / "locked"
                if not locked.exists():
                    locked.mkdir()
                    (locked / "hidden.txt").write_text("secret\n")
                    held["mode"] = deny_read(locked)

            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    watch_polling(
                        root,
                        0.01,
                        seen.append,
                        max_iterations=2,
                        debounce=0,
                        sleep=_sleep,
                        unreadable_out=bucket,
                    )
            finally:
                locked = root / "locked"
                if locked.exists() and "mode" in held:
                    allow_read(locked, held["mode"])
            text = err.getvalue()
            self.assertTrue(bucket, text)
            self.assertTrue(any(p == "locked" or p.startswith("locked") for p in bucket), bucket)
            self.assertIn("illisible", text)
            self.assertIn("exit 3", text)
            self.assertTrue(
                any(diff.get("unreadable") for diff in seen),
                seen,
            )

    def test_cli_watch_exits_3_for_unreadable_dir(self) -> None:
        from tests.osutil import allow_read, deny_read, is_privileged

        if is_privileged():
            self.skipTest("root lit les modes 000")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a\n")
            locked = root / "locked"
            locked.mkdir()
            (locked / "x.txt").write_text("nope\n")
            previous = deny_read(locked)
            try:
                r = _run(
                    [
                        "watch",
                        str(root),
                        "--interval",
                        "0.05",
                        "--debounce",
                        "0",
                        "--max-iterations",
                        "1",
                    ]
                )
            finally:
                allow_read(locked, previous)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn("illisible", r.stderr)
            self.assertIn("locked", r.stderr)

    def test_two_mebibyte_file_with_restored_mtime_is_modified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "big.bin"
            payload = b"A" * (2 * 1024 * 1024)
            path.write_bytes(payload)
            before = _snapshot(root)
            st = path.stat()
            mutated = bytearray(payload)
            mutated[1_000_000] = ord("B")
            path.write_bytes(mutated)
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
            after = _snapshot(root)
            self.assertEqual(before["big.bin"].size, after["big.bin"].size)
            self.assertEqual(before["big.bin"].mtime, after["big.bin"].mtime)
            self.assertNotEqual(before["big.bin"].digest, after["big.bin"].digest)
            diff = _diff_snapshots(before, after)
            self.assertIn("big.bin", diff["modified"])

            events: list[dict] = []

            def _sleep(_interval: float) -> None:
                if path.read_bytes()[1_000_000:1_000_001] == b"B":
                    path.write_bytes(payload)
                    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))

            # Repart de l'état muté (mtime restauré) et revient au payload
            # d'origine pendant le premier sleep : même taille, même mtime.
            path.write_bytes(mutated)
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
            watch_polling(
                root,
                0.01,
                events.append,
                max_iterations=2,
                debounce=0,
                sleep=_sleep,
            )
            modified = [p for event in events for p in event.get("modified", [])]
            self.assertIn("big.bin", modified, events)

    def test_large_file_full_hash_survives_another_files_change(self) -> None:
        """Un >8 Mio modifié hors échantillon, juste après un autre fichier,
        doit être vu en ≤ 10 tours. Le hash complet n'est pas jeté."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            small = root / "small.txt"
            small.write_text("v1\n")
            big = root / "big.bin"
            size = _WATCH_FULL_HASH_MAX + (1024 * 1024)
            payload = bytearray(b"A" * size)
            big.write_bytes(payload)
            st = big.stat()
            before_sample = _sample_digest(big, size)
            payload[200_000] = ord("Z")
            big.write_bytes(payload)
            os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))
            self.assertEqual(_sample_digest(big, size), before_sample)
            # Revenir à l'état initial : la mutation a lieu pendant le watch.
            payload[200_000] = ord("A")
            big.write_bytes(payload)
            os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))

            phase = {"n": 0}

            def _sleep(_interval: float) -> None:
                if phase["n"] == 0:
                    small.write_text("v2\n")
                    phase["n"] = 1
                elif phase["n"] == 1:
                    payload[200_000] = ord("Z")
                    big.write_bytes(payload)
                    os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))
                    phase["n"] = 2

            events: list[dict] = []
            iters = watch_polling(
                root,
                0.01,
                events.append,
                max_iterations=10,
                debounce=0,
                sleep=_sleep,
            )
            modified = [p for event in events for p in event.get("modified", [])]
            self.assertIn("small.txt", modified, events)
            self.assertIn("big.bin", modified, events)
            self.assertLessEqual(iters, 10)
            self.assertEqual(phase["n"], 2)


class TestTrainSymlinks(unittest.TestCase):
    def test_train_does_not_read_outside_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            secret = outside / "secret.py"
            secret.write_text("TOP_SECRET_TRAIN = 1\n")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "ok.py").write_text("def ok():\n    return 1\n")
            link = corpus / "leak.py"
            link.symlink_to(secret)
            (corpus / "subdir").symlink_to(outside, target_is_directory=True)

            opened: list[Path] = []
            real_open = Path.open

            def tracking_open(self: Path, *args: object, **kwargs: object):
                opened.append(Path(self))
                return real_open(self, *args, **kwargs)

            out = root / "model.json"
            with mock.patch.object(Path, "open", tracking_open):
                from sentinel.__main__ import main

                code = main(["train", str(corpus), "--out", str(out), "--epochs", "1"])
                scorer = AutoencoderScorer()
                scorer.train([link], epochs=1, root=corpus)
            self.assertEqual(code, 0, "le fichier réel du corpus doit suffire")
            secret_real = secret.resolve()
            leaked = []
            for path in opened:
                try:
                    if path.resolve() == secret_real:
                        leaked.append(path)
                except OSError:
                    continue
            self.assertEqual(leaked, [], leaked)
            self.assertTrue(out.is_file())


if __name__ == "__main__":
    unittest.main()
