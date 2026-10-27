"""Fenêtre principale, pages et icône de barre."""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import signal
import sys
import threading
import time
import warnings
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QEventLoop, QSettings, QSortFilterProxyModel, Qt, QThread, QTimer, QUrl
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QIcon,
    QPixmap,
    QStandardItem,
    QStandardItemModel,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from sentinel import __version__
from sentinel.guidance import guidance
from sentinel.models import Report
from sentinel.platform import UnsafeNtPath, unsafe_nt_message
from sentinel.quarantine import (
    JournalInterrupted,
    JournalLocked,
    bind_journal_cancel,
    flush_quarantine_journals,
    format_journal_issues,
    init_engine,
)


def _integrity_lines(report: Report) -> list[str]:
    """Fichiers qui expliquent un exit 1 sans finding de signature."""
    diff = report.integrity
    rows = (
        ("modifiés", diff.modified),
        ("ajoutés", diff.added),
        ("supprimés", diff.removed),
        ("mode", diff.mode_changed),
        ("propriétaire", diff.owner_changed),
        ("capabilities", diff.cap_changed),
    )
    return [f"{label} : {', '.join(items)}" for label, items in rows if items]


from .locations import data_dir, default_scan_paths
from .services import (
    commit_resign,
    describe_baseline,
    export_report,
    load_baseline_for_scan,
    manifest_rows,
    preview_resign,
    restore,
)
from .session import SessionKey
from .workers import BaselineThread, PathNoteThread, QuarantineThread, ScanThread, WatchThread

_SEVERITY_COLOR = {
    "critical": "#ff6b6b",
    "high": "#ff9f43",
    "medium": "#f6c945",
    "low": "#9aa4b2",
}


def _tray_icon() -> QIcon:
    pixmap = QPixmap(32, 32)
    pixmap.fill(QColor("#3d8bfd"))
    return QIcon(pixmap)


# Fils encore en cours, parents de l'application : les détruire avec la
# page pendant qu'ils tournent fait planter Qt. Un classement de dossier
# est attendu au plus ``NOTE_EXIT_WAIT_S``. Une quarantaine est attendue
# jusqu'au bout : ``aboutToQuit`` ne fait pas ``os._exit`` pendant le
# déplacement. Un arrêt forcé reste récupérable (journal en deux phases).
NOTE_EXIT_WAIT_S = 2.5
JOURNAL_WAIT_TEXT = "Attente du journal de quarantaine…"
RESTORE_INTERRUPTED_TEXT = (
    "Restauration interrompue. La fermeture a annulé l'attente du journal. "
    "Aucun fichier n'a été remis en place."
)
RECOVERY_INTERRUPTED_TEXT = (
    "Reprise du journal interrompue. La fermeture a annulé l'attente du verrou. "
    "Le journal n'a pas été modifié."
)
_background_threads: list[QThread] = []
_hooked_apps: set[int] = set()
_tracked_settings: list[QSettings] = []
_note_exit_deadline: float | None = None
_quit_requested = False
_shutdown_dialog: QDialog | None = None
_force_confirm_open = False
_quit_wait_active = False
_quit_in_progress = False
_RESULT_SIGNALS = ("noted", "failed", "completed", "refused")
_SHUTDOWN_TEXT = "Fermeture après la fin de la mise en quarantaine…"


def retain_background_thread(thread: QThread) -> None:
    """Garde ``thread`` hors de la page, le temps qu'il se termine."""
    app = QApplication.instance()
    if isinstance(app, QApplication):
        thread.setParent(app)
        _install_exit_hook(app)
    _background_threads.append(thread)
    thread.finished.connect(lambda held=thread: release_background_thread(held))


def release_background_thread(thread: QThread) -> None:
    if thread.isRunning():
        return
    try:
        _background_threads.remove(thread)
    except ValueError:
        pass
    thread.setParent(None)


def detach_result_signals(thread: QThread) -> None:
    """Ignore un résultat tardif. Le fil lui-même continue."""
    for name in _RESULT_SIGNALS:
        signal = getattr(thread, name, None)
        if signal is None:
            continue
        # PySide avertit si le signal n'a aucun slot, au lieu de lever.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", message=".*Failed to disconnect", category=RuntimeWarning
            )
            try:
                signal.disconnect()
            except (RuntimeError, TypeError):
                pass


def register_settings(settings: QSettings) -> None:
    """Réglages à ``sync`` avant un ``os._exit``."""
    if all(existing is not settings for existing in _tracked_settings):
        _tracked_settings.append(settings)


class _CallThread(QThread):
    """Exécute un appel au journal hors du thread Qt.

    ``request_cancel`` réveille l'attente du verrou. Le corps déjà
    engagé (verrou pris) termine : le journal n'est pas coupé au milieu.
    """

    def __init__(self, func: Callable[[], object]) -> None:
        super().__init__()
        self._func = func
        self._cancel = threading.Event()
        self.result: object = None
        self.error: BaseException | None = None

    def request_cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            with bind_journal_cancel(self._cancel):
                self.result = self._func()
        except Exception as exc:
            self.error = exc


def _restore_outcome(outcome: object) -> tuple[list, list]:
    if not isinstance(outcome, tuple) or len(outcome) != 2:
        return [], []
    restored, failures = outcome
    if not isinstance(restored, list) or not isinstance(failures, list):
        return [], []
    return restored, failures


def _run_off_gui(parent: QWidget, func: Callable[[], object]) -> object:
    """Lance ``func`` dans un fil et affiche l'attente sans figer l'interface.

    Le verrou du journal peut retenir l'appel plusieurs secondes. La
    boucle Qt continue : la fenêtre d'attente se dessine, et un minuteur
    peut encore tourner.
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle("Journal de quarantaine")
    dialog.setModal(True)
    dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
    layout = QVBoxLayout()
    layout.addWidget(QLabel(JOURNAL_WAIT_TEXT))
    dialog.setLayout(layout)
    worker = _CallThread(func)
    retain_background_thread(worker)
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    worker.start()
    dialog.show()
    try:
        if worker.isRunning():
            loop.exec()
    finally:
        dialog.close()
        # Quitter fait sortir la boucle tout de suite. On annule l'attente
        # avant de joindre, pour ne pas rester sur le délai du verrou.
        if worker.isRunning():
            worker.request_cancel()
        worker.wait(int(NOTE_EXIT_WAIT_S * 1000))
        if not worker.isRunning():
            release_background_thread(worker)
    if worker.isRunning():
        raise JournalInterrupted()
    if worker.error is not None:
        raise worker.error
    return worker.result


def _cancel_off_gui_journal_waits() -> None:
    """Annule les attentes de verrou. Ne bloque pas."""
    for thread in list(_background_threads):
        if isinstance(thread, _CallThread):
            thread.request_cancel()


def _join_call_threads() -> bool:
    """Joint les ``_CallThread``. Faux si l'un d'eux dépasse le délai.

    ``hard_exit`` évite « QThread: Destroyed » : Qt ne doit pas détruire
    un fil encore vivant. Le délai est le même que pour un classement.
    """
    _cancel_off_gui_journal_waits()
    for thread in list(_background_threads):
        if not isinstance(thread, _CallThread):
            continue
        if thread.isRunning():
            thread.wait(int(NOTE_EXIT_WAIT_S * 1000))
        if thread.isRunning():
            hard_exit()
            return False
        detach_result_signals(thread)
        release_background_thread(thread)
    return True


def _announce_interrupted(parent: QWidget, log: QTextEdit, title: str, message: str) -> None:
    """Dit que l'attente a été annulée. Pas de modale pendant la fermeture."""
    log.append(message)
    print(message, file=sys.stderr)
    window = parent.window()
    if isinstance(window, QMainWindow):
        window.statusBar().showMessage(message)
    if _quit_in_progress:
        return
    QMessageBox.warning(parent, title, message)


def hard_exit() -> None:
    """Quitte sans destructeurs Qt. Vide d'abord ce qu'un crash perdrait.

    Ordre : journal de quarantaine (flush, fsync, close), réglages,
    handlers de log, sorties standard. ``os._exit(0)`` ne revient pas,
    sauf dans un test qui le remplace.
    """
    try:
        flush_quarantine_journals()
    except Exception:
        pass
    for settings in list(_tracked_settings):
        try:
            settings.sync()
        except Exception:
            pass
    try:
        logging.shutdown()
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass
    os._exit(0)


def _running_quarantine() -> QuarantineThread | None:
    for thread in _background_threads:
        if isinstance(thread, QuarantineThread) and thread.isRunning():
            return thread
    return None


def _quit_application() -> None:
    app = QApplication.instance()
    if isinstance(app, QApplication):
        app.quit()


def _focus_open_confirmation() -> None:
    """Ramène la confirmation déjà ouverte, sans en créer une autre."""
    active = QApplication.activeModalWidget()
    if isinstance(active, QMessageBox):
        active.raise_()
        active.activateWindow()
        return
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMessageBox) and widget.isVisible():
            widget.raise_()
            widget.activateWindow()
            return
    if _shutdown_dialog is not None and _shutdown_dialog.isVisible():
        _shutdown_dialog.raise_()
        _shutdown_dialog.activateWindow()


def _confirm_force_exit(parent: QWidget) -> None:
    global _force_confirm_open
    if _force_confirm_open:
        _focus_open_confirmation()
        return
    _force_confirm_open = True
    try:
        answer = QMessageBox.question(
            parent,
            "Forcer la fermeture",
            "Un fichier peut rester à moitié déplacé. Forcer la fermeture quand même ?",
        )
    finally:
        _force_confirm_open = False
    if answer == QMessageBox.StandardButton.Yes:
        hard_exit()


def _show_shutdown_dialog(thread: QuarantineThread) -> None:
    """Fenêtre modale non bloquante : la boucle Qt continue."""
    global _shutdown_dialog
    if _shutdown_dialog is not None and _shutdown_dialog.isVisible():
        return
    parent = QApplication.activeWindow()
    dialog = QDialog(parent if isinstance(parent, QWidget) else None)
    dialog.setWindowTitle(_SHUTDOWN_TEXT)
    dialog.setModal(True)
    dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
    layout = QVBoxLayout()
    layout.addWidget(QLabel(_SHUTDOWN_TEXT))
    force = QPushButton("Forcer la fermeture")
    force.clicked.connect(lambda: _confirm_force_exit(dialog))
    layout.addWidget(force)
    dialog.setLayout(layout)

    def finish() -> None:
        global _shutdown_dialog
        if _shutdown_dialog is dialog:
            _shutdown_dialog = None
        dialog.close()
        # ``aboutToQuit`` a déjà demandé la sortie. Un second ``quit``
        # après coup laisserait l'application fermée pour la suite.
        if not _quit_wait_active:
            _quit_application()

    thread.finished.connect(finish)
    _shutdown_dialog = dialog
    dialog.show()
    if not thread.isRunning():
        finish()


def request_graceful_quit(*_args: object) -> None:
    """Quitte, ou attend la fin de la quarantaine sans bloquer le thread Qt.

    Un second Ctrl+C / SIGTERM pendant l'attente ouvre une seule
    confirmation. Les suivants la ramènent au premier plan : les
    modales ne s'empilent pas. ``QApplication.quit`` n'est pas appelé
    tant qu'un déplacement tourne : ``aboutToQuit`` ne peut pas annuler
    la sortie.

    Une attente du verrou (restauration, reprise) est annulée tout de
    suite. Quitter ne reste pas bloqué sur ce délai.
    """
    global _quit_in_progress
    _quit_in_progress = True
    _cancel_off_gui_journal_waits()
    quarantine = _running_quarantine()
    if quarantine is None:
        _quit_application()
        return
    if _force_confirm_open:
        _focus_open_confirmation()
        return
    if _shutdown_dialog is not None and _shutdown_dialog.isVisible():
        _confirm_force_exit(_shutdown_dialog)
        return
    _show_shutdown_dialog(quarantine)


def _mark_quit(_signum: int, _frame: object) -> None:
    global _quit_requested
    _quit_requested = True


def _drain_quit_signal() -> None:
    global _quit_requested
    if not _quit_requested:
        return
    _quit_requested = False
    request_graceful_quit()


def _await_quarantine_completion(thread: QuarantineThread) -> None:
    """Laisse le déplacement finir. N'appelle pas ``os._exit``.

    ``aboutToQuit`` (``app.exit``, fin de session) arrive quand la boucle
    principale s'arrête. Si la plateforme le permet, une boucle interne
    attend le signal ``finished`` et garde la fenêtre d'attente (le
    bouton « Forcer la fermeture » reste utilisable). Sinon on attend le
    fil quand même : le move n'est pas abandonné. Un ``os._exit`` plus
    tard est récupérable grâce au journal en deux phases.
    """
    _show_shutdown_dialog(thread)
    if not thread.isRunning():
        return
    app = QApplication.instance()
    if isinstance(app, QApplication):
        loop = QEventLoop()
        thread.finished.connect(loop.quit)
        if thread.isRunning():
            loop.exec()
    while thread.isRunning():
        thread.wait(200)
    app = QApplication.instance()
    if isinstance(app, QApplication):
        # Livre ``finished`` tant que l'attente de sortie est active,
        # pour fermer la fenêtre sans relancer ``quit``.
        app.processEvents()


def wait_for_background_threads() -> None:
    """Attend la quarantaine jusqu'au bout, puis les classements ≤ 2,5 s.

    ``aboutToQuit`` ne tue pas le processus pendant une mise en
    quarantaine. Un classement encore bloqué après le délai quitte via
    ``os._exit``. Une quarantaine que l'attente n'a pas pu finir aussi :
    le journal « en cours » sera repris au prochain démarrage.
    Le même chemin sert à ``aboutToQuit`` et au retour de ``app.exec``.
    """
    global _quit_wait_active
    if _quit_wait_active:
        return
    _quit_wait_active = True
    try:
        _finish_background_threads()
    finally:
        _quit_wait_active = False


def _finish_background_threads() -> None:
    global _note_exit_deadline
    if not _join_call_threads():
        return
    quarantine = _running_quarantine()
    if quarantine is not None:
        _await_quarantine_completion(quarantine)
    now = time.monotonic()
    if _note_exit_deadline is None or now >= _note_exit_deadline:
        _note_exit_deadline = now + NOTE_EXIT_WAIT_S
    for thread in list(_background_threads):
        if not isinstance(thread, PathNoteThread):
            continue
        detach_result_signals(thread)
        remaining = _note_exit_deadline - time.monotonic()
        if thread.isRunning() and remaining > 0:
            thread.wait(int(remaining * 1000))
    alive_notes = [
        thread
        for thread in _background_threads
        if thread.isRunning() and isinstance(thread, PathNoteThread)
    ]
    if alive_notes:
        for thread in alive_notes:
            detach_result_signals(thread)
        hard_exit()
        return
    still_quarantine = _running_quarantine()
    if still_quarantine is not None:
        detach_result_signals(still_quarantine)
        hard_exit()
        return
    for thread in list(_background_threads):
        detach_result_signals(thread)
        release_background_thread(thread)


def _install_exit_hook(app: QApplication) -> None:
    key = id(app)
    if key in _hooked_apps:
        return
    app.aboutToQuit.connect(wait_for_background_threads)
    signal.signal(signal.SIGINT, _mark_quit)
    if os.name == "posix":
        signal.signal(signal.SIGTERM, _mark_quit)
    timer = QTimer(app)
    timer.setInterval(200)
    timer.timeout.connect(_drain_quit_signal)
    timer.start()
    _hooked_apps.add(key)


class ScanPage(QWidget):
    def __init__(self, host: MainWindow) -> None:
        super().__init__()
        self._host = host
        self._thread: ScanThread | None = None
        self._note_threads: list[PathNoteThread] = []
        self._note_generation = 0
        self._report: Report | None = None
        self.state = "idle"
        self._rows_seen = 0

        self.paths = QListWidget()
        for path in default_scan_paths():
            self.paths.addItem(str(path))
        add = QPushButton("Ajouter un dossier")
        add.clicked.connect(self._add_path)
        remove = QPushButton("Retirer")
        remove.clicked.connect(self._remove_path)

        self.follow = QCheckBox("Suivre les liens internes")
        self.anomaly = QCheckBox("Score d'anomalie")
        self.require_signed = QCheckBox("Exiger une baseline signée")
        self.allow_unverified = QCheckBox("Accepter une signature sans clé")
        self.severity = QComboBox()
        self.severity.addItems(["low", "medium", "high", "critical"])
        self.baseline = QLineEdit()
        self.baseline.setPlaceholderText("Baseline (optionnelle)")
        pick_base = QPushButton("…")
        pick_base.clicked.connect(self._pick_baseline)

        self.run_btn = QPushButton("Analyser")
        self.run_btn.clicked.connect(self._start_current)
        self.cancel_btn = QPushButton("Annuler")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel)
        self.progress = QLabel("En attente.")
        self.progress.setWordWrap(True)
        self._baseline_warning = ""
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filtrer sévérité, règle, chemin…")

        self.model = QStandardItemModel(0, 4)
        self.model.setHorizontalHeaderLabels(["Sévérité", "Règle", "Chemin", "Détail"])
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)

        export_json = QPushButton("Exporter JSON")
        export_json.clicked.connect(lambda: self._export("json"))
        export_sarif = QPushButton("Exporter SARIF")
        export_sarif.clicked.connect(lambda: self._export("sarif"))
        reveal = QPushButton("Ouvrir le dossier")
        reveal.clicked.connect(self._reveal)

        path_row = QHBoxLayout()
        path_row.addWidget(add)
        path_row.addWidget(remove)
        base_row = QHBoxLayout()
        base_row.addWidget(self.baseline)
        base_row.addWidget(pick_base)
        actions = QHBoxLayout()
        actions.addWidget(self.run_btn)
        actions.addWidget(self.cancel_btn)
        actions.addWidget(export_json)
        actions.addWidget(export_sarif)
        actions.addWidget(reveal)
        actions.addStretch(1)

        left = QVBoxLayout()
        left.addWidget(QLabel("Dossiers"))
        left.addWidget(self.paths)
        left.addLayout(path_row)
        form = QFormLayout()
        form.addRow("Sévérité min.", self.severity)
        form.addRow(self.follow)
        form.addRow(self.anomaly)
        form.addRow(self.require_signed)
        form.addRow(self.allow_unverified)
        left.addLayout(form)
        left.addWidget(QLabel("Baseline"))
        left.addLayout(base_row)
        left.addLayout(actions)
        left.addWidget(self.progress)
        left_w = QWidget()
        left_w.setLayout(left)

        right = QVBoxLayout()
        right.addWidget(self.filter)
        right.addWidget(self.table)
        right_w = QWidget()
        right_w.setLayout(right)
        split = QSplitter()
        split.addWidget(left_w)
        split.addWidget(right_w)
        split.setStretchFactor(1, 2)
        layout = QVBoxLayout(self)
        layout.addWidget(split)

    def progress_count(self) -> int:
        return self._rows_seen

    def _add_path(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Dossier à analyser")
        if folder:
            self.consider_folder(Path(folder))

    def consider_folder(self, folder: Path) -> None:
        """Classe ``folder`` dans un fil, puis l'ajoute. Le thread Qt n'attend pas le DNS."""
        self._note_generation += 1
        request_id = self._note_generation
        thread = PathNoteThread(folder, request_id)
        retain_background_thread(thread)
        thread.noted.connect(self._on_folder_noted)
        thread.failed.connect(self._on_folder_refused)
        thread.finished.connect(lambda t=thread: self._forget_note_thread(t))
        self._note_threads.append(thread)
        thread.start()

    def _forget_note_thread(self, thread: PathNoteThread) -> None:
        try:
            self._note_threads.remove(thread)
        except ValueError:
            pass

    def discard_note_results(self) -> None:
        """Oublie les résultats en cours. L'attente est réservée à la sortie réelle."""
        self._note_generation += 1
        for thread in list(self._note_threads):
            detach_result_signals(thread)

    def _on_folder_noted(self, request_id: int, folder: str, note: str) -> None:
        if request_id != self._note_generation:
            return
        if note:
            QMessageBox.information(self, "Chemin sensible", note)
        self.paths.addItem(folder)

    def _on_folder_refused(self, request_id: int, message: str) -> None:
        if request_id != self._note_generation:
            return
        QMessageBox.warning(self, "Refus", message)

    def _remove_path(self) -> None:
        row = self.paths.currentRow()
        if row >= 0:
            self.paths.takeItem(row)

    def _pick_baseline(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Baseline", "", "JSON (*.json)")
        if path:
            self.baseline.setText(path)

    def selected_folder(self) -> Path | None:
        item = self.paths.currentItem()
        if item is None and self.paths.count():
            item = self.paths.item(0)
        if item is None:
            return None
        return Path(item.text())

    def _start_current(self) -> None:
        folder = self.selected_folder()
        if folder is None:
            self.progress.setText("Choisissez un dossier.")
            return
        self.start_scan(folder)

    def start_scan(self, folder: Path, *, runner=None) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        base_text = self.baseline.text().strip()
        base = Path(base_text) if base_text else None
        loaded, error, warning = load_baseline_for_scan(
            base,
            self._host.keys.value,
            require_signed=self.require_signed.isChecked(),
            allow_unverified=self.allow_unverified.isChecked(),
        )
        self._baseline_warning = warning or ""
        if error:
            self.state = "error"
            self.progress.setText(error)
            return
        if warning:
            self.progress.setText(warning)
        options = {
            "baseline": loaded,
            "with_anomaly": self.anomaly.isChecked(),
            "follow_links": self.follow.isChecked(),
            "encrypt_key": self._host.keys.value,
        }
        self.state = "running"
        self._rows_seen = 0
        self.model.removeRows(0, self.model.rowCount())
        self._report = None
        self.run_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress.setText(f"Analyse de {folder}…")
        self._thread = ScanThread(folder, options, runner=runner)
        self._thread.progress.connect(self._on_progress)
        self._thread.succeeded.connect(self._on_done)
        self._thread.failed.connect(self._on_fail)
        self._thread.cancelled.connect(self._on_cancel)
        self._thread.start()

    def cancel(self) -> None:
        if self._thread is not None:
            self._thread.request_stop()

    def _on_progress(self, rel: str, index: int, total: int) -> None:
        self._rows_seen = index
        self.progress.setText(f"{index}/{total}  {rel}")

    def _finish_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

    def _on_done(self, report: object) -> None:
        self._finish_buttons()
        if not isinstance(report, Report):
            self.state = "error"
            self.progress.setText("Rapport inattendu.")
            return
        self._report = report
        self.state = "done"
        minimum = self.severity.currentText()
        order = ["low", "medium", "high", "critical"]
        floor = order.index(minimum)
        for finding in report.findings:
            if order.index(finding.severity) < floor:
                continue
            cells = [
                QStandardItem(finding.severity),
                QStandardItem(finding.rule_id),
                QStandardItem(finding.path),
                QStandardItem(f"{finding.message} — {finding.evidence}"),
            ]
            details = guidance(finding.rule_id)
            cells[3].setToolTip(
                f"{details['limitation']}\n{details['check']}\nEmpreinte : {finding.suppression_fingerprint()}"
            )
            color = QColor(_SEVERITY_COLOR.get(finding.severity, "#e8eaed"))
            cells[0].setForeground(color)
            for cell in cells:
                cell.setEditable(False)
            self.model.appendRow(cells)
        self.table.resizeColumnsToContents()
        integrity = _integrity_lines(report)
        for line in integrity:
            cells = [
                QStandardItem("high"),
                QStandardItem("intégrité"),
                QStandardItem(line.split(": ", 1)[-1].split(",")[0].strip()),
                QStandardItem(line),
            ]
            for cell in cells:
                cell.setEditable(False)
            self.model.appendRow(cells)
        summary = (
            f"{len(report.findings)} finding(s), exit {report.exit_code}. "
            f"Analysés : {report.scanned_files} ; binaires : {len(report.binary_files)} ; "
            f"éléments exclus : {len(report.excluded_entries)} ; "
            f"illisibles : {len(report.unreadable)} ; disparus : {len(report.disappeared_files)}."
        )
        if integrity:
            summary += "\n" + "\n".join(integrity)
        if self._baseline_warning:
            summary = self._baseline_warning + "\n" + summary
        self.progress.setText(summary)
        try:
            self._host.remember_scan(report, summary)
        except OSError as exc:
            self.progress.setText(f"{summary} État non enregistré ({exc}).")

    def _on_fail(self, message: str) -> None:
        self._finish_buttons()
        self.state = "error"
        self.progress.setText(message)

    def _on_cancel(self) -> None:
        self._finish_buttons()
        self.state = "cancelled"
        self.progress.setText("Analyse annulée.")

    def _export(self, kind: str) -> None:
        if self._report is None:
            self.progress.setText("Rien à exporter.")
            return
        suffix = "sarif" if kind == "sarif" else "json"
        path, _ = QFileDialog.getSaveFileName(self, "Exporter", f"sentinel.{suffix}")
        if not path:
            return
        export_report(self._report, Path(path), kind)
        self.progress.setText(f"Exporté : {path}")

    def export_to(self, path: Path, kind: str) -> None:
        if self._report is None:
            raise RuntimeError("pas de rapport")
        export_report(self._report, path, kind)

    def _reveal(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            folder = self.selected_folder()
            if folder is not None:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))
            return
        source = self.proxy.mapToSource(indexes[0])
        rel = self.model.item(source.row(), 2).text()
        folder = self.selected_folder()
        if folder is None:
            return
        target = (folder / rel).parent
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))


class BaselinePage(QWidget):
    def __init__(self, host: MainWindow) -> None:
        super().__init__()
        self._host = host
        self._thread: BaselineThread | None = None
        self.folder = QLineEdit()
        self.out = QLineEdit()
        self.diff = QTextEdit()
        self.diff.setReadOnly(True)
        self.trust = QCheckBox("Je fais confiance à cette baseline non signée")
        self._trust_signed = False
        self.backup = QCheckBox("Conserver une copie .bak")
        self.backup.setChecked(True)
        self.status = QLabel("—")
        browse_folder = QPushButton("Dossier…")
        browse_folder.clicked.connect(self._pick_folder)
        browse_out = QPushButton("Fichier…")
        browse_out.clicked.connect(self._pick_out)
        create = QPushButton("Créer")
        create.clicked.connect(self._create)
        self.cancel_btn = QPushButton("Annuler")
        self.cancel_btn.clicked.connect(self._cancel)
        preview = QPushButton("Voir les écarts")
        preview.clicked.connect(self._preview)
        resign = QPushButton("Resigner")
        resign.clicked.connect(self._resign)
        row1 = QHBoxLayout()
        row1.addWidget(self.folder)
        row1.addWidget(browse_folder)
        row2 = QHBoxLayout()
        row2.addWidget(self.out)
        row2.addWidget(browse_out)
        actions = QHBoxLayout()
        actions.addWidget(create)
        actions.addWidget(self.cancel_btn)
        actions.addWidget(preview)
        actions.addWidget(resign)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Dossier à indexer"))
        layout.addLayout(row1)
        layout.addWidget(QLabel("Fichier baseline"))
        layout.addLayout(row2)
        layout.addLayout(actions)
        layout.addWidget(self.trust)
        layout.addWidget(self.backup)
        layout.addWidget(self.status)
        layout.addWidget(self.diff)

    def _pick_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Dossier")
        if folder:
            self.folder.setText(folder)

    def _pick_out(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Baseline", "baseline.json")
        if path:
            self.out.setText(path)

    def _create(self) -> None:
        folder = Path(self.folder.text().strip() or ".")
        out = Path(self.out.text().strip() or "baseline.json")
        if self._thread is not None and self._thread.isRunning():
            return
        self.status.setText("Création…")
        self._thread = BaselineThread(folder, out, self._host.keys.value)
        self._thread.succeeded.connect(self._created)
        self._thread.failed.connect(self.status.setText)
        self._thread.cancelled.connect(lambda: self.status.setText("Création annulée."))
        self._thread.start()

    def _cancel(self) -> None:
        if self._thread is not None:
            self._thread.request_stop()

    def _created(self, path: str) -> None:
        self.status.setText(f"Baseline écrite : {path}")
        self._host.settings.setValue("baseline_path", path)
        self._host.refresh_dashboard()

    def _preview(self) -> None:
        key = self._host.ensure_key()
        if not key:
            self.status.setText("Clé requise pour la resignature.")
            return
        try:
            preview = preview_resign(Path(self.out.text().strip()), key)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.status.setText(str(exc))
            return
        self.diff.setPlainText(preview.diff_text)
        self.status.setText(preview.message or preview.status)
        self._sync_trust(preview.signed)

    def _sync_trust(self, signed: bool) -> None:
        """Décoche la confiance quand l'état signé change.

        Une case restée cochée pendant qu'elle est désactivée (baseline
        signée, puis de nouveau non signée) signerait sans un geste
        explicite.
        """
        if self._trust_signed != signed:
            self.trust.setChecked(False)
            self._trust_signed = signed
        self.trust.setEnabled(not signed)
        if signed:
            self.trust.setChecked(False)

    def _confirm_resign(self, preview) -> bool:
        from sentinel.integrity import UNSIGNED_RESIGN_WARNING

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning if not preview.signed else QMessageBox.Icon.Question)
        box.setWindowTitle("Resignature")
        box.setText(
            UNSIGNED_RESIGN_WARNING if not preview.signed else "Resignature de cette baseline ?"
        )
        box.setInformativeText("Écarts :\n" + (preview.diff_text or "(aucun)"))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _resign(self) -> None:
        key = self._host.ensure_key()
        if not key:
            self.status.setText("Clé requise pour la resignature.")
            return
        path = Path(self.out.text().strip())
        try:
            preview = preview_resign(path, key)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.status.setText(str(exc))
            return
        self.diff.setPlainText(preview.diff_text)
        self._sync_trust(preview.signed)
        if not preview.signed and not self.trust.isChecked():
            self.status.setText(
                "Baseline non signée : la confiance initiale (--trust-unsigned) est requise. "
                "Le fichier n'a pas été modifié."
            )
            return
        if not self._confirm_resign(preview):
            self.status.setText("Resignature annulée.")
            return
        try:
            backup = commit_resign(
                path,
                key,
                trust_unsigned=self.trust.isChecked(),
                backup=self.backup.isChecked(),
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.status.setText(str(exc))
            return
        self._sync_trust(True)
        extra = f" Copie : {backup}." if backup else ""
        self.status.setText(f"Baseline signée.{extra}\n{preview.diff_text}")
        self._host.settings.setValue("baseline_path", str(path))
        self._host.refresh_dashboard()


class QuarantinePage(QWidget):
    def __init__(self, host: MainWindow) -> None:
        super().__init__()
        self._host = host
        self._put_thread: QuarantineThread | None = None
        self.dest = QLineEdit(str(data_dir() / "quarantine"))
        self.manifest = QLineEdit()
        self._sync_manifest()
        self.dest.textChanged.connect(lambda _text: self._sync_manifest())
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.model = QStandardItemModel(0, 4)
        self.model.setHorizontalHeaderLabels(["Statut", "Origine", "Quarantaine", "SHA-256"])
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        reload_btn = QPushButton("Recharger")
        reload_btn.clicked.connect(self.reload)
        restore_btn = QPushButton("Restaurer la sélection")
        restore_btn.clicked.connect(self.restore_selected)
        put_btn = QPushButton("Mettre en quarantaine…")
        put_btn.clicked.connect(self._put)
        row = QHBoxLayout()
        row.addWidget(reload_btn)
        row.addWidget(restore_btn)
        row.addWidget(put_btn)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Dossier de quarantaine"))
        layout.addWidget(self.dest)
        layout.addWidget(QLabel("Journal"))
        layout.addWidget(self.manifest)
        layout.addLayout(row)
        layout.addWidget(self.table)
        layout.addWidget(self.log)

    def _sync_manifest(self) -> None:
        dest = self.dest.text().strip() or ".sentinel-quarantine"
        self.manifest.setText(str(Path(dest) / "manifest.jsonl"))

    def reload(self) -> None:
        self.model.removeRows(0, self.model.rowCount())
        rows = manifest_rows(Path(self.manifest.text().strip()))
        for row in rows:
            items = [
                QStandardItem(str(row.get("_status") or "done")),
                QStandardItem(str(row.get("original", ""))),
                QStandardItem(str(row.get("quarantined", ""))),
                QStandardItem(str(row.get("sha256", ""))[:16]),
            ]
            for item in items:
                item.setEditable(False)
            self.model.appendRow(items)
        self.log.append(f"{len(rows)} entrée(s).")

    def _refuse_restore_during_quarantine(self) -> bool:
        """Une restauration lancée pendant un move perdrait des lignes du journal."""
        if self._put_thread is None or not self._put_thread.isRunning():
            return False
        message = (
            "Une mise en quarantaine est déjà en cours. "
            "Attendez la fin du déplacement avant de restaurer."
        )
        self.log.append(message)
        QMessageBox.information(self, "Restaurer", message)
        return True

    def _restore_off_gui(
        self, only: set[str] | None, *, dialog: bool
    ) -> tuple[tuple[list, list] | None, int]:
        """Résultat, ou ``(None, échecs)`` si l'appel n'a pas restauré.

        L'interruption de fermeture compte 0 échec de fichier : ce n'est
        pas une restauration vide. Le refus de chemin et le verrou tenu
        comptent 1, comme avant.
        """
        try:
            outcome = _run_off_gui(
                self,
                lambda: restore(
                    Path(self.manifest.text().strip()),
                    Path(self.dest.text().strip()),
                    only=only,
                ),
            )
        except JournalInterrupted:
            _announce_interrupted(self, self.log, "Restaurer", RESTORE_INTERRUPTED_TEXT)
            return None, 0
        except JournalLocked as exc:
            self.log.append(str(exc))
            QMessageBox.warning(self, "Restaurer", str(exc))
            return None, 1
        except UnsafeNtPath as exc:
            message = unsafe_nt_message(exc)
            if dialog:
                QMessageBox.warning(self, "Refus", message)
            else:
                self.log.append(message)
            return None, 1
        return _restore_outcome(outcome), 0

    def restore_selected(self) -> None:
        if self._refuse_restore_during_quarantine():
            return
        indexes = self.table.selectionModel().selectedRows()
        only: set[str] | None = None
        if indexes:
            only = set()
            for index in indexes:
                only.add(self.model.item(index.row(), 1).text())
        answer = QMessageBox.question(
            self,
            "Restaurer",
            "Restaurer les fichiers sélectionnés à leur emplacement d'origine ?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        parsed, _failed = self._restore_off_gui(only, dialog=True)
        if parsed is None:
            return
        restored, failures = parsed
        self.log.append(f"Restaurés : {len(restored)}. Échecs : {len(failures)}.")
        self.reload()

    def restore_without_dialog(self, originals: set[str] | None = None) -> tuple[int, int]:
        if self._refuse_restore_during_quarantine():
            return 0, 1
        parsed, failed = self._restore_off_gui(originals, dialog=False)
        if parsed is None:
            return 0, failed
        restored, failures = parsed
        self.reload()
        return len(restored), len(failures)

    def _put(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Fichiers à isoler")
        if not paths:
            return
        self.quarantine_files([Path(path) for path in paths])

    def quarantine_files(self, paths: list[Path]) -> None:
        """Isole ``paths``. La classe UNC du dossier tourne dans un ``QThread``."""
        if self._put_thread is not None and self._put_thread.isRunning():
            message = "Une mise en quarantaine est déjà en cours. Attendez la fin du déplacement."
            self.log.append(message)
            QMessageBox.information(self, "Quarantaine", message)
            return
        thread = QuarantineThread(
            paths,
            Path(self.dest.text().strip()),
            Path(self.manifest.text().strip()),
        )
        retain_background_thread(thread)
        thread.completed.connect(self._on_quarantine_done)
        thread.refused.connect(self._on_quarantine_refused)
        thread.failed.connect(self._on_quarantine_refused)
        thread.start()
        self._put_thread = thread

    def discard_result_signals(self) -> None:
        """Le déplacement continue. L'interface n'affiche plus son résultat."""
        if self._put_thread is not None:
            detach_result_signals(self._put_thread)

    def _on_quarantine_done(self, records: object, failures: object) -> None:
        moved = len(records) if isinstance(records, list) else 0
        failed = len(failures) if isinstance(failures, list) else 0
        self.log.append(f"Déplacés : {moved}. Échecs : {failed}.")
        self.reload()

    def _on_quarantine_refused(self, message: str) -> None:
        QMessageBox.warning(self, "Refus", message)
        self.log.append(message)


class WatchPage(QWidget):
    def __init__(self, host: MainWindow) -> None:
        super().__init__()
        self._host = host
        self._thread: WatchThread | None = None
        self._follow: ScanThread | None = None
        self._pending: dict | None = None
        self.folder = QLineEdit()
        self.interval = QLineEdit("2.0")
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        browse = QPushButton("Dossier…")
        browse.clicked.connect(self._pick)
        self.start_btn = QPushButton("Démarrer")
        self.start_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Arrêter")
        self.stop_btn.clicked.connect(self.stop)
        self.stop_btn.setEnabled(False)
        row = QHBoxLayout()
        row.addWidget(self.folder)
        row.addWidget(browse)
        actions = QHBoxLayout()
        actions.addWidget(QLabel("Intervalle (s)"))
        actions.addWidget(self.interval)
        actions.addWidget(self.start_btn)
        actions.addWidget(self.stop_btn)
        layout = QVBoxLayout(self)
        layout.addLayout(row)
        layout.addLayout(actions)
        layout.addWidget(self.log)
        self.running = False

    def _pick(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Surveiller")
        if folder:
            self.folder.setText(folder)

    def start(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        folder = Path(self.folder.text().strip() or ".")
        if not folder.is_dir():
            self.log.append(f"Pas un dossier : {folder}")
            return
        try:
            interval = float(self.interval.text().strip() or "2")
        except ValueError:
            self.log.append("Intervalle invalide.")
            return
        if interval <= 0:
            self.log.append("L'intervalle doit être supérieur à 0.")
            return
        self.running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.log.append(f"Surveillance de {folder}.")
        self._host.set_watch_running(True, str(folder))
        self._thread = WatchThread(folder, interval=interval)
        self._thread.changed.connect(self._on_change)
        self._thread.failed.connect(self._on_failed)
        self._thread.stopped.connect(self._on_stopped)
        self._thread.start()

    def stop(self) -> None:
        self._pending = None
        if self._follow is not None:
            self._follow.request_stop()
        if self._thread is not None:
            self._thread.request_stop()

    def _on_change(self, diff: object) -> None:
        if not isinstance(diff, dict):
            return
        added = ", ".join(diff.get("added") or []) or "—"
        self.log.append(f"Changement. Ajouts : {added}")
        if self._follow is not None and self._follow.isRunning():
            self._pending = diff
            return
        self._scan_change(diff)

    def _scan_change(self, diff: dict) -> None:
        """Lit les widgets ici (thread GUI), puis scanne dans un QThread."""
        folder = Path(self.folder.text().strip() or ".")
        base_text = self._host.scan.baseline.text().strip()
        base = Path(base_text) if base_text else None
        loaded, error, warning = load_baseline_for_scan(
            base,
            self._host.keys.value,
            require_signed=self._host.scan.require_signed.isChecked(),
            allow_unverified=self._host.scan.allow_unverified.isChecked(),
        )
        if warning:
            self.log.append(warning)
        if error:
            self.log.append(error)
            return
        options = {
            "baseline": loaded,
            "with_anomaly": self._host.scan.anomaly.isChecked(),
            "follow_links": self._host.scan.follow.isChecked(),
            "encrypt_key": self._host.keys.value,
        }
        frozen = dict(diff)
        self._follow = ScanThread(folder, options)
        self._follow.succeeded.connect(
            lambda report, payload=frozen: self._scanned(payload, report)
        )
        self._follow.failed.connect(self.log.append)
        self._follow.cancelled.connect(lambda: self.log.append("Analyse de surveillance annulée."))
        self._follow.finished.connect(self._follow_done)
        self._follow.start()

    def _scanned(self, diff: dict, report: object) -> None:
        if isinstance(report, Report):
            self._host.notify_findings(diff, report)

    def _follow_done(self) -> None:
        pending = self._pending
        self._pending = None
        if pending is not None and self.running:
            self._scan_change(pending)

    def _on_failed(self, message: str) -> None:
        self.log.append(message)
        self._on_stopped(0)

    def _on_stopped(self, count: int) -> None:
        self.running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log.append(f"Surveillance arrêtée ({count} changement(s) traités).")
        self._host.set_watch_running(False, "")


class DashboardPage(QWidget):
    def __init__(self, host: MainWindow) -> None:
        super().__init__()
        self._host = host
        self.scan_label = QLabel("Aucun scan enregistré.")
        self.scan_label.setWordWrap(True)
        self.base_label = QLabel("Baseline : —")
        self.base_label.setWordWrap(True)
        self.watch_label = QLabel("Surveillance : arrêtée.")
        refresh = QPushButton("Actualiser")
        refresh.clicked.connect(self.refresh)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Dernier scan"))
        layout.addWidget(self.scan_label)
        layout.addWidget(QLabel("Intégrité"))
        layout.addWidget(self.base_label)
        layout.addWidget(QLabel("Surveillance"))
        layout.addWidget(self.watch_label)
        layout.addWidget(refresh)
        layout.addStretch(1)

    def refresh(self) -> None:
        path = data_dir() / "last_scan.json"
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
            self.scan_label.setText(f"{payload.get('summary', '—')}\n{payload.get('when', '')}")
        else:
            self.scan_label.setText("Aucun scan enregistré.")
        raw = self._host.settings.value("baseline_path", "")
        text = raw if isinstance(raw, str) else ""
        view = describe_baseline(Path(text) if text else None, self._host.keys.value)
        bits = [
            f"Présente : {'oui' if view.present else 'non'}",
            f"Signée : {'oui' if view.signed else 'non'}",
            f"Vérifiée : {'oui' if view.verified else 'non'}",
            f"Resignée depuis non signée : {'oui' if view.resigned_from_unsigned else 'non'}",
            view.message,
        ]
        if view.notice:
            bits.append(view.notice)
        self.base_label.setText("\n".join(bit for bit in bits if bit))
        self.watch_label.setText(self._host.watch_status_text())


class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings | None = None) -> None:
        super().__init__()
        self.setWindowTitle(f"Sentinel {__version__}")
        self.resize(1100, 720)
        self.settings = settings or QSettings("Sentinel", "Sentinel")
        register_settings(self.settings)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            _install_exit_hook(app)
        self.keys = SessionKey()
        self._watch_running = False
        self._watch_folder = ""
        self._tray: QSystemTrayIcon | None = None

        self.dashboard = DashboardPage(self)
        self.scan = ScanPage(self)
        self.baseline = BaselinePage(self)
        self.quarantine = QuarantinePage(self)
        self.watch = WatchPage(self)
        self.stack = QStackedWidget()
        for page in (self.dashboard, self.scan, self.baseline, self.quarantine, self.watch):
            self.stack.addWidget(page)

        nav = QVBoxLayout()
        self._nav_buttons: list[QPushButton] = []
        for index, label in enumerate(
            ("Tableau", "Analyse", "Intégrité", "Quarantaine", "Surveillance")
        ):
            button = QPushButton(label)
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, i=index: self._show(i))
            nav.addWidget(button)
            self._nav_buttons.append(button)
        key_btn = QPushButton("Clé de session…")
        key_btn.clicked.connect(self.prompt_key)
        forget = QPushButton("Oublier la clé")
        forget.clicked.connect(self._forget_key)
        nav.addStretch(1)
        nav.addWidget(key_btn)
        nav.addWidget(forget)
        nav_w = QFrame()
        nav_w.setLayout(nav)
        nav_w.setFixedWidth(180)

        body = QHBoxLayout()
        body.addWidget(nav_w)
        body.addWidget(self.stack, 1)
        central = QWidget()
        central.setLayout(body)
        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self._show(0)
        self._setup_tray()
        saved = self.settings.value("baseline_path", "")
        if saved:
            self.baseline.out.setText(str(saved))
            self.scan.baseline.setText(str(saved))
        self.refresh_dashboard()
        self._recover_quarantine_journal()

    def _recover_quarantine_journal(self) -> None:
        """Reprise au démarrage de l'interface. Aucun fichier n'est supprimé.

        L'attente du verrou tourne dans un fil : la fenêtre d'attente
        reste visible si un autre processus déplace un fichier.
        """
        raw = self.quarantine.manifest.text().strip()
        if not raw:
            return
        try:
            issues = _run_off_gui(self, lambda: init_engine([Path(raw)]))
        except JournalInterrupted:
            _announce_interrupted(
                self,
                self.quarantine.log,
                "Journal de quarantaine",
                RECOVERY_INTERRUPTED_TEXT,
            )
            return
        except JournalLocked as exc:
            text = str(exc)
            self.quarantine.log.append(text)
            QMessageBox.warning(self, "Journal de quarantaine", text)
            return
        if not isinstance(issues, list) or not issues:
            return
        text = format_journal_issues(issues)
        self.quarantine.log.append(text)
        QMessageBox.warning(self, "Journal de quarantaine incohérent", text)

    def _show(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self._nav_buttons):
            button.setChecked(i == index)
        if index == 0:
            self.refresh_dashboard()

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.statusBar().showMessage("Pas d'icône de barre sur cette session.")
            QApplication.setQuitOnLastWindowClosed(True)
            return
        tray = QSystemTrayIcon(_tray_icon(), self)
        tray.setToolTip("Sentinel")
        menu_show = QAction("Ouvrir", self)
        menu_show.triggered.connect(self._show_window)
        menu_watch = QAction("Arrêter la surveillance", self)
        menu_watch.triggered.connect(self.watch.stop)
        menu_quit = QAction("Quitter", self)
        menu_quit.triggered.connect(request_graceful_quit)
        menu = QMenu()
        menu.addAction(menu_show)
        menu.addAction(menu_watch)
        menu.addSeparator()
        menu.addAction(menu_quit)
        tray.setContextMenu(menu)
        tray.activated.connect(
            lambda reason: (
                self._show_window() if reason == QSystemTrayIcon.ActivationReason.Trigger else None
            )
        )
        tray.show()
        self._tray = tray
        QApplication.setQuitOnLastWindowClosed(False)

    def _show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event) -> None:  # noqa: N802
        running = self.quarantine._put_thread
        if running is not None and running.isRunning():
            event.ignore()
            QMessageBox.warning(
                self,
                "Quarantaine en cours",
                "Une mise en quarantaine est en cours. "
                "La fenêtre reste ouverte pour ne pas interrompre le déplacement.",
            )
            return
        if self._tray is not None and self.isVisible():
            event.ignore()
            self.hide()
            self.statusBar().showMessage("Sentinel reste dans la barre.")
            return
        self.scan.discard_note_results()
        self.quarantine.discard_result_signals()
        super().closeEvent(event)

    def prompt_key(self) -> None:
        existing = self.keys.value or self.keys.load_keyring()
        text, ok = QInputDialog.getText(
            self,
            "Clé HMAC",
            "Clé de signature pour cette session (non enregistrée dans les réglages) :",
            QLineEdit.EchoMode.Password,
            "",
        )
        if not ok:
            return
        if not text and existing:
            self.statusBar().showMessage("Clé de session inchangée.")
            return
        self.keys.set(text)
        if self.keys.keyring_available() and text:
            answer = QMessageBox.question(
                self,
                "Trousseau",
                "Enregistrer cette clé dans le trousseau du système (keyring) ?",
            )
            if answer == QMessageBox.StandardButton.Yes:
                error = self.keys.store_keyring(text)
                if error:
                    QMessageBox.warning(self, "Trousseau", error)
                else:
                    self.statusBar().showMessage("Clé enregistrée dans le trousseau.")
                    return
        self.statusBar().showMessage("Clé gardée en mémoire pour cette session.")

    def ensure_key(self) -> str | None:
        if self.keys.value:
            return self.keys.value
        loaded = self.keys.load_keyring()
        if loaded:
            return loaded
        self.prompt_key()
        return self.keys.value

    def _forget_key(self) -> None:
        self.keys.clear()
        self.statusBar().showMessage("Clé de session effacée.")

    def remember_scan(self, report: Report, summary: str) -> None:
        payload = {
            "summary": summary,
            "when": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "exit_code": report.exit_code,
            "findings": len(report.findings),
        }
        path = data_dir() / "last_scan.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.refresh_dashboard()

    def refresh_dashboard(self) -> None:
        self.dashboard.refresh()

    def set_watch_running(self, running: bool, folder: str) -> None:
        self._watch_running = running
        self._watch_folder = folder
        self.refresh_dashboard()

    def watch_status_text(self) -> str:
        if self._watch_running:
            return f"Surveillance active : {self._watch_folder}"
        return "Surveillance : arrêtée."

    def notify_findings(self, diff: dict, report: Report) -> None:
        count = len(report.findings)
        text = (
            f"{count} finding(s). "
            f"Ajouts {len(diff.get('added') or [])}, "
            f"modifiés {len(diff.get('modified') or [])}."
        )
        self.statusBar().showMessage(text)
        if self._tray is not None and count:
            self._tray.showMessage("Sentinel", text, QSystemTrayIcon.MessageIcon.Warning, 5000)


def main(argv: list[str] | None = None) -> int:
    del argv
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication(sys.argv)
    app.setApplicationName("Sentinel")
    app.setOrganizationName("Sentinel")
    app.setStyle("Fusion")
    app.setStyleSheet(
        """
        QWidget { background: #1c1f24; color: #e8eaed; font-size: 13px; }
        QLineEdit, QTextEdit, QListWidget, QTableView, QComboBox {
            background: #262b33; border: 1px solid #3a414c; padding: 4px; border-radius: 4px;
        }
        QPushButton {
            background: #2e3540; border: 1px solid #3a414c; padding: 6px 10px; border-radius: 4px;
        }
        QPushButton:checked { background: #3d8bfd; color: white; }
        QHeaderView::section { background: #262b33; padding: 4px; border: 0; }
        """
    )
    _install_exit_hook(app)
    window = MainWindow()
    window.show()
    return run_event_loop(app)


def run_event_loop(app: QApplication) -> int:
    """Boucle principale. Une fermeture déjà demandée pendant la reprise sort tout de suite."""
    if _quit_in_progress:
        wait_for_background_threads()
        return 0
    code = app.exec()
    wait_for_background_threads()
    return int(code)


__all__ = ["MainWindow", "main"]
