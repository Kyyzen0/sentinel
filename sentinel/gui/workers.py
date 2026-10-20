"""Travaux longs hors du thread Qt.

La classification d'un chemin (``live_dest_class``) peut résoudre un
hôte UNC, jusqu'à ``UNC_DNS_TIMEOUT``. Elle ne s'exécute que dans un
``QThread`` : ``PathNoteThread`` pour l'avertissement d'un dossier,
``QuarantineThread`` pour l'isolement. Le thread de l'interface ne fait
qu'afficher le résultat.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from sentinel.platform import OperationCancelled, UnsafeNtPath, unsafe_nt_message
from sentinel.scanner import scan_folder
from sentinel.watch import has_watchdog, watch_event, watch_polling

from .locations import sensitive_scan_note
from .services import create_baseline, quarantine


class ScanThread(QThread):
    progress = Signal(str, int, int)
    succeeded = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, folder: Path, options: dict, runner: Callable | None = None) -> None:
        super().__init__()
        self._folder = folder
        self._options = options
        self._runner = runner
        self._stop = threading.Event()

    def request_stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            if self._runner is not None:
                report = self._runner(
                    self._stop.is_set,
                    lambda rel, index, total: self.progress.emit(rel, index, total),
                )
            else:
                report = scan_folder(
                    self._folder,
                    on_progress=lambda rel, index, total: self.progress.emit(rel, index, total),
                    cancel=self._stop.is_set,
                    **self._options,
                )
        except OperationCancelled:
            self.cancelled.emit()
            return
        except UnsafeNtPath as exc:
            self.failed.emit(unsafe_nt_message(exc))
            return
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(report)


class BaselineThread(QThread):
    succeeded = Signal(str)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, folder: Path, out: Path, key: str | None) -> None:
        super().__init__()
        self._folder = folder
        self._out = out
        self._key = key
        self._stop = threading.Event()

    def request_stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            create_baseline(self._folder, self._out, self._key, cancel=self._stop.is_set)
        except OperationCancelled:
            self.cancelled.emit()
            return
        except UnsafeNtPath as exc:
            self.failed.emit(unsafe_nt_message(exc))
            return
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(str(self._out))


class WatchThread(QThread):
    """Surveille le disque et émet ``changed``.

    Le slot vit dans le thread de l'interface : lire des widgets ou
    afficher une notification depuis ``run`` n'est pas sûr. Le scan qui
    suit un changement est lancé par ce slot, pas ici.
    """

    changed = Signal(object)
    failed = Signal(str)
    stopped = Signal(int)

    def __init__(self, folder: Path, *, interval: float) -> None:
        super().__init__()
        self._folder = folder
        self._interval = interval
        self._stop = threading.Event()

    def request_stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        def _emit(diff: dict) -> None:
            self.changed.emit(diff)

        try:
            if has_watchdog():
                count = watch_event(self._folder, _emit, stop=self._stop.is_set)
            else:
                count = watch_polling(
                    self._folder,
                    self._interval,
                    _emit,
                    stop=self._stop.is_set,
                )
        except UnsafeNtPath as exc:
            self.failed.emit(unsafe_nt_message(exc))
            return
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.stopped.emit(count)


class PathNoteThread(QThread):
    """Avertissement de chemin sensible, hors du thread Qt.

    ``request_id`` identifie la demande. L'interface ignore un résultat
    qui n'est plus le dernier, ou qui arrive après la fermeture.
    """

    noted = Signal(int, str, str)
    failed = Signal(int, str)

    def __init__(self, folder: Path, request_id: int) -> None:
        super().__init__()
        self._folder = folder
        self._request_id = request_id

    def run(self) -> None:
        try:
            note = sensitive_scan_note(self._folder) or ""
        except UnsafeNtPath as exc:
            self.failed.emit(self._request_id, unsafe_nt_message(exc))
            return
        except Exception as exc:
            self.failed.emit(self._request_id, str(exc))
            return
        self.noted.emit(self._request_id, str(self._folder), note)


class QuarantineThread(QThread):
    """Isole des fichiers. La classe du dossier est calculée ici, pas dans l'UI."""

    completed = Signal(object, object)
    refused = Signal(str)
    failed = Signal(str)

    def __init__(self, paths: list[Path], dest: Path, manifest: Path) -> None:
        super().__init__()
        self._paths = paths
        self._dest = dest
        self._manifest = manifest

    def run(self) -> None:
        try:
            note = sensitive_scan_note(self._dest)
        except UnsafeNtPath as exc:
            self.refused.emit(unsafe_nt_message(exc))
            return
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        if note and "critique" in note:
            self.refused.emit(note)
            return
        try:
            records, failures = quarantine(self._paths, self._dest, self._manifest)
        except UnsafeNtPath as exc:
            self.refused.emit(unsafe_nt_message(exc))
            return
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.completed.emit(records, failures)
