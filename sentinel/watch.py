"""Surveillance temps réel d'un dossier.

Deux backends :
  1. `watchdog` (optionnel) : FSEvents sur macOS, inotify sur Linux. Événementiel,
     instantané. Sort de la philosophie « stdlib only ».
  2. Polling : le même `os.walk(onerror=…)` que le scanner, plus un contrôle
     de contenu. Stdlib only.

Sur tout changement (ou nouveau fichier), relance un scan et imprime le
diff (added / removed / modified) sur stdout. Un dossier illisible est
signalé (même sémantique que l'exit 3 du scan). S'arrête sur Ctrl-C / SIGTERM.

Coût du contrôle de contenu
---------------------------
- Fichiers ≤ 8 Mio : SHA-256 en flux à chaque tour. Un fichier de 2 Mio
  réécrit à taille égale avec mtime restauré est donc vu au tour suivant.
- Fichiers plus gros : empreinte échantillonnée (début, milieu, fin,
  64 Kio chacun) à chaque tour. Le SHA-256 complet est planifié **par
  fichier** (au plus 10 instantanés depuis le dernier hash complet), et
  le dernier hash complet est recopié sur les tours « échantillon ».
  Une modification hors des trois fenêtres est donc comparée à ce hash,
  même si un autre fichier a changé entre-temps. On ne relit jamais tout
  un disque à chaque tick.
"""

from __future__ import annotations

import hashlib
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# SHA-256 complet à chaque tour, jusqu'à cette taille. 8 Mio couvre le
# cas « 2 Mio, même taille, mtime restauré » sans relire les gros
# binaires en continu. Au-delà : échantillon + hash complet par fichier.
_WATCH_FULL_HASH_MAX = 8 * 1024 * 1024
_WATCH_SAMPLE_BYTES = 64 * 1024
# Nombre d'instantanés de CE fichier entre deux SHA-256 complets.
_WATCH_FULL_EVERY = 10


@dataclass(frozen=True)
class _FileStamp:
    path: str
    mtime: float
    size: int
    digest: str = ""
    # Empreinte partielle des fichiers > _WATCH_FULL_HASH_MAX. Vide quand
    # le fichier est assez petit pour un SHA-256 à chaque tour.
    sample: str = ""
    # Instantanés de ce fichier depuis son dernier SHA-256 complet.
    # 0 = ce stamp porte un hash frais. Défaut 0 : les stamps construits
    # par les tests (chemin, mtime, taille) restent valides.
    full_age: int = 0


class _Snapshot(dict[str, _FileStamp]):
    """Dict chemin → stamp, plus les chemins illisibles de ce tour."""

    def __init__(self) -> None:
        super().__init__()
        self.unreadable: list[str] = []


def _hash_stream(path: Path, size: int) -> str:
    """SHA-256 d'au plus ``size`` octets. Lève OSError si illisible."""
    h = hashlib.sha256()
    remaining = size
    with path.open("rb") as fh:
        while remaining > 0:
            chunk = fh.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def _sample_digest(path: Path, size: int) -> str:
    """Empreinte bornée : 64 Kio en tête, au milieu et en queue.

    Le coût est constant (≤ 192 Kio lus) quelle que soit la taille.
    Une modification strictement entre les fenêtres n'est pas vue ici ;
    le hash complet périodique la rattrape.
    """
    h = hashlib.sha256()
    h.update(size.to_bytes(8, "big"))
    span = _WATCH_SAMPLE_BYTES
    offsets = [0]
    if size > span:
        offsets.append(max(0, size // 2 - span // 2))
        offsets.append(max(0, size - span))
    with path.open("rb") as fh:
        for off in offsets:
            fh.seek(off)
            chunk = fh.read(span)
            h.update(off.to_bytes(8, "big"))
            h.update(chunk)
    return h.hexdigest()


def _content_fingerprint(path: Path, size: int, *, full_hash: bool) -> tuple[str, str]:
    """``(digest complet ou "", échantillon ou "")``.

    ≤ 8 Mio : digest complet à chaque appel. Au-delà : échantillon, et
    digest complet seulement si ``full_hash`` (un tour sur dix).
    """
    if size <= _WATCH_FULL_HASH_MAX:
        return _hash_stream(path, size), ""
    sample = _sample_digest(path, size)
    digest = _hash_stream(path, size) if full_hash else ""
    return digest, sample


def _needs_full_hash(size: int, prev: _FileStamp | None) -> bool:
    """SHA-256 complet : petit fichier, premier tour, ou quota du fichier.

    Le quota est l'âge de CE fichier, pas un compteur global de tours.
    Un autre fichier qui change ne remet pas l'âge à zéro.
    """
    if size <= _WATCH_FULL_HASH_MAX or prev is None or not prev.digest:
        return True
    return prev.full_age + 1 >= _WATCH_FULL_EVERY


def _snapshot(
    folder: Path,
    *,
    prev: Mapping[str, _FileStamp] | None = None,
) -> _Snapshot:
    """Instantané des fichiers réguliers.

    Réutilise le parcours du scanner (``os.walk(onerror=…)``, symlinks
    ignorés). Un dossier en mode 000 atterrit dans ``snap.unreadable``
    au lieu d'être sauté en silence par ``rglob``.

    ``prev`` porte le dernier hash complet connu de chaque fichier. Sur
    un tour échantillon, ce hash est recopié : le tour suivant peut
    encore le comparer, même si l'instantané annoncé a été remplacé
    parce qu'un autre fichier a changé.
    """
    from .scanner import _iter_text_files

    snap = _Snapshot()
    unreadable: list[str] = []
    for p in _iter_text_files(folder, unreadable=unreadable):
        rel = p.relative_to(folder).as_posix()
        previous = prev.get(rel) if prev is not None else None
        try:
            st = p.stat()
            full = _needs_full_hash(st.st_size, previous)
            digest, sample = _content_fingerprint(p, st.st_size, full_hash=full)
        except OSError:
            if rel not in unreadable:
                unreadable.append(rel)
            continue
        if full or previous is None:
            age = 0
        else:
            # Tour échantillon : on garde le dernier SHA-256 complet.
            digest = previous.digest
            age = previous.full_age + 1
        snap[rel] = _FileStamp(
            path=rel,
            mtime=st.st_mtime,
            size=st.st_size,
            digest=digest,
            sample=sample,
            full_age=age,
        )
    snap.unreadable = unreadable
    return snap


def _report_unreadable(paths: list[str], seen: set[str], out: list[str] | None) -> None:
    """Notice alignée sur le scan : chemin listé, sémantique exit 3."""
    fresh = [p for p in paths if p not in seen]
    if not fresh:
        return
    seen.update(fresh)
    if out is not None:
        out.extend(fresh)
    print(
        f"\n⚠ {len(fresh)} chemin(s) illisible(s) — surveillance incomplète "
        "(exit 3). Le contenu n'a pas pu être lu.",
        file=sys.stderr,
    )
    for rel in fresh:
        print(f"  - {rel}", file=sys.stderr)


def _unreadable_of(snap: dict[str, _FileStamp]) -> list[str]:
    found = getattr(snap, "unreadable", None)
    return list(found) if isinstance(found, list) else []


def _content_changed(prev: _FileStamp, cur: _FileStamp) -> bool:
    """Compare les empreintes seulement quand les deux côtés en ont une.

    Le digest d'un gros fichier est le dernier SHA-256 complet connu
    (recopié sur les tours échantillon). Un hash frais est donc comparé
    à ce digest, pas à une chaîne vide. L'échantillon, lui, ne se
    compare qu'à un autre échantillon.
    """
    if prev.digest and cur.digest and prev.digest != cur.digest:
        return True
    if prev.sample and cur.sample and prev.sample != cur.sample:
        return True
    return False


def _diff_snapshots(
    prev: dict[str, _FileStamp], cur: dict[str, _FileStamp]
) -> dict[str, list[str]]:
    added = sorted(set(cur) - set(prev))
    removed = sorted(set(prev) - set(cur))
    modified: list[str] = []
    for p in set(cur) & set(prev):
        if (
            cur[p].mtime != prev[p].mtime
            or cur[p].size != prev[p].size
            or _content_changed(prev[p], cur[p])
        ):
            modified.append(p)
    prev_u = set(_unreadable_of(prev))
    new_unreadable = [p for p in _unreadable_of(cur) if p not in prev_u]
    return {
        "added": added,
        "removed": removed,
        "modified": sorted(modified),
        "unreadable": new_unreadable,
    }


def watch_polling(
    folder: Path,
    interval: float,
    on_change: Callable[[dict], None],
    max_iterations: int | None = None,
    debounce: float = 0.0,
    *,
    # P4-C : horloge et sleep injectables. Les tests passent un fake
    # clock + un fake sleep pour ne pas dépendre de `time.sleep`
    # (qui rend les tests flaky sur CI chargés).
    sleep: Callable[[float], None] = time.sleep,
    # Chemins illisibles vus pendant la surveillance (dédupliqués).
    # La signature positionnelle ne change pas : argument nommé seulement.
    unreadable_out: list[str] | None = None,
    stop: Callable[[], bool] | None = None,
) -> int:
    """Boucle polling : snapshot → diff → callback, jusqu'à KeyboardInterrupt,
    `SIGTERM` ou `max_iterations` itérations.

    P3-3 (S) : si `debounce > 0`, on attend que le snapshot reste **inchangé
    pendant `debounce` secondes consécutives** avant de déclencher le
    callback. Cela collapse la rafale d'événements générée par une
    sauvegarde d'éditeur (write → flush → chmod → etc.) en un seul
    callback. C'est ce que l'OS fait déjà pour inotify/FSEvents, mais en
    polling on doit le faire à la main.

    P4-C : `sleep` est injectable. En prod, on utilise `time.sleep`. Dans
    les tests, on peut passer un sleep déterministe (qui consomme les
    "ticks" d'une FakeClock) pour rendre la boucle déterministe.

    Lève KeyboardInterrupt (propagée). Retourne le nombre d'itérations
    effectuées.
    """
    import signal
    import threading

    seen_unreadable: set[str] = set()

    # `last` avance à CHAQUE instantané : l'âge du hash complet est par
    # fichier et ne se remet pas à zéro quand le diff est vide.
    # `reported` est le dernier état annoncé. On diff contre lui, pour
    # qu'un hash complet tardif soit comparé au dernier digest connu et
    # non à un stamp « échantillon » qui aurait perdu ce digest.
    last = _snapshot(folder)
    reported = last
    _report_unreadable(_unreadable_of(reported), seen_unreadable, unreadable_out)
    iters = 0
    stop_requested = {"flag": False}

    def _halt() -> bool:
        return stop_requested["flag"] or (stop is not None and stop())

    # SIGTERM ne peut être installé que depuis le main thread (limitation
    # Python). On installe le handler seulement dans ce cas — sinon, le
    # polling s'arrête uniquement sur SIGINT / KeyboardInterrupt.
    prev_handler = None
    if threading.current_thread() is threading.main_thread():

        def _handle_sigterm(signum, frame):
            stop_requested["flag"] = True

        prev_handler = signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        while not _halt():
            # IMPORTANT : on check `max_iterations` ICI (avant le sleep)
            # sinon on boucle à l'infini quand aucune modification n'est
            # détectée (le `continue` skip le check en fin d'itération).
            if max_iterations is not None and iters >= max_iterations:
                return iters
            try:
                sleep(interval)
            except KeyboardInterrupt:
                raise
            iters += 1
            cur = _snapshot(folder, prev=last)
            last = cur
            step = _diff_snapshots(reported, cur)
            _report_unreadable(step["unreadable"], seen_unreadable, unreadable_out)
            if not any(step.values()):
                continue
            if debounce > 0:
                # Attend que la situation se stabilise. On attend qu'un
                # nouveau snapshot soit IDENTIQUE au précédent (modifications
                # terminées). On NE compare PAS à `reported` — sinon on ne
                # verrait jamais de stabilité tant que le fichier bouge.
                stable_until = iters * interval + debounce  # P4-C : horloge virtuelle
                last_seen = cur
                while (iters * interval) < stable_until and not _halt():
                    try:
                        sleep(interval)
                    except KeyboardInterrupt:
                        raise
                    iters += 1
                    latest = _snapshot(folder, prev=last)
                    last = latest
                    step = _diff_snapshots(last_seen, latest)
                    _report_unreadable(step["unreadable"], seen_unreadable, unreadable_out)
                    if any(step.values()):
                        # Encore un changement, reset le timer.
                        stable_until = iters * interval + debounce
                        last_seen = latest
                        cur = latest
                    else:
                        break
            # Diff contre l'état d'avant cette rafale, pas contre le premier
            # snapshot intermédiaire : un fichier créé pendant le debounce
            # doit apparaître dans le callback, sinon `reported` saute jusqu'à
            # l'état final et ce fichier n'est plus jamais signalé.
            diff = _diff_snapshots(reported, cur)
            if any(diff.values()):
                on_change(diff)
                reported = cur
    finally:
        # Restaure le handler d'origine (ne pas laisser notre handler
        # fuiter si watch_polling est appelé plusieurs fois).
        if prev_handler is not None:
            signal.signal(signal.SIGTERM, prev_handler)
    return iters


# Tentative d'import de watchdog (optionnel).
try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore

    _HAS_WATCHDOG = True
except ImportError:
    _HAS_WATCHDOG = False


def has_watchdog() -> bool:
    return _HAS_WATCHDOG


def _make_watchdog_handler(
    folder: Path,
    on_change: Callable[[dict], None],
    debounce: float = 0.0,
    unreadable_out: list[str] | None = None,
) -> FileSystemEventHandler:  # type: ignore
    """Handler watchdog : déclenche un diff à chaque événement FS.

    `debounce > 0` regroupe les événements rapprochés : on attend que le
    filesystem soit stable pendant `debounce` secondes avant de scanner.
    Sans ça, une sauvegarde d'éditeur (write + chmod + rename) déclenchait
    plusieurs snapshots complets de l'arbre par événement.
    """
    import threading
    import time as _time

    prev = _snapshot(folder)
    seen_unreadable: set[str] = set()
    _report_unreadable(_unreadable_of(prev), seen_unreadable, unreadable_out)
    lock = threading.Lock()
    state = {"pending": False, "last": 0.0, "count": 0}

    class _Handler(FileSystemEventHandler):  # type: ignore
        def __init__(self) -> None:
            super().__init__()
            # Exposé pour que `watch_event` puisse lire le compteur et
            # l'état « événement en attente ».
            self.state = state
            self.lock = lock

        def on_any_event(self, event) -> None:  # noqa: N802
            with lock:
                state["pending"] = True
                state["last"] = _time.monotonic()

        def flush(self) -> None:
            """Traite l'événement en attente si le FS est stable."""
            nonlocal prev
            with lock:
                if not state["pending"]:
                    return
                if debounce > 0 and (_time.monotonic() - state["last"]) < debounce:
                    return
                state["pending"] = False
            cur = _snapshot(folder)
            diff = _diff_snapshots(prev, cur)
            _report_unreadable(diff["unreadable"], seen_unreadable, unreadable_out)
            prev = cur
            if any(diff.values()):
                state["count"] += 1
                on_change(diff)

    return _Handler()


def watch_event(
    folder: Path,
    on_change: Callable[[dict], None],
    max_iterations: int | None = None,
    debounce: float = 0.0,
    *,
    unreadable_out: list[str] | None = None,
    stop: Callable[[], bool] | None = None,
) -> int:
    """Surveillance événementielle via watchdog. Lève RuntimeError si
    watchdog n'est pas installé.

    `max_iterations` compte les changements traités (comme le nombre de tours
    du polling) : la boucle s'arrête une fois ce quota atteint. Retourne le
    nombre de changements traités.

    P3-3 : `debounce` est désormais honoré ici aussi. Il n'était câblé que
    sur le polling, donc `--debounce` était sans effet dès que `watchdog`
    était installé — c'est-à-dire dans le cas nominal.
    """
    if not _HAS_WATCHDOG:
        raise RuntimeError(
            "watchdog n'est pas installé ; utilisez watch_polling() ou pip install watchdog"
        )

    handler = _make_watchdog_handler(
        folder, on_change, debounce=debounce, unreadable_out=unreadable_out
    )
    observer = Observer()
    observer.schedule(handler, str(folder), recursive=True)
    observer.start()
    tick = min(0.2, max(debounce / 2, 0.05))
    try:
        while observer.is_alive():
            if stop is not None and stop():
                break
            if max_iterations is not None and handler.state["count"] >= max_iterations:
                break
            time.sleep(tick)
            handler.flush()
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
    return handler.state["count"]
