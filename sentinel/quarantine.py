"""Quarantaine read-only : déplace (mv) des fichiers suspects dans un dossier
de quarantaine, les rend non-modifiables (chmod 0444), et tient un manifest
JSON qui relie l'emplacement d'origine, le SHA-256 et la date de mise en
quarantaine.

SENTINEL ne supprime jamais. Si une copie supplémentaire est voulue, utiliser
`cp -a` AVANT la mise en quarantaine. Le manifest est conservé pour audit.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import errno
import hashlib
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from .platform import (
    apply_saved_mode,
    is_link,
    live_dest_class,
    lock_quarantine_path,
    protect_storage_dir,
    read_link,
    shared_destination,
    source_class,
    unlock_quarantine_path,
)

# Taille des blocs pour le hachage en flux (cf. integrity._HASH_CHUNK).
_HASH_CHUNK = 1024 * 1024

# Nom du dossier de quarantaine par défaut (relatif au CWD). Il n'est pas
# sensible, y compris lorsqu'il se résout en `$HOME/.sentinel-quarantine`.
DEFAULT_QUARANTINE_NAME = ".sentinel-quarantine"


@dataclass
class QuarantineRecord:
    original: str  # chemin d'origine (absolu)
    quarantined: str  # chemin de destination (absolu)
    sha256: str
    size: int
    mode_before: int  # mode POSIX avant le déplacement
    moved_at: str  # ISO 8601 UTC


@dataclass
class _PlannedQuarantine:
    """Déplacement préparé, pas encore fait. Le journal « en cours » s'en sert."""

    src: Path
    dest: Path
    sha256: str
    size: int
    mode_before: int


# Test : entre l'intention et le déplacement, verrou encore tenu.
_before_move: Callable[[], None] | None = None
# Test : tué entre le déplacement et la ligne de confirmation.
_crash_before_commit: Callable[[], None] | None = None
# Test : après la lecture des intentions encore « en cours », verrou tenu.
_after_pending_read: Callable[[], None] | None = None


def _safe_dest(dest_dir: Path, src: Path) -> Path:
    """Génère un nom de fichier unique sous dest_dir, à partir de `src.name`."""
    candidate = dest_dir / src.name
    if not candidate.exists():
        return candidate
    stem, suffix = src.stem, src.suffix
    i = 1
    while True:
        candidate = dest_dir / f"{stem}.{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def _sha256_path(p: Path) -> str:
    """SHA-256 d'un fichier lu en flux (mémoire constante).

    `read_bytes()` chargeait le fichier entier : mettre en quarantaine un
    disque d'image de plusieurs Go faisait tomber le process avant même
    le déplacement.
    """
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    # Un fichier vide a le SHA-256 de zéro octet, pas "". Une chaîne vide
    # était traitée comme « pas de hash » à la restauration : on pouvait
    # remplacer le fichier en quarantaine sans que le contrôle s'en aperçoive.
    return h.hexdigest()


def _hash_tree(p: Path) -> str:
    """Empreinte du contenu d'un dossier, pas seulement de la liste des noms.

    Chaque fichier régulier contribue par son chemin relatif et son SHA-256.
    Un lien symbolique contribue par sa cible (`readlink`), pas par le
    contenu du fichier pointé. Remplacer le contenu d'un fichier en
    quarantaine change donc l'empreinte.
    """
    h = hashlib.sha256()
    entries: list[tuple[str, bytes, bytes]] = []
    for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
        kept: list[str] = []
        for name in dirnames:
            child = Path(dirpath) / name
            if is_link(child):
                rel = child.relative_to(p).as_posix()
                try:
                    target = read_link(child)
                except OSError:
                    target = ""
                entries.append((rel, b"l\0", target.encode("utf-8", errors="surrogateescape")))
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            child = Path(dirpath) / name
            rel = child.relative_to(p).as_posix()
            if is_link(child):
                try:
                    target = read_link(child)
                except OSError:
                    target = ""
                entries.append((rel, b"l\0", target.encode("utf-8", errors="surrogateescape")))
                continue
            if child.is_file():
                entries.append((rel, b"f\0", _sha256_path(child).encode("ascii")))
    for rel, kind, payload in sorted(entries):
        h.update(kind)
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(payload)
        h.update(b"\0")
    return h.hexdigest()


def _legacy_dir_hash(p: Path) -> str:
    """Empreinte d'un dossier telle que les manifests précédents la stockaient.

    SHA-256 des chemins relatifs des fichiers, triés et joints par un saut de ligne.
    Le contenu n'entrait pas dans le calcul. Un dossier non vide mis en
    quarantaine par cette version a une empreinte différente (`_hash_tree`) :
    sans ce repli, le restaurer après une mise à jour était refusé alors
    que rien n'avait changé. Les manifests nouveaux ne coïncident avec
    cette valeur que pour un dossier vide, déjà couvert par `_hash_tree`.
    """
    paths: list[str] = []
    for child in sorted(p.rglob("*")):
        if child.is_file():
            paths.append(str(child.relative_to(p)))
    return hashlib.sha256("\n".join(paths).encode("utf-8")).hexdigest()


def _hash_and_stat(p: Path) -> tuple[str, int, int]:
    """Hash + size + mode avant déplacement.

    Un répertoire est empreinté par le contenu de ses fichiers (`_hash_tree`),
    pas seulement par la liste des noms.
    """
    st = p.lstat() if is_link(p) else p.stat()
    mode = st.st_mode
    if is_link(p):
        try:
            target = read_link(p)
        except OSError:
            target = ""
        digest = hashlib.sha256(
            b"l\0" + target.encode("utf-8", errors="surrogateescape")
        ).hexdigest()
        return digest, st.st_size, mode
    if p.is_dir():
        return _hash_tree(p), st.st_size, mode
    return _sha256_path(p), st.st_size, mode


def _verify_hash_after_move(dest: Path, expected_sha: str) -> bool:
    """P1-2 : relit le fichier à destination et vérifie son SHA-256.

    Pourquoi : `shutil.move` en cross-filesystem fait copie + suppression.
    Si la copie est partielle (disque plein, I/O error), la suppression
    de l'original peut quand même réussir. On ne s'en rendrait compte
    qu'à la prochaine utilisation du fichier.

    Retourne True si le hash correspond, False sinon.
    """
    if is_link(dest) or (dest.is_dir() and not is_link(dest)):
        try:
            return _hash_and_stat(dest)[0] == expected_sha
        except OSError:
            return False
    if not dest.is_file():
        return False
    try:
        return _sha256_path(dest) == expected_sha
    except OSError:
        return False


def _plan_quarantine(src: Path, dest_dir: Path) -> _PlannedQuarantine:
    """Prépare le déplacement sans y toucher : dossier, empreinte, nom libre."""
    # `Path.exists` suit le lien : un symlink cassé (cible absente ou
    # déjà déplacée) était refusé alors que l'entrée elle-même est bien
    # là. On quarantaine le lien, pas sa cible.
    if not _entry_exists(src):
        raise FileNotFoundError(src)
    # Ne jamais chmod un dossier déjà là (/tmp en 1777). On ne resserre
    # que le dossier que cet appel vient de créer.
    existed = dest_dir.exists()
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not existed:
        protect_storage_dir(dest_dir)

    sha, size, mode_before = _hash_and_stat(src)
    dest = _safe_dest(dest_dir, src)
    return _PlannedQuarantine(
        src=src,
        dest=dest,
        sha256=sha,
        size=size,
        mode_before=mode_before,
    )


def _perform_quarantine_move(plan: _PlannedQuarantine) -> QuarantineRecord:
    """Déplace `plan.src` vers `plan.dest`, vérifie l'empreinte, pose le read-only.

    L'intention est déjà dans le journal. Un arrêt ici se reprend au
    démarrage : rien n'est effacé par la reprise.
    """
    src, dest, sha = plan.src, plan.dest, plan.sha256
    # shutil.move gère les fichiers et les dossiers, et fait cross-filesystem.
    shutil.move(str(src), str(dest))

    # P1-2 : vérification du hash post-move. Si corrompu, on essaie de
    # remettre l'original (rollback best-effort) et on lève OSError.
    if not _verify_hash_after_move(dest, sha):
        try:
            shutil.move(str(dest), str(src))
        except OSError:
            pass
        raise OSError(
            f"hash post-move ne correspond pas à {src} → {dest} "
            "(corruption possible, rollback tenté)"
        )

    # read-only. Un lien symbolique n'est pas suivi : `chmod` modifierait
    # la cible, et un lien relatif ne pointe plus après le déplacement
    # (la cible est restée à côté de l'ancien emplacement).
    try:
        _make_quarantine_readonly(dest)
    except OSError as exc:
        try:
            shutil.move(str(dest), str(src))
        except OSError:
            pass
        raise OSError(
            f"chmod après quarantaine impossible pour {src} → {dest} ({exc}), rollback tenté"
        ) from exc

    return QuarantineRecord(
        original=str(src),
        quarantined=str(dest),
        sha256=sha,
        size=plan.size,
        mode_before=plan.mode_before,
        moved_at=_utcnow_iso(),
    )


def quarantine_file(src: Path, dest_dir: Path) -> QuarantineRecord:
    """Déplace `src` dans `dest_dir`, le rend read-only, et retourne un record.

    P1-2 (M) : on vérifie le hash APRÈS le déplacement. Si `shutil.move`
    a corrompu (cross-filesystem + disque plein, etc.), on lève une
    exception pour que le caller rollback si possible.

    Lève `FileNotFoundError` si `src` n'existe pas, `PermissionError` si
    la mise en quarantaine est impossible, `OSError` si le hash post-move
    ne correspond pas (corruption). Sans journal : `quarantine_paths`
    écrit l'intention avant d'appeler le déplacement.
    """
    return _perform_quarantine_move(_plan_quarantine(src, dest_dir))


def _entry_exists(p: Path) -> bool:
    """Vrai si l'entrée existe, y compris un lien symbolique cassé.

    `Path.exists` suit le lien : un lien relatif déplacé en quarantaine
    ne pointe plus sur sa cible et serait traité comme absent.
    """
    try:
        p.lstat()
    except OSError:
        return False
    return True


def _iter_nofollow(root: Path):
    """Enfants de ``root`` sans descendre dans un lien ou une jonction."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept: list[str] = []
        for name in dirnames:
            child = Path(dirpath) / name
            if is_link(child):
                continue
            kept.append(name)
            yield child
        dirnames[:] = kept
        for name in filenames:
            yield Path(dirpath) / name


def _make_quarantine_readonly(dest: Path) -> None:
    """0444 / 0555, sans suivre liens ni jonctions.

    Windows : l'attribut lecture seule ne suffit pas (le propriétaire le
    retire). Une ACL sans écriture est posée en plus. Un échec d'ACL
    remonte : on ne laisse pas la copie modifiable.
    """
    if is_link(dest):
        return
    if not dest.is_dir():
        lock_quarantine_path(dest, directory=False)
        return
    for child in _iter_nofollow(dest):
        if is_link(child):
            continue
        try:
            lock_quarantine_path(child, directory=child.is_dir())
        except OSError:
            if os.name == "nt":
                raise
    lock_quarantine_path(dest, directory=True)


def _discard_partial(p: Path) -> None:
    """Retire un résidu de copie. Ne suit pas un lien symbolique."""
    if not _entry_exists(p):
        return
    if is_link(p) or not p.is_dir():
        p.unlink()
        return
    shutil.rmtree(p)


def _utcnow_iso() -> str:
    """Horodatage ISO 8601 UTC (`2026-10-18T12:00:00Z`).

    `datetime.utcnow()` est déprécié depuis Python 3.12 et `datetime.UTC` n'existe
    qu'en 3.11+ ; on utilise `datetime.timezone.utc` (3.2+) qui couvre toutes
    les versions encore supportées.
    """
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry_is_inside_dir(entry: Path, directory: Path) -> bool:
    """Vrai si l'entrée `entry` réside dans `directory`.

    On résout les dossiers parents (un maillon symbolique qui sort du
    dossier est refusé) mais pas le dernier composant : un lien mis en
    quarantaine pointe souvent hors du dossier, et `restore` doit
    déplacer le lien, pas la cible.
    """
    try:
        root = directory.resolve()
        parent = entry.parent.resolve()
        location = parent / entry.name
        location.relative_to(root)
    except (OSError, ValueError):
        return False
    return location != root


def _dest_policy(dest: Path) -> str:
    """`hard` (refus même avec --force), `soft` (--force requis) ou `allow`.

    Le défaut `.sentinel-quarantine` n'est dans aucune de ces listes : il
    reste autorisé quand le CWD est `$HOME`. Listes par système :
    voir ``sentinel.platform.classify_dest_text`` (casse ignorée sur
    Windows et macOS).
    """
    return live_dest_class(dest)


def _dest_would_capture_scanned_paths(dest: Path, paths: list[Path]) -> bool:
    """Vrai si dest est un ancêtre d'un des paths à scanner (boucle de
    quarantaine) ou si dest est DANS un des dossiers sources (fuite
    possible)."""
    try:
        d = dest.resolve()
    except OSError:
        return False
    for p in paths:
        try:
            p_resolved = p.resolve()
        except OSError:
            continue
        if p_resolved == d:
            return True
        # dest est ancêtre d'un path source → la quarantaine le contient.
        try:
            p_resolved.relative_to(d)
            return True
        except ValueError:
            pass
        # dest est DANS un dossier source → on scannera dest plus tard.
        # Exception : le dossier par défaut à côté d'un *fichier* est
        # l'emplacement documenté. Déplacer un dossier dans son propre
        # sous-dossier reste refusé.
        container = p_resolved.parent if p_resolved.is_file() else p_resolved
        try:
            d.relative_to(container)
        except ValueError:
            continue
        if p_resolved.is_file() and d.name == DEFAULT_QUARANTINE_NAME:
            continue
        return True
    return False


def quarantine_paths(
    paths: list[Path],
    dest_dir: Path,
    manifest_path: Path,
    force: bool = False,
) -> tuple[list[QuarantineRecord], list[tuple[Path, str]]]:
    """Met en quarantaine une liste de chemins. Écrit le manifest à la fin.

    Retourne (records, échecs) où échecs = [(path, raison), ...].

    P1-3 : garde-fous sur les chemins.
      - Refuse toujours si `dest_dir` est critique (`/`, `$HOME`,
        `~/.ssh`, `~/.gnupg`), même avec `force`.
      - Refuse si `dest_dir` est sensible mais non critique (`~/.config`,
        répertoire système) — sans `force`.
      - Refuse si `dest_dir` capture un des paths (boucle) — sans `force`.
        Le dossier par défaut `.sentinel-quarantine` à côté d'un fichier
        n'est pas une boucle.
      - Avec `force=True`, on autorise le sensible non critique et la
        boucle, et on log explicitement.

    Avant toute décision, les entrées « en cours » de ce journal sont
    reprises (démarrage du moteur). Un refus de chemin ne les efface pas.
    """
    pending_issues = recover_journal(manifest_path)
    if pending_issues:
        print(format_journal_issues(pending_issues), file=sys.stderr)

    policy = _dest_policy(dest_dir)
    if shared_destination(dest_dir):
        msg = (
            f"❌ Refus : {dest_dir} est un dossier partagé "
            "(sticky ou modifiable par tous, comme /tmp en 1777). "
            "Son mode ne sera pas modifié."
        )
        print(msg, file=sys.stderr)
        return [], [(p, "dest partagé (sticky ou world-writable)") for p in paths]
    if policy == "hard":
        msg = (
            f"❌ Refus : {dest_dir} est un chemin critique "
            "(/, $HOME, ~/.ssh, ~/.gnupg, ~/Library/Keychains, "
            "racine de lecteur ou %USERPROFILE%). --force ne lève pas ce refus."
        )
        print(msg, file=sys.stderr)
        for p in paths:
            print(f"  ⏭ {p} : refusé (dest critique)", file=sys.stderr)
        return [], [(p, "dest critique (refus définitif)") for p in paths]
    if not force:
        if policy == "soft":
            msg = (
                f"❌ Refus : {dest_dir} est un chemin sensible "
                "(~/.config, %APPDATA%, répertoire système, …). Réessayez avec --force "
                "si vous savez ce que vous faites."
            )
            print(msg, file=sys.stderr)
            for p in paths:
                print(f"  ⏭ {p} : refusé (dest sensible)", file=sys.stderr)
            return [], [(p, "dest sensible (--force requis)") for p in paths]
        if _dest_would_capture_scanned_paths(dest_dir, paths):
            msg = (
                f"❌ Refus : {dest_dir} capture un des fichiers à scanner "
                "(boucle de quarantaine). Réessayez avec --force si vous "
                "savez ce que vous faites."
            )
            print(msg, file=sys.stderr)
            for p in paths:
                print(f"  ⏭ {p} : refusé (dest dans le périmètre)", file=sys.stderr)
            return [], [(p, "dest capture le périmètre (--force requis)") for p in paths]
    elif policy == "soft":
        print(
            f"⚠ --force : destination sensible autorisée ({dest_dir}).",
            file=sys.stderr,
        )

    records: list[QuarantineRecord] = []
    failures: list[tuple[Path, str]] = []

    for p in paths:
        zone = source_class(p)
        if zone == "hard":
            reason = "source critique (refus définitif, zone dure ou dossier qui en contient une)"
            failures.append((p, reason))
            print(f"  ⏭ {p} : refusé ({reason})", file=sys.stderr)
            continue
        if zone == "soft" and not force:
            reason = "source sensible (--force requis)"
            failures.append((p, reason))
            print(f"  ⏭ {p} : refusé ({reason})", file=sys.stderr)
            continue
        try:
            plan = _plan_quarantine(p, dest_dir)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            failures.append((p, str(exc)))
            print(f"  ✗ {p} : {exc}", file=sys.stderr)
            continue

        # Deux phases, sous le même verrou fichier. L'intention est sur
        # disque et fsync avant le move : un SIGKILL entre les deux se
        # reprend au démarrage. Tant que ce processus tient le verrou, un
        # autre ne peut pas annuler l'entrée (le move est encore le sien).
        journal_id = uuid.uuid4().hex
        intent = _intent_line(plan, journal_id)
        try:
            with _journal_exclusive(manifest_path):
                try:
                    _manifest_append_unlocked(manifest_path, intent)
                except OSError as exc:
                    failures.append((p, f"journal d'intention NON écrit ({exc})"))
                    print(
                        f"  ✗ {p} : journal d'intention impossible ({exc}) — "
                        "le fichier n'a pas été déplacé.",
                        file=sys.stderr,
                    )
                    continue

                if _before_move is not None:
                    _before_move()

                try:
                    rec = _perform_quarantine_move(plan)
                except (FileNotFoundError, PermissionError, OSError) as exc:
                    failures.append((p, str(exc)))
                    print(f"  ✗ {p} : {exc}", file=sys.stderr)
                    try:
                        failed_issues = _recover_unlocked(manifest_path)
                    except OSError as recover_exc:
                        failed_issues = []
                        print(
                            f"  ⚠ {p} : reprise du journal impossible ({recover_exc}).",
                            file=sys.stderr,
                        )
                    if failed_issues:
                        print(format_journal_issues(failed_issues), file=sys.stderr)
                    continue

                records.append(rec)
                print(
                    f"  ✓ {p} → {rec.quarantined}  (sha256={rec.sha256[:12]}…)",
                    file=sys.stderr,
                )

                # Arrêt injecté (test) : le fichier est déjà en quarantaine,
                # la confirmation n'est pas encore écrite. Le verrou est
                # encore tenu : un autre processus attend, il n'annule pas.
                if _crash_before_commit is not None:
                    _crash_before_commit()

                # P1-2 : confirmation IMMÉDIATE, entrée par entrée.
                # Le manifest était auparavant écrit après la boucle complète :
                # un crash (ou un Ctrl-C) au 3e fichier laissait les deux
                # premiers déplacés *sans aucune trace* — donc irrécupérables
                # par `restore`, et invisibles pour l'audit. L'intention
                # « en cours » est déjà sur disque ; cette ligne la confirme.
                line = dict(asdict(rec))
                line["id"] = journal_id
                line["_status"] = "done"
                line["_appended_at"] = _utcnow_iso()
                try:
                    _manifest_append_unlocked(manifest_path, line)
                except OSError as exc:
                    # Le fichier est déjà déplacé et l'intention est sur disque :
                    # le prochain démarrage confirmera l'entrée.
                    failures.append((p, f"déplacé mais confirmation du journal NON écrite ({exc})"))
                    print(
                        f"  ⚠ {p} : déplacé vers {rec.quarantined} mais la confirmation "
                        f"du journal n'a pas pu être écrite ({exc}) — reprise au prochain "
                        "démarrage.",
                        file=sys.stderr,
                    )
        except OSError as exc:
            failures.append((p, f"journal de quarantaine indisponible ({exc})"))
            print(
                f"  ✗ {p} : journal de quarantaine indisponible ({exc}).",
                file=sys.stderr,
            )

    if records:
        print(
            f"\nManifest : {manifest_path} "
            f"({len(records)} nouvelle(s) entrée(s), JSONL append-only)",
            file=sys.stderr,
        )

    return records, failures


# Journal encore ouvert : un ``os._exit`` doit le vider avant de tuer
# le processus, sinon la dernière ligne reste dans le tampon Python.
# ``_journal_lock`` exclut les fils du même processus (réentrant : le
# même fil peut reprendre le journal pendant qu'il le tient déjà).
# ``flock`` (ou ``msvcrt.locking``) exclut les autres processus. Les deux
# se prennent dans cet ordre, et se relâchent dans l'ordre inverse.
# L'attente est bornée : au-delà, ``JournalLocked``.
# Un fil de l'interface peut lier un ``threading.Event`` : la boucle
# d'attente le consulte et lève ``JournalInterrupted`` sans toucher au
# journal. Une section déjà engagée n'est pas coupée.
JOURNAL_LOCK_TIMEOUT = 15.0
_LOCK_POLL_S = 0.05
_LOCK_MESSAGE = "journal verrouillé par un autre processus"
_INTERRUPTED_MESSAGE = "attente du journal interrompue par la fermeture"
# flock n'est pas un verrou de partage. Sur NFS (souvent local au client)
# et sur SMB/CIFS, deux machines peuvent ne pas se voir. On pose alors
# un fichier O_EXCL en plus du flock. Il porte le pid, l'instant de
# démarrage du processus, et le boot id / machine-id quand ils existent.
# Un verrou d'un autre hôte expire s'il n'est plus rafraîchi.
# ``SENTINEL_HOSTLOCK_STALE_SECONDS`` règle cet âge (défaut : 24 h).
# Pour reprendre la main tout de suite, supprimer le fichier ``.hostlock``
# nommé dans le message, une fois le processus terminé.
HOSTLOCK_STALE_AFTER_S = 24 * 60 * 60
HOSTLOCK_HEARTBEAT_S = 60.0
_HOSTLOCK_STALE_ENV = "SENTINEL_HOSTLOCK_STALE_SECONDS"
_REMOTE_LOCK_FS = frozenset(
    {
        "nfs",
        "nfs3",
        "nfs4",
        "cifs",
        "smb",
        "smb2",
        "smb3",
        "smbfs",
        "fuse.sshfs",
        "afs",
        "afp",
        "webdav",
    }
)
_DRIVE_REMOTE = 4
_journal_handles: dict[str, io.BufferedWriter] = {}
_lock_fds: dict[str, int] = {}
# Profondeur du verrou fichier pour le fil qui tient déjà ``_journal_lock``.
# Sans elle, la sortie d'une section imbriquée ferait ``LOCK_UN`` et
# lâcherait le déplacement encore en cours.
_lock_depth: dict[str, int] = {}
_held_hostlocks: dict[str, str] = {}
_held_hostlock_owners: dict[str, _HostLock] = {}
_hostlock_beats: dict[str, tuple[threading.Event, threading.Thread]] = {}
_identity_cache: dict[str, str] = {}
_remote_lock_warned: set[str] = set()
_thread_cancel = threading.local()


class JournalLocked(OSError):
    """Un autre processus tient encore le journal après le délai d'attente.

    Sur un disque réseau, le message nomme l'hôte, le pid, l'âge et le
    fichier ``.hostlock`` à supprimer pour forcer la reprise.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or _LOCK_MESSAGE)


class JournalInterrupted(Exception):
    """La fermeture a annulé l'attente. Le journal n'a pas été modifié."""

    def __init__(self) -> None:
        super().__init__(_INTERRUPTED_MESSAGE)


class _JournalRLock:
    """``RLock`` avec ``locked()``, absent de la bibliothèque en 3.10."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._guard = threading.Lock()
        self._count = 0

    def acquire(self, timeout: float | None = None) -> bool:
        if timeout is None:
            ok = self._lock.acquire()
        else:
            ok = self._lock.acquire(timeout=timeout)
        if ok:
            with self._guard:
                self._count += 1
        return ok

    def release(self) -> None:
        with self._guard:
            if self._count > 0:
                self._count -= 1
        self._lock.release()

    def locked(self) -> bool:
        with self._guard:
            return self._count > 0

    def __enter__(self) -> _JournalRLock:
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


_journal_lock = _JournalRLock()


def _journal_key(manifest_path: Path) -> str:
    return os.path.abspath(os.fspath(manifest_path))


def _lock_file_path(manifest_path: Path) -> str:
    """Fichier de verrou stable. Il n'est jamais remplacé par ``os.replace``."""
    return _journal_key(manifest_path) + ".lock"


def _journal_file(manifest_path: Path) -> io.BufferedWriter:
    """Descripteur append du journal. L'appelant tient ``_journal_lock``."""
    key = _journal_key(manifest_path)
    handle = _journal_handles.get(key)
    if handle is not None and not handle.closed:
        return handle
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    opened = os.fdopen(fd, "ab", buffering=4096)
    if not isinstance(opened, io.BufferedWriter):
        opened.close()
        raise OSError("journal de quarantaine")
    _journal_handles[key] = opened
    return opened


def _append_handle_matches(handle: io.BufferedWriter, key: str) -> bool:
    """Faux si ``os.replace`` a changé l'inode sous ce descripteur."""
    if handle.closed:
        return False
    try:
        fd_stat = os.fstat(handle.fileno())
        path_stat = os.stat(key)
    except OSError:
        return False
    if fd_stat.st_nlink == 0:
        return False
    return fd_stat.st_dev == path_stat.st_dev and fd_stat.st_ino == path_stat.st_ino


def _discard_append_handle(handle: io.BufferedWriter) -> None:
    """Ferme sans vider le tampon : l'inode visé n'est plus le journal."""
    if handle.closed:
        return
    raw = handle.detach()
    if raw is not None and not raw.closed:
        raw.close()


def _retire_append_handle(manifest_path: Path) -> None:
    """Ferme le descripteur. Le prochain append rouvre le fichier du chemin.

    Après un ``os.replace`` fait par un autre processus, l'ancien
    descripteur écrit un inode déjà détaché. On ne le réutilise pas
    d'une section à l'autre. S'il vise encore le bon fichier, on vide
    d'abord le tampon (un test peut y avoir laissé une ligne).
    """
    key = _journal_key(manifest_path)
    handle = _journal_handles.pop(key, None)
    if handle is None or handle.closed:
        return
    if not _append_handle_matches(handle, key):
        _discard_append_handle(handle)
        return
    handle.flush()
    os.fsync(handle.fileno())
    handle.close()


def _wait_cancelled() -> bool:
    event = getattr(_thread_cancel, "event", None)
    return isinstance(event, threading.Event) and event.is_set()


def _raise_if_cancelled() -> None:
    if _wait_cancelled():
        raise JournalInterrupted()


@contextlib.contextmanager
def bind_journal_cancel(cancel: threading.Event) -> Iterator[None]:
    """Ce fil abandonne l'attente du verrou quand ``cancel`` est signalé.

    Une section déjà engagée va jusqu'au bout : une écriture du journal
    n'est pas coupée. L'événement est celui du fil courant.
    """
    previous = getattr(_thread_cancel, "event", None)
    _thread_cancel.event = cancel
    try:
        yield
    finally:
        _thread_cancel.event = previous


def _longest_mount(path: str, mounts: list[tuple[str, str]]) -> str | None:
    """Type du plus long point de montage qui couvre ``path``."""
    try:
        target = os.path.realpath(path)
    except OSError:
        target = path
    best_len = -1
    best: str | None = None
    for mount, fstype in mounts:
        prefix = mount.rstrip("/") or "/"
        # ``/`` rstrip jusqu'à vide : sans ce cas, la racine ne couvre aucun chemin.
        if prefix == "/":
            matched = target.startswith("/")
        else:
            matched = target == prefix or target.startswith(prefix + "/")
        if matched and len(prefix) >= best_len:
            best_len = len(prefix)
            best = fstype
    return best


def _lock_fstype_proc(path: str) -> str | None:
    """``/proc/mounts`` (Linux). ``None`` si le fichier est illisible."""
    mounts = "/proc/mounts"
    try:
        with open(mounts, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    parsed: list[tuple[str, str]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        mount = parts[1].replace("\\040", " ").replace("\\011", "\t")
        parsed.append((mount, parts[2]))
    return _longest_mount(path, parsed)


def _parse_mount_line(line: str) -> tuple[str, str] | None:
    """Une ligne ``mount`` macOS : ``spec on /point (fstype, flags)``."""
    marker = " on "
    idx = line.find(marker)
    if idx < 0:
        return None
    rest = line[idx + len(marker) :]
    paren = rest.rfind(" (")
    if paren < 0 or not rest.endswith(")"):
        return None
    mount = rest[:paren]
    fstype = rest[paren + 2 : -1].split(",", 1)[0].strip()
    if not mount or not fstype:
        return None
    return mount, fstype


def _parse_mount_output(output: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in output.splitlines():
        parsed = _parse_mount_line(line)
        if parsed is not None:
            rows.append(parsed)
    return rows


def _lock_fstype_from_mounts(path: str, mounts: list[tuple[str, str]]) -> str | None:
    return _longest_mount(path, mounts)


def _darwin_mount_output() -> str | None:
    import subprocess

    for program in ("/sbin/mount", "mount"):
        try:
            return subprocess.check_output(
                [program],
                text=True,
                timeout=2,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def _lock_fstype_darwin(path: str) -> str | None:
    output = _darwin_mount_output()
    if not output:
        return None
    return _lock_fstype_from_mounts(path, _parse_mount_output(output))


def _windows_drive_type(root: str) -> int | None:
    """``GetDriveTypeW``. ``None`` hors Windows ou si l'appel échoue."""
    if os.name != "nt":
        return None
    import ctypes

    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    try:
        return int(windll.kernel32.GetDriveTypeW(root))
    except (AttributeError, OSError, ValueError):
        return None


def _lock_fstype_windows(
    path: str, drive_type: Callable[[str], int | None] | None = None
) -> str | None:
    """UNC ou lecteur ``DRIVE_REMOTE``. ``local`` pour un disque fixe."""
    import ntpath

    text = str(path).replace("/", "\\")
    if text.startswith("\\\\"):
        return "smb"
    drive, _rest = ntpath.splitdrive(text)
    if not drive:
        return None
    lookup = drive_type if drive_type is not None else _windows_drive_type
    kind = lookup(drive + "\\")
    if kind == _DRIVE_REMOTE:
        return "smb"
    if kind is None:
        return None
    return "local"


def _lock_fstype(path: str) -> str | None:
    """Type du système de fichiers qui porte ``path``.

    Linux : ``/proc/mounts``. macOS : table ``mount``. Windows : UNC ou
    ``GetDriveTypeW``. ``None`` si on ne peut pas décider.
    """
    if os.name == "nt":
        return _lock_fstype_windows(path)
    if os.path.isfile("/proc/mounts"):
        return _lock_fstype_proc(path)
    if sys.platform == "darwin":
        return _lock_fstype_darwin(path)
    return None


def _note_remote_lock(path: str, fstype: str) -> None:
    """Une fois par journal : flock ne suffit pas, le fichier O_EXCL prend le relais."""
    try:
        key = os.path.realpath(path)
    except OSError:
        key = path
    if key in _remote_lock_warned:
        return
    _remote_lock_warned.add(key)
    print(
        f"⚠ Journal sur système de fichiers réseau ({fstype}) : {key}. "
        "flock n'est pas fiable entre clients NFS et SMB. "
        "Un fichier créé en O_EXCL porte le pid, l'instant de démarrage "
        "du processus et, s'ils existent, le boot id et le machine-id. "
        "On ne reprend ce verrou que si cette identité est celle d'un "
        "processus terminé. Un verrou d'un autre hôte expire s'il n'est "
        "plus rafraîchi (SENTINEL_HOSTLOCK_STALE_SECONDS). "
        "Le message d'attente indique l'hôte, le pid, l'âge et le fichier "
        "à supprimer. Placez le journal sur un disque local pour un verrou du noyau.",
        file=sys.stderr,
    )


def _our_host() -> str:
    host = socket.gethostname().split("\0", 1)[0]
    host = host.replace("\r", "").replace("\n", "").strip()
    return host or "localhost"


@dataclass(frozen=True)
class _HostLock:
    """Identité du processus qui tient un ``.hostlock``.

    Le nom d'hôte seul ne suffit pas : deux machines, ou deux conteneurs,
    peuvent le partager. On compare aussi le boot id et le machine-id
    quand ils sont écrits, et l'instant de démarrage du processus pour
    ne pas confondre un pid recyclé avec le détenteur.
    """

    pid: int
    host: str
    start: str
    boot_id: str
    machine_id: str


def _lock_field(value: str) -> str:
    cleaned = value.replace("\r", " ").replace("\n", " ").replace("\0", "").strip()
    if len(cleaned) > 200:
        cleaned = cleaned[:200]
    return cleaned


def _hostlock_path(manifest_path: Path) -> str:
    return _journal_key(manifest_path) + ".hostlock"


def _read_single_token(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read(256)
    except OSError:
        return ""
    lines = raw.splitlines()
    if not lines:
        return ""
    return _lock_field(lines[0])


def _our_boot_id() -> str:
    cached = _identity_cache.get("boot")
    if cached is None:
        cached = _read_boot_id()
        _identity_cache["boot"] = cached
    return cached


def _our_machine_id() -> str:
    cached = _identity_cache.get("machine")
    if cached is None:
        cached = _read_machine_id()
        _identity_cache["machine"] = cached
    return cached


def _read_boot_id() -> str:
    if os.name == "nt":
        return _win_boot_id()
    token = _read_single_token("/proc/sys/kernel/random/boot_id")
    if token:
        return token
    if sys.platform == "darwin":
        return _darwin_boot_id()
    return ""


def _read_machine_id() -> str:
    if os.name == "nt":
        return _win_machine_id()
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        token = _read_single_token(path)
        if token:
            return token
    if sys.platform == "darwin":
        return _darwin_machine_id()
    return ""


def _darwin_boot_id() -> str:
    try:
        import ctypes

        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    except OSError:
        return ""

    class Timeval(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int)]

    buf = Timeval()
    size = ctypes.c_size_t(ctypes.sizeof(buf))
    try:
        rc = libc.sysctlbyname(b"kern.boottime", ctypes.byref(buf), ctypes.byref(size), None, 0)
    except (AttributeError, OSError):
        return ""
    if rc != 0 or int(buf.tv_sec) <= 0:
        return ""
    return str(int(buf.tv_sec))


def _darwin_machine_id() -> str:
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        if "IOPlatformUUID" not in line or "=" not in line:
            continue
        token = _lock_field(line.split("=", 1)[1].strip().strip('"'))
        if token:
            return token
    return ""


def _win_reg_value(subkey: str, name: str) -> str:
    """Lit une valeur de registre. Vide hors Windows ou si la clé manque.

    ``winreg`` n'a pas ces attributs dans le typage Linux : on passe par
    ``getattr`` pour que le contrôle de types reste le même partout.
    """
    if os.name != "nt":
        return ""
    try:
        import winreg
    except ImportError:
        return ""
    open_key = getattr(winreg, "OpenKey", None)
    query = getattr(winreg, "QueryValueEx", None)
    close_key = getattr(winreg, "CloseKey", None)
    hive = getattr(winreg, "HKEY_LOCAL_MACHINE", None)
    if open_key is None or query is None or close_key is None or hive is None:
        return ""
    try:
        key = open_key(hive, subkey)
        try:
            value, _kind = query(key, name)
        finally:
            close_key(key)
    except OSError:
        return ""
    return _lock_field(str(value))


def _win_boot_id() -> str:
    return _win_reg_value(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
        "BootId",
    )


def _win_machine_id() -> str:
    return _win_reg_value(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")


def _parse_linux_stat_start(raw: bytes) -> str | None:
    """Champ ``starttime`` de ``/proc/<pid>/stat`` (ticks depuis le boot).

    ``comm`` est entre parenthèses et peut contenir des espaces.
    """
    right = raw.rfind(b")")
    if right < 0:
        return None
    fields = raw[right + 1 :].split()
    # starttime est le champ 22, donc l'index 19 après ``comm``.
    if len(fields) <= 19:
        return None
    token = fields[19]
    if not token.isdigit():
        return None
    return token.decode("ascii")


def _linux_process_start(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            raw = fh.read(4096)
    except OSError:
        return None
    return _parse_linux_stat_start(raw)


def _darwin_process_start(pid: int) -> str | None:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    token = _lock_field(result.stdout)
    return token or None


def _win_process_start(pid: int) -> str | None:
    import ctypes

    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    access = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
    handle = windll.kernel32.OpenProcess(access, False, pid)
    if not handle:
        return None
    try:
        created = ctypes.c_ulonglong()
        exited = ctypes.c_ulonglong()
        kernel = ctypes.c_ulonglong()
        user = ctypes.c_ulonglong()
        ok = windll.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok or int(created.value) == 0:
            return None
        return str(int(created.value))
    finally:
        windll.kernel32.CloseHandle(handle)


def _process_start_token(pid: int) -> str | None:
    """Instant de démarrage stable de ``pid``, ou None si on ne peut pas le lire."""
    if pid <= 0:
        return None
    if os.name == "nt":
        return _win_process_start(pid)
    token = _linux_process_start(pid)
    if token:
        return token
    if sys.platform == "darwin":
        return _darwin_process_start(pid)
    return None


def _our_hostlock() -> _HostLock:
    return _HostLock(
        pid=os.getpid(),
        host=_our_host(),
        start=_process_start_token(os.getpid()) or "",
        boot_id=_our_boot_id(),
        machine_id=_our_machine_id(),
    )


def _encode_hostlock(lock: _HostLock) -> bytes:
    fields = [
        "2",
        str(lock.pid),
        _lock_field(lock.host),
        _lock_field(lock.start),
        _lock_field(lock.boot_id),
        _lock_field(lock.machine_id),
    ]
    return ("\n".join(fields) + "\n").encode("utf-8")


def _lock_from_fields(
    pid_text: str,
    host: str,
    start: str,
    boot_id: str,
    machine_id: str,
) -> _HostLock | None:
    try:
        pid = int(pid_text.strip())
    except ValueError:
        return None
    if pid <= 0:
        return None
    host = _lock_field(host)
    if not host:
        return None
    return _HostLock(
        pid=pid,
        host=host,
        start=_lock_field(start),
        boot_id=_lock_field(boot_id),
        machine_id=_lock_field(machine_id),
    )


def _parse_hostlock(raw: bytes) -> _HostLock | None:
    parts = raw.decode("utf-8", errors="replace").split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    if not parts:
        return None
    if parts[0] == "2":
        if len(parts) != 6:
            return None
        return _lock_from_fields(parts[1], parts[2], parts[3], parts[4], parts[5])
    # Ancien format : une ligne pid, une ligne hôte. Pas d'identité de
    # machine : on ne le reprend pas par le pid, seulement par l'âge.
    if len(parts) >= 2 and parts[0].strip().isdigit():
        return _lock_from_fields(parts[0], parts[1], "", "", "")
    return None


def _hostlock_owner(path: str) -> _HostLock | None:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(1024)
    except OSError:
        return None
    return _parse_hostlock(raw)


def _pid_alive(pid: int) -> bool:
    """Vrai si ``pid`` existe encore. Ne signale aucun processus."""
    if pid <= 0:
        return False
    if os.name == "nt":
        return _win_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _win_pid_alive(pid: int) -> bool:
    import ctypes

    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return True
    access = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
    handle = windll.kernel32.OpenProcess(access, False, pid)
    if not handle:
        # 5 = accès refusé : le processus existe. Le reste : il n'existe pas.
        return int(windll.kernel32.GetLastError()) == 5
    try:
        code = ctypes.c_ulong()
        ok = windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        if not ok:
            return True
        return int(code.value) == 259  # STILL_ACTIVE
    finally:
        windll.kernel32.CloseHandle(handle)


def _tokens_match(left: str, right: str) -> bool:
    return bool(left) and bool(right) and left == right


def _same_machine(owner: _HostLock) -> bool:
    """Même machine encore démarrée, au-delà du nom d'hôte.

    Le machine-id tranche. Sans lui, un boot id identique ne suffit pas :
    deux conteneurs voient souvent le même. Il faut alors le hostname,
    le boot id et l'instant de démarrage de ce pid. Sinon le verrou est
    étranger et seul l'âge le reprend. Un boot id différent est un autre
    démarrage, même si le machine-id correspond.
    """
    if owner.host != _our_host():
        return False
    boot = _our_boot_id()
    machine = _our_machine_id()
    if owner.boot_id and boot and owner.boot_id != boot:
        return False
    if owner.machine_id and machine and owner.machine_id != machine:
        return False
    if _tokens_match(owner.machine_id, machine):
        return True
    if owner.machine_id or machine:
        return False
    if not _tokens_match(owner.boot_id, boot) or not owner.start or not _pid_alive(owner.pid):
        return False
    current = _process_start_token(owner.pid)
    return bool(current) and current == owner.start


def _previous_boot_same_machine(owner: _HostLock) -> bool:
    """Même machine, boot précédent : le processus enregistré est terminé."""
    if owner.host != _our_host():
        return False
    boot = _our_boot_id()
    machine = _our_machine_id()
    return bool(
        owner.machine_id
        and machine
        and owner.machine_id == machine
        and owner.boot_id
        and boot
        and owner.boot_id != boot
    )


def _holder_process_is_dead(owner: _HostLock) -> bool:
    """Vrai seulement si l'identité du fichier est celle d'un processus mort.

    Un pid vivant dont l'instant de démarrage diffère a été recyclé : le
    détenteur d'origine est mort. Sans machine-id, le boot id ne prouve
    pas la machine : on ne reprend pas sur un pid mort ou recyclé, l'âge
    du fichier s'en charge. Le hostname, le boot id et l'instant de
    démarrage ensemble reconnaissent seulement un processus encore vivant.
    """
    if _previous_boot_same_machine(owner):
        return True
    if not _same_machine(owner):
        return False
    if not _tokens_match(owner.machine_id, _our_machine_id()):
        return False
    if not _pid_alive(owner.pid):
        return True
    if not owner.start:
        return False
    current = _process_start_token(owner.pid)
    if not current:
        return False
    return current != owner.start


def _holder_process_is_live(owner: _HostLock) -> bool:
    """Vrai si le pid vivant a le même instant de démarrage, sur cette machine."""
    if not _same_machine(owner) or not owner.start or not _pid_alive(owner.pid):
        return False
    current = _process_start_token(owner.pid)
    return bool(current) and current == owner.start


def _hostlock_stale_after() -> float:
    """Âge sans rafraîchissement au-delà duquel un verrou étranger est périmé.

    ``SENTINEL_HOSTLOCK_STALE_SECONDS`` l'emporte sur
    :data:`HOSTLOCK_STALE_AFTER_S`. Une valeur illisible est ignorée.
    ``0`` rend périmé tout verrou qui n'est pas un processus vivant ici :
    ce n'est pas le moyen de forcer une reprise. Pour ça, supprimer le
    fichier ``.hostlock`` indiqué dans le message.
    """
    raw = os.environ.get(_HOSTLOCK_STALE_ENV, "").strip()
    if raw:
        try:
            value = float(raw)
        except ValueError:
            value = -1.0
        if value >= 0:
            return value
    return float(HOSTLOCK_STALE_AFTER_S)


def _hostlock_age(path: str) -> float | None:
    try:
        modified = os.stat(path).st_mtime
    except OSError:
        return None
    return time.time() - modified


def _format_age(seconds: float) -> str:
    total = max(0, int(seconds))
    if total < 60:
        return f"{total} s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes} min {secs} s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min"
    days, hours = divmod(hours, 24)
    return f"{days} j {hours} h"


def _hostlock_wait_message(path: str) -> str:
    owner = _hostlock_owner(path)
    age = _hostlock_age(path)
    host = owner.host if owner is not None else "inconnu"
    pid = str(owner.pid) if owner is not None else "inconnu"
    if age is None:
        age_text = "inconnu"
    else:
        age_text = f"{_format_age(age)} ({int(age)} s)"
    limit = int(_hostlock_stale_after())
    lines = [
        _LOCK_MESSAGE,
        f"hôte : {host}",
        f"pid : {pid}",
        f"âge : {age_text}",
        f"fichier : {path}",
    ]
    if owner is not None and owner.boot_id:
        lines.append(f"boot id : {owner.boot_id}")
    if owner is not None and owner.machine_id:
        lines.append(f"machine-id : {owner.machine_id}")
    lines.append(
        "Ce fichier est rafraîchi tant que le processus le tient. "
        f"Sans rafraîchissement, il est périmé après {limit} s "
        f"({_HOSTLOCK_STALE_ENV}). "
        "Pour forcer la reprise une fois le processus terminé, supprimez ce fichier."
    )
    return "\n".join(lines)


def _owner_is_stale(path: str, owner: _HostLock | None) -> bool:
    """Périmé : processus mort de cette machine, ou fichier trop ancien.

    Un détenteur confirmé vivant n'est pas repris, même si le rafraîchissement
    a du retard. Un autre hôte, ou le même hostname sur une autre machine,
    n'est repris qu'après :func:`_hostlock_stale_after` sans mise à jour de
    la date du fichier. Un fichier illisible et ancien reste périmé au bout
    de :data:`JOURNAL_LOCK_TIMEOUT`.
    """
    if owner is None:
        age = _hostlock_age(path)
        return age is not None and age >= JOURNAL_LOCK_TIMEOUT
    if _holder_process_is_dead(owner):
        return True
    if _holder_process_is_live(owner):
        return False
    age = _hostlock_age(path)
    return age is not None and age >= _hostlock_stale_after()


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _try_break_stale_hostlock(path: str) -> bool:
    """Écarte un verrou périmé. Remet en place un verrou qu'on n'aurait pas dû prendre."""
    owner = _hostlock_owner(path)
    if not _owner_is_stale(path, owner):
        return False
    grave = f"{path}.stale.{os.getpid()}.{time.time_ns()}"
    try:
        os.rename(path, grave)
    except OSError:
        return False
    moved = _hostlock_owner(grave)
    if moved != owner:
        try:
            os.rename(grave, path)
        except OSError:
            pass
        return False
    _unlink_quiet(grave)
    parent = os.path.dirname(path) or "."
    _fsync_directory(parent)
    return True


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("écriture du verrou réseau")
        view = view[written:]


def _touch_hostlock(path: str) -> bool:
    try:
        os.utime(path, None)
    except OSError:
        return False
    return True


def _hostlock_heartbeat_interval() -> float:
    return HOSTLOCK_HEARTBEAT_S


def _start_hostlock_heartbeat(path: str) -> None:
    """Rafraîchit la date du fichier tant qu'on le tient.

    Un autre hôte ne voit pas nos processus. Il se fie à cette date pour
    décider qu'un verrou est périmé.
    """
    _stop_hostlock_heartbeat(path)
    stop = threading.Event()

    def loop() -> None:
        while not stop.wait(_hostlock_heartbeat_interval()):
            if not _touch_hostlock(path):
                return

    thread = threading.Thread(target=loop, name="sentinel-hostlock", daemon=True)
    thread.start()
    _hostlock_beats[path] = (stop, thread)


def _stop_hostlock_heartbeat(path: str) -> None:
    state = _hostlock_beats.pop(path, None)
    if state is None:
        return
    stop, thread = state
    stop.set()
    if thread is not threading.current_thread():
        thread.join(timeout=2.0)


def _unlink_hostlock(path: str) -> None:
    _stop_hostlock_heartbeat(path)
    expected = _held_hostlock_owners.pop(path, None)
    owner = _hostlock_owner(path)
    if expected is not None:
        if owner is not None and owner != expected:
            return
    elif owner is not None and owner != _our_hostlock():
        return
    _unlink_quiet(path)
    _fsync_directory(os.path.dirname(path) or ".")


def _acquire_hostlock(path: str, deadline: float) -> None:
    """Création exclusive. Un verrou vivant fait attendre, un verrou périmé est repris."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    owner = _our_hostlock()
    payload = _encode_hostlock(owner)
    while True:
        _raise_if_cancelled()
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError as exc:
            if _try_break_stale_hostlock(path):
                continue
            if _wait_cancelled():
                raise JournalInterrupted() from exc
            if time.monotonic() >= deadline:
                raise JournalLocked(_hostlock_wait_message(path)) from exc
            remaining = deadline - time.monotonic()
            time.sleep(min(_LOCK_POLL_S, max(0.0, remaining)))
            continue
        try:
            _write_all(fd, payload)
            os.fsync(fd)
        except Exception:
            os.close(fd)
            _unlink_quiet(path)
            _fsync_directory(parent)
            raise
        os.close(fd)
        _fsync_directory(parent)
        _held_hostlock_owners[path] = owner
        _start_hostlock_heartbeat(path)
        return


def _ensure_lock_fd(manifest_path: Path) -> int:
    key = _journal_key(manifest_path)
    fd = _lock_fds.get(key)
    if fd is not None:
        return fd
    path = _lock_file_path(manifest_path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        if os.fstat(fd).st_size < 1:
            os.write(fd, b"\0")
    except Exception:
        os.close(fd)
        raise
    _lock_fds[key] = fd
    return fd


def _acquire_kernel_lock(manifest_path: Path, deadline: float) -> None:
    """``flock`` ou ``msvcrt``. L'attente consulte l'annulation à chaque tour."""
    fd = _ensure_lock_fd(manifest_path)
    if os.name == "nt":
        import msvcrt

        locking = getattr(msvcrt, "locking")  # noqa: B009
        mode = getattr(msvcrt, "LK_NBLCK")  # noqa: B009
        while True:
            _raise_if_cancelled()
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                locking(fd, mode, 1)
                return
            except OSError as exc:
                if _wait_cancelled():
                    raise JournalInterrupted() from exc
                if time.monotonic() >= deadline:
                    raise JournalLocked() from exc
                remaining = deadline - time.monotonic()
                time.sleep(min(_LOCK_POLL_S, max(0.0, remaining)))
    import fcntl

    while True:
        _raise_if_cancelled()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            if _wait_cancelled():
                raise JournalInterrupted() from exc
            if time.monotonic() >= deadline:
                raise JournalLocked() from exc
            remaining = deadline - time.monotonic()
            time.sleep(min(_LOCK_POLL_S, max(0.0, remaining)))


def _unlock_kernel_lock(key: str) -> None:
    fd = _lock_fds.get(key)
    if fd is None:
        return
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        getattr(msvcrt, "locking")(fd, getattr(msvcrt, "LK_UNLCK"), 1)  # noqa: B009
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def _acquire_thread_lock() -> None:
    """``RLock`` du processus. Avec annulation, l'attente est découpée."""
    event = getattr(_thread_cancel, "event", None)
    if not isinstance(event, threading.Event):
        if not _journal_lock.acquire(timeout=JOURNAL_LOCK_TIMEOUT):
            raise JournalLocked()
        return
    deadline = time.monotonic() + JOURNAL_LOCK_TIMEOUT
    while True:
        if event.is_set():
            raise JournalInterrupted()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise JournalLocked()
        if _journal_lock.acquire(timeout=min(_LOCK_POLL_S, remaining)):
            return


def _acquire_process_lock(manifest_path: Path, timeout: float | None = None) -> None:
    """Verrou exclusif inter-processus. L'appelant tient ``_journal_lock``.

    POSIX : ``fcntl.flock`` non bloquant, interrogé jusqu'au délai.
    Windows : ``msvcrt.locking`` non bloquant, même délai. Au-delà :
    :class:`JournalLocked` (``journal verrouillé par un autre processus``).
    Le descripteur flock reste ouvert : le relâcher fermerait le verrou.

    Sur un disque local, flock (ou ``msvcrt``) suffit. Sur NFS ou SMB,
    flock peut être ignoré d'un client à l'autre : un fichier ``O_EXCL``
    (pid, instant de démarrage, boot id et machine-id) est pris avant.
    On ne le reprend que si cette identité est un processus terminé, ou
    si sa date n'a plus été rafraîchie depuis
    ``SENTINEL_HOSTLOCK_STALE_SECONDS``. flock reste en complément sur
    la même machine.
    """
    if timeout is None:
        timeout = JOURNAL_LOCK_TIMEOUT
    key = _journal_key(manifest_path)
    # Le même fil reprend le verrou : flock est déjà à nous, et un
    # ``LOCK_UN`` ici lâcherait la section extérieure.
    depth = _lock_depth.get(key, 0)
    if depth > 0:
        _lock_depth[key] = depth + 1
        return
    deadline = time.monotonic() + max(0.0, timeout)
    _raise_if_cancelled()
    path = _lock_file_path(manifest_path)
    fstype = _lock_fstype(os.path.dirname(path) or path)
    remote = fstype is not None and fstype in _REMOTE_LOCK_FS
    hostlock: str | None = None
    if remote and fstype is not None:
        _note_remote_lock(path, fstype)
        hostlock = _hostlock_path(manifest_path)
        _acquire_hostlock(hostlock, deadline)
    try:
        _acquire_kernel_lock(manifest_path, deadline)
    except BaseException:
        if hostlock is not None:
            _unlink_hostlock(hostlock)
        raise
    if _wait_cancelled():
        _unlock_kernel_lock(key)
        if hostlock is not None:
            _unlink_hostlock(hostlock)
        raise JournalInterrupted()
    _lock_depth[key] = 1
    if hostlock is not None:
        _held_hostlocks[key] = hostlock


def _release_process_lock(manifest_path: Path) -> None:
    key = _journal_key(manifest_path)
    depth = _lock_depth.get(key, 0)
    if depth > 1:
        _lock_depth[key] = depth - 1
        return
    if depth == 1:
        _lock_depth.pop(key, None)
    _unlock_kernel_lock(key)
    hostlock = _held_hostlocks.pop(key, None)
    if hostlock is not None:
        _unlink_hostlock(hostlock)


@contextlib.contextmanager
def _journal_exclusive(manifest_path: Path) -> Iterator[None]:
    """Fils, puis processus. Lecture, reprise, réécriture et appends.

    Un ``os.replace`` fait pendant qu'un autre processus a encore son
    descripteur append ouvert enverrait ses lignes vers l'inode détaché.
    On jette ce descripteur en entrant, et on le rouvre après le replace.
    L'attente du verrou est bornée (:data:`JOURNAL_LOCK_TIMEOUT`).
    Si la fermeture annule l'attente, on lâche tout de suite : le corps
    n'a pas commencé, le journal reste tel quel.
    """
    _acquire_thread_lock()
    acquired = False
    try:
        _acquire_process_lock(manifest_path)
        acquired = True
        if _wait_cancelled():
            raise JournalInterrupted()
        _retire_append_handle(manifest_path)
        yield
    finally:
        if acquired:
            _release_process_lock(manifest_path)
        _journal_lock.release()


def flush_quarantine_journals() -> None:
    """Vide les journaux ouverts sans attendre un déplacement en cours.

    Chaque ligne ajoutée est déjà ``fsync``. Si un move tient le verrou,
    on n'attend pas : une sortie forcée doit rester immédiate. Le tampon
    encore sale (un test, ou une ligne non encore synchronisée) est vidé
    seulement quand le verrou est libre.
    """
    if not _journal_lock.acquire(timeout=0):
        return
    try:
        keys = list(_journal_handles)
        for key in keys:
            handle = _journal_handles.get(key)
            if handle is None or handle.closed:
                _journal_handles.pop(key, None)
                continue
            if not _append_handle_matches(handle, key):
                _journal_handles.pop(key, None)
                _discard_append_handle(handle)
                continue
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            _journal_handles.pop(key, None)
    finally:
        _journal_lock.release()


def _terminate_partial_line_unlocked(manifest_path: Path) -> None:
    """Une dernière ligne coupée ne doit pas coller à l'append suivant."""
    key = _journal_key(manifest_path)
    _flush_journal_handle_unlocked(manifest_path)
    if not os.path.isfile(key):
        return
    size = os.path.getsize(key)
    if size <= 0:
        return
    with open(key, "rb") as fh:
        fh.seek(size - 1)
        if fh.read(1) == b"\n":
            return
    handle = _journal_file(manifest_path)
    handle.write(b"\n")
    handle.flush()
    os.fsync(handle.fileno())


def _manifest_append_unlocked(manifest_path: Path, record: dict) -> None:
    """Append + fsync. L'appelant tient le verrou exclusif du journal."""
    _terminate_partial_line_unlocked(manifest_path)
    payload = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    handle = _journal_file(manifest_path)
    handle.write(payload)
    handle.flush()
    os.fsync(handle.fileno())


def _manifest_append(manifest_path: Path, record: dict) -> None:
    """Append une ligne JSON au manifest avec fsync.

    P1-2 (M) : c'est la primitive transactionnelle. Chaque entrée est
    écrite individuellement et le fd est `fsync()`é — donc un crash
    après l'append ne perdra que ce qui était en cours d'écriture, pas
    les entrées précédentes. Le descripteur reste ouvert : la fermeture
    forcée le vide encore une fois avant ``os._exit``.

    Format : JSONL (une ligne JSON par record). Lisible par `jq -c .`,
    par `restore_paths`, et par les outils d'audit standard.
    """
    with _journal_exclusive(manifest_path):
        _manifest_append_unlocked(manifest_path, record)


def _close_journal_handle_unlocked(manifest_path: Path) -> None:
    """Ferme le descripteur append. L'appelant tient ``_journal_lock``."""
    key = _journal_key(manifest_path)
    handle = _journal_handles.pop(key, None)
    if handle is None or handle.closed:
        return
    handle.flush()
    os.fsync(handle.fileno())
    handle.close()


def _flush_journal_handle_unlocked(manifest_path: Path) -> None:
    key = _journal_key(manifest_path)
    handle = _journal_handles.get(key)
    if handle is None or handle.closed:
        return
    handle.flush()
    os.fsync(handle.fileno())


def _fsync_directory(parent: str) -> None:
    """Durcit l'entrée de répertoire après ``os.replace`` (POSIX)."""
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    directory = getattr(os, "O_DIRECTORY", 0)
    fd = os.open(parent, flags | directory)
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            # Un dossier ne se synchronise pas partout (EINVAL, ENOTSUP).
            if exc.errno not in (
                errno.EINVAL,
                errno.ENOTSUP,
                getattr(errno, "EBADF", 9),
            ):
                raise
    finally:
        os.close(fd)


def _journal_line_bytes(records: list[dict | str]) -> bytes:
    parts: list[str] = []
    for rec in records:
        if isinstance(rec, str):
            parts.append(rec.rstrip("\r\n") + "\n")
        else:
            parts.append(json.dumps(rec, sort_keys=True) + "\n")
    return "".join(parts).encode("utf-8")


def _manifest_replace(manifest_path: Path, records: list[dict | str]) -> None:
    """Réécrit le journal. L'appelant tient ``_journal_exclusive``.

    Fichier temporaire, fsync, ``os.replace``, fsync du répertoire, puis
    réouverture du descripteur append sur le nouvel inode. Les lignes
    illisibles (``str``) sont réécrites telles quelles.
    """
    if not _journal_lock.locked():
        raise RuntimeError("réécriture du journal hors verrou")
    payload = _journal_line_bytes(records)
    key = _journal_key(manifest_path)
    parent = os.path.dirname(key) or "."
    os.makedirs(parent, exist_ok=True)
    _close_journal_handle_unlocked(manifest_path)
    fd, tmp_name = tempfile.mkstemp(prefix=".journal-", suffix=".tmp", dir=parent)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("écriture du journal interrompue")
            view = view[written:]
        os.chmod(tmp_name, 0o644)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        os.replace(tmp_name, key)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    _fsync_directory(parent)
    _journal_file(manifest_path)


def _intent_line(plan: _PlannedQuarantine, journal_id: str) -> dict:
    """Ligne « en cours » : assez pour remettre le fichier à sa place."""
    return {
        "id": journal_id,
        "original": str(plan.src),
        "quarantined": str(plan.dest),
        "sha256": plan.sha256,
        "size": plan.size,
        "mode_before": plan.mode_before,
        "_status": "en cours",
        "_appended_at": _utcnow_iso(),
    }


def _journal_path_exists(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    return _entry_exists(Path(value))


def _pending_intents(records: list[dict]) -> list[dict]:
    """Intentions dont la dernière ligne pour cet id est encore « en cours »."""
    latest: dict[str, dict] = {}
    order: list[str] = []
    for rec in records:
        ident = rec.get("id")
        if not isinstance(ident, str) or not ident:
            continue
        if ident not in latest:
            order.append(ident)
        latest[ident] = rec
    return [latest[ident] for ident in order if latest[ident].get("_status") == "en cours"]


def _read_journal_lines_unlocked(manifest_path: Path) -> list[dict | str]:
    """Lit le JSONL. Les lignes illisibles restent des ``str``.

    L'appelant tient le verrou exclusif. Une réécriture qui ne garderait
    que les dicts jetterait ces lignes : elles sont donc renvoyées.
    """
    _flush_journal_handle_unlocked(manifest_path)
    key = _journal_key(manifest_path)
    if not os.path.isfile(key):
        return []
    out: list[dict | str] = []
    try:
        with open(key, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                text = raw.strip()
                if not text:
                    continue
                try:
                    rec = json.loads(text)
                except ValueError as exc:
                    print(
                        f"⚠ manifest ligne {lineno} corrompue: {exc}",
                        file=sys.stderr,
                    )
                    out.append(text)
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
                else:
                    print(
                        f"⚠ manifest ligne {lineno} corrompue: objet attendu",
                        file=sys.stderr,
                    )
                    out.append(text)
    except OSError as exc:
        print(f"⚠ manifest illisible: {exc}", file=sys.stderr)
    return out


def _read_journal_unlocked(manifest_path: Path) -> list[dict]:
    """Objets JSON du journal. L'appelant tient le verrou exclusif."""
    return [rec for rec in _read_journal_lines_unlocked(manifest_path) if isinstance(rec, dict)]


def _resolve_intent(intent: dict, manifest_path: Path) -> tuple[dict, dict[str, str] | None]:
    """Décide confirmation, annulation ou incohérence. Ne supprime rien."""
    at_origin = _journal_path_exists(intent.get("original"))
    in_quarantine = _journal_path_exists(intent.get("quarantined"))
    resolved = dict(intent)
    resolved["_appended_at"] = _utcnow_iso()
    issue: dict[str, str] | None = None
    if in_quarantine and not at_origin:
        resolved["_status"] = "done"
        if not resolved.get("moved_at"):
            resolved["moved_at"] = resolved["_appended_at"]
    elif at_origin and not in_quarantine:
        resolved["_status"] = "annulé"
    else:
        if at_origin and in_quarantine:
            reason = "les deux emplacements existent"
        else:
            reason = "aucun des deux emplacements n'existe"
        resolved["_status"] = "incohérent"
        resolved["_reason"] = reason
        issue = {
            "manifest": str(manifest_path),
            "id": str(intent.get("id", "")),
            "original": str(intent.get("original", "")),
            "quarantined": str(intent.get("quarantined", "")),
            "reason": reason,
        }
    return resolved, issue


def _recover_unlocked(manifest_path: Path) -> list[dict[str, str]]:
    """Reprend les « en cours ». L'appelant tient le verrou exclusif.

    Un move encore en cours dans un autre processus tient ce verrou :
    on ne s'exécute qu'après sa confirmation, ou après sa mort (le
    noyau lâche alors le verrou et l'état du disque est le bon).
    """
    records = _read_journal_unlocked(manifest_path)
    pending = _pending_intents(records)
    if pending and _after_pending_read is not None:
        _after_pending_read()
    issues: list[dict[str, str]] = []
    for intent in pending:
        resolved, issue = _resolve_intent(intent, manifest_path)
        _manifest_append_unlocked(manifest_path, resolved)
        if issue is not None:
            issues.append(issue)
    return issues


def recover_journal(manifest_path: Path) -> list[dict[str, str]]:
    """Reprend chaque entrée laissée « en cours ». Idempotent, sous le verrou.

    - en quarantaine, absente de l'origine → confirmée (``done``) ;
    - encore à l'origine, absente de la quarantaine → annulée ;
    - les deux, ou aucun → ``incohérent``. Rien n'est supprimé.

    Retourne les entrées devenues incohérentes. Un journal absent n'est
    pas créé.
    """
    if not os.path.isfile(_journal_key(manifest_path)):
        return []
    with _journal_exclusive(manifest_path):
        return _recover_unlocked(manifest_path)


def format_journal_issues(issues: list[dict[str, str]]) -> str:
    """Texte montré à l'utilisateur. Aucun chemin n'a été effacé."""
    lines = [
        "Journal de quarantaine incohérent. Rien n'a été supprimé.",
        "Vérifiez les chemins ci-dessous avant toute restauration.",
    ]
    for issue in issues:
        lines.append(
            f"• id {issue.get('id', '')} : {issue.get('reason', '')}\n"
            f"  origine : {issue.get('original', '')}\n"
            f"  quarantaine : {issue.get('quarantined', '')}\n"
            f"  journal : {issue.get('manifest', '')}"
        )
    return "\n".join(lines)


def default_journal_path() -> Path:
    """Journal CLI par défaut, relatif au répertoire courant."""
    return Path(DEFAULT_QUARANTINE_NAME) / "manifest.jsonl"


def init_engine(manifests: Iterable[Path] | None = None) -> list[dict[str, str]]:
    """Reprise au démarrage du moteur, du CLI et de l'interface.

    Sans argument : le journal par défaut ``.sentinel-quarantine/manifest.jsonl``.
    Idempotent. Les incohérences sont écrites sur stderr.
    """
    paths = list(manifests) if manifests is not None else [default_journal_path()]
    seen: set[str] = set()
    issues: list[dict[str, str]] = []
    for path in paths:
        key = os.path.abspath(os.fspath(path))
        if key in seen:
            continue
        seen.add(key)
        issues.extend(recover_journal(Path(key)))
    if issues:
        print(format_journal_issues(issues), file=sys.stderr)
    return issues


def read_manifest(manifest_path: Path) -> list[dict]:
    """Toutes les entrées du journal JSONL, y compris celles déjà restaurées."""
    return _manifest_read_all(manifest_path)


def _manifest_read_all(manifest_path: Path) -> list[dict]:
    """Lit TOUTES les entrées d'un manifest JSONL, quel que soit leur statut.

    Tolère les lignes corrompues (les skippe avec un warning). Utilisé par
    `restore_paths`, qui doit préserver les entrées déjà restaurées (audit)
    et les états intermédiaires au lieu de les jeter.
    """
    if not manifest_path.is_file():
        return []
    out: list[dict] = []
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError as exc:
                    print(
                        f"⚠ manifest ligne {lineno} corrompue: {exc}",
                        file=sys.stderr,
                    )
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    except OSError as exc:
        print(f"⚠ manifest illisible: {exc}", file=sys.stderr)
    return out


def _manifest_read(manifest_path: Path) -> list[dict]:
    """Entrées encore actives (`done` ou sans statut).

    Les entrées `restored` sont exclues : elles restent dans le fichier
    pour l'audit, mais ne doivent pas être restaurées une seconde fois.
    """
    return [
        rec for rec in _manifest_read_all(manifest_path) if rec.get("_status") in (None, "done")
    ]


def _restore_aside(original: Path) -> Path:
    """Nom libre à côté de `original` pour le mettre de côté le temps du move."""
    i = 0
    while True:
        suffix = "" if i == 0 else f".{i}"
        cand = original.with_name(f".{original.name}.sentinel-restore-aside{suffix}")
        if not cand.exists():
            return cand
        i += 1


def _make_writable(p: Path) -> None:
    """Rend un fichier (ou un dossier) accessible en écriture.

    Les fichiers en quarantaine sont en 0444/0555. Pour les déplacer,
    il faut d'abord les repasser en 0644/0755. On le fait sur le parent
    si nécessaire (le déplacement d'un dossier exige que le parent
    destination soit writable).
    """
    # Si c'est un dossier, on doit rendre les enfants writables d'abord
    # sinon on ne peut pas traverser pour les déplacer ensuite.
    if is_link(p):
        return

    def _unlock(node: Path) -> None:
        if os.name == "nt":
            unlock_quarantine_path(node)
            return
        mode = node.stat().st_mode
        node.chmod(mode | stat.S_IWUSR)

    if p.is_dir():
        for child in _iter_nofollow(p):
            if is_link(child):
                continue
            try:
                _unlock(child)
            except OSError:
                if os.name == "nt":
                    raise
        try:
            _unlock(p)
        except OSError:
            if os.name == "nt":
                raise
    else:
        try:
            _unlock(p)
        except OSError:
            if os.name == "nt":
                raise


def _restore_one(record: dict, dest_dir: Path, force: bool) -> tuple[dict | None, str | None]:
    """Restaure un fichier depuis le manifest.

    Retourne (record_restauré, message_d_erreur). Si la restauration
    réussit, `record_restauré` est le dict à ré-écrire dans le manifest
    (avec `restored_at` ajouté). Sinon, `message_d_erreur` explique.
    """
    original = Path(record["original"])
    quarantined = Path(record["quarantined"])
    # Le paramètre `dest_dir` est documenté comme une validation : sans
    # ce contrôle, un manifest modifié déplaçait n'importe quel fichier
    # lisible par l'utilisateur (chemin `quarantined` arbitraire), pas
    # seulement une entrée du dossier de quarantaine.
    if not _entry_is_inside_dir(quarantined, dest_dir):
        return None, (f"refus : {quarantined} n'est pas dans le dossier de quarantaine {dest_dir}")
    if not _entry_exists(quarantined):
        return None, f"fichier de quarantaine introuvable: {quarantined}"

    # 0. Vérifier que le contenu en quarantaine est bien celui qu'on a
    #    déplacé. Sans ce contrôle, un fichier remplacé ou corrompu dans
    #    le dossier de quarantaine (0444 n'empêche pas root, ni un
    #    remontage) était restauré silencieusement à la place de l'original.
    expected = record.get("sha256")
    if isinstance(expected, str):
        try:
            actual, _size, _mode = _hash_and_stat(quarantined)
        except OSError as exc:
            return None, f"impossible de relire {quarantined}: {exc}"
        # Les manifests anciens enregistraient "" pour un fichier vide.
        # On n'accepte ce marqueur que si le fichier est encore vide :
        # un contenu ajouté après coup est un remplacement.
        legacy_empty = expected == "" and quarantined.is_file() and not is_link(quarantined)
        if legacy_empty:
            try:
                still_empty = quarantined.stat().st_size == 0
            except OSError as exc:
                return None, f"impossible de relire {quarantined}: {exc}"
            if not still_empty:
                return None, (
                    "intégrité compromise: fichier vide attendu, "
                    "contenu présent — restauration refusée"
                )
        elif actual != expected:
            legacy_ok = False
            if quarantined.is_dir() and not is_link(quarantined):
                try:
                    legacy_ok = _legacy_dir_hash(quarantined) == expected
                except OSError:
                    legacy_ok = False
            if not legacy_ok:
                return None, (
                    f"intégrité compromise: sha256 attendu {expected[:12]}…, "
                    f"calculé {actual[:12]}… — restauration refusée"
                )

    # 1. L'original est-il déjà là ?
    if _entry_exists(original) and not force:
        return None, (f"chemin d'origine déjà occupé: {original} (utilisez --force pour écraser)")

    # 2. Rendre le fichier writable (sinon shutil.move échoue en lecture).
    _make_writable(quarantined)

    # 3. S'assurer que le parent destination existe.
    original.parent.mkdir(parents=True, exist_ok=True)

    # 4. Si l'original existe et qu'on force, on le met de côté PUIS on
    #    ramène le fichier de quarantaine. L'unlink d'abord laissait un trou
    #    si le move suivant échouait : l'original était déjà détruit.
    aside: Path | None = None
    if _entry_exists(original) and force:
        if original.is_dir() and not is_link(original):
            return None, (
                f"le chemin d'origine est un dossier ({original}) : "
                "restauration refusée pour ne rien supprimer. Déplacez-le manuellement."
            )
        aside = _restore_aside(original)
        try:
            shutil.move(str(original), str(aside))
        except OSError as exc:
            return None, f"impossible de mettre de côté l'original {original}: {exc}"

    # 5. Déplacer. En cas d'échec, l'original mis de côté est remis en place.
    #    Un move cross-filesystem peut laisser un fichier partiel sur
    #    `original` : ce n'est pas l'occupant précédent (il est dans `aside`).
    #    On retire ce résidu avant de remettre `aside`, sinon le rollback
    #    voit le chemin occupé et ne tente rien.
    try:
        shutil.move(str(quarantined), str(original))
    except OSError as exc:
        if aside is not None:
            try:
                _discard_partial(original)
                if _entry_exists(aside):
                    shutil.move(str(aside), str(original))
            except OSError as back:
                return None, (
                    f"impossible de restaurer {quarantined} → {original}: {exc} "
                    f"(l'original est resté de côté : {aside}; rollback: {back})"
                )
        return None, f"impossible de restaurer {quarantined} → {original}: {exc}"
    if aside is not None and _entry_exists(aside):
        try:
            aside.unlink()
        except OSError:
            pass

    # 6. Remettre le mode d'origine (qu'on a stocké en mode_before).
    #    Pas sur un lien : chmod suivrait la cible.
    mode_before = record.get("mode_before")
    if mode_before is not None and _entry_exists(original) and not is_link(original):
        try:
            apply_saved_mode(original, int(mode_before))
        except (OSError, TypeError, ValueError):
            pass

    # 7. Marqué comme restauré.
    restored = dict(record)
    restored["restored_at"] = _utcnow_iso()
    return restored, None


def restore_paths(
    manifest_path: Path,
    dest_dir: Path,
    force: bool = False,
    only: set[str] | None = None,
) -> tuple[list[dict], list[tuple[Path, str]]]:
    """Restaure les fichiers en quarantaine à leur emplacement d'origine.

    P1-1 (M) : sans cette fonction, la quarantaine est sans appel. Si
    l'utilisateur a mis un fichier innocent en quarantaine, il est
    coincé. Cette fonction rejoue l'opération inverse : pour chaque
    entrée du manifest, remet le fichier au chemin `original` (en
    restaurant le `mode_before`).

    Paramètres :
      - `manifest_path` : chemin du manifest JSON.
      - `dest_dir` : dossier de quarantaine (utilisé pour validation,
        pas pour la résolution — le manifest stocke les chemins
        absolus).
      - `force` : si True, écrase les fichiers d'origine déjà présents.
      - `only` : si fourni, ne restaure que les entrées dont le chemin
        d'origine est dans ce set (filtre — pratique pour la
        restauration sélective depuis la CLI).

    Retourne (records_restaurés, échecs). Le manifest est ré-écrit avec
    **toutes** les entrées : celles qui viennent d'être restaurées y restent,
    marquées `_status="restored"` + `restored_at`. Un journal d'audit qui
    perd la trace des fichiers restaurés ne vaut rien : on doit pouvoir
    répondre à « ce fichier a-t-il été mis en quarantaine, quand, et
    quand a-t-il été remis ? ».
    """
    # Lecture, reprise, déplacements et réécriture sous le même verrou.
    # Sinon un append concurrent est perdu : la réécriture remplace le
    # fichier, et l'autre processus continue d'écrire l'inode détaché.
    if not os.path.isfile(_journal_key(manifest_path)):
        return [], []

    restored: list[dict] = []
    failures: list[tuple[Path, str]] = []
    with _journal_exclusive(manifest_path):
        # Une intention « en cours » dont le fichier est déjà en quarantaine
        # devient « done » avant d'être rejouée. Rien n'est supprimé.
        startup_issues = _recover_unlocked(manifest_path)
        if startup_issues:
            print(format_journal_issues(startup_issues), file=sys.stderr)
        # P1-2 : le manifest est un JSONL (une ligne par record). On lit TOUT,
        # y compris les entrées déjà restaurées et les lignes illisibles.
        all_records = _read_journal_lines_unlocked(manifest_path)
        if not all_records:
            return [], []

        remaining: list[dict | str] = []

        for rec in all_records:
            # Ligne illisible, déjà restaurée, ou état intermédiaire :
            # on la conserve telle quelle, on ne la rejoue pas.
            if not isinstance(rec, dict) or rec.get("_status") not in (None, "done"):
                remaining.append(rec)
                continue
            original = Path(rec.get("original", ""))
            if only is not None and str(original) not in only:
                # Pas concerné par cette restauration.
                remaining.append(rec)
                continue
            ok, err = _restore_one(rec, dest_dir, force)
            if err is not None or ok is None:
                if err is None:
                    err = "restauration incomplète"
                failures.append((original, err))
                print(f"  ✗ {original} : {err}", file=sys.stderr)
                # On garde l'entrée pour ne pas perdre la trace d'un échec.
                remaining.append(rec)
            else:
                restored.append(ok)
                print(f"  ✓ {original} restauré", file=sys.stderr)
                # Marqué comme restauré, mais CONSERVÉ dans le journal.
                ok["_status"] = "restored"
                remaining.append(ok)

        # Ré-écrit le manifest avec les entrées non restaurées.
        # P1-2 : on garde le format JSONL. On ré-écrit tout le fichier
        # (c'est ok : restore est une opération ponctuelle, pas dans la
        # boucle chaude). Sous le verrou, via un fichier temporaire : un
        # crash au milieu ne laisse pas un journal à moitié tronqué.
        _manifest_replace(manifest_path, remaining)
    if restored:
        print(
            f"\n{len(restored)} fichier(s) restauré(s). "
            f"{len(remaining)} entrée(s) au journal "
            f"(les restaurées y restent, marquées `restored`).",
            file=sys.stderr,
        )
    return restored, failures
