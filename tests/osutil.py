"""Aides de tests qui ont un vrai équivalent sur Windows.

Les tests historiques faisaient ``chmod``. Sur POSIX on garde exactement
ça. Sur Windows ``chmod`` ne change pas l'ACL : on passe par les mêmes
fonctions que le produit, pour que la suite échoue si le contrôle est un
no-op.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


def is_privileged() -> bool:
    """Root Unix. Sur Windows le bit « root » n'existe pas : False."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def seal_private(path: Path) -> None:
    from sentinel.platform import restrict_key_file

    restrict_key_file(path)


def loosen_private(path: Path, mode: int = 0o644) -> None:
    from sentinel.platform import expose_key_file

    if os.name == "nt":
        expose_key_file(path)
        return
    path.chmod(mode)


def deny_read(path: Path) -> int:
    from sentinel.platform import make_unreadable

    return make_unreadable(path)


def allow_read(path: Path, previous: int) -> None:
    from sentinel.platform import restore_access

    restore_access(path, previous)


def release_quarantine_write(path: Path) -> None:
    """Autorise l'écriture pour simuler une altération en test.

    POSIX : ``chmod``. Windows : l'ACE deny de quarantaine bloque
    ``FILE_WRITE_DATA`` même après ``chmod``. Le propriétaire garde
    ``WRITE_DAC`` ; on remplace l'ACL comme ``restore`` le fait.
    """
    if os.name == "nt":
        from sentinel._winapi import grant_user_full

        grant_user_full(path)
        os.chmod(path, stat.S_IWRITE)
        return
    path.chmod(0o755 if path.is_dir() else 0o644)


def _make_writable(path: Path) -> None:
    """Rend une entrée effaçable sans suivre un lien.

    POSIX : bit d'écriture (et d'exécution sur un dossier) pour le
    propriétaire. Windows : l'ACL de quarantaine peut refuser
    l'écriture même au propriétaire, et l'attribut lecture seule bloque
    ``DeleteFile``. On remplace le DACL puis on retire l'attribut.
    """
    try:
        mode = path.lstat().st_mode
    except OSError:
        return
    if stat.S_ISLNK(mode):
        return
    if os.name == "nt":
        try:
            from sentinel._winapi import grant_user_full

            grant_user_full(path)
        except OSError:
            pass
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        return
    extra = stat.S_IWUSR | stat.S_IRUSR
    if stat.S_ISDIR(mode):
        extra |= stat.S_IXUSR
    try:
        os.chmod(path, stat.S_IMODE(mode) | extra)
    except OSError:
        pass


def remove_tree(path: Path | str, *, ignore_errors: bool = False) -> None:
    """Supprime un arbre, y compris un dossier de quarantaine en 0555."""
    root = Path(path)
    if root.is_symlink():
        root.unlink(missing_ok=True)
        return
    if not root.exists():
        return
    if not root.is_dir():
        _make_writable(root)
        root.unlink(missing_ok=True)
        return
    _make_writable(root)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        _make_writable(current)
        for name in dirnames:
            child = current / name
            if not child.is_symlink():
                _make_writable(child)
        for name in filenames:
            child = current / name
            if not child.is_symlink():
                _make_writable(child)
    shutil.rmtree(root, ignore_errors=ignore_errors)


def install_temp_cleanup() -> None:
    """Les ``mkdtemp`` de la suite sont retirés en fin de processus.

    ``TemporaryDirectory`` réessaie avec :func:`remove_tree` si le
    dossier de quarantaine, en 0555, a fait échouer ``rmtree``.
    """
    import atexit
    import tempfile

    if getattr(tempfile, "_sentinel_cleanup", False):
        return
    tempfile._sentinel_cleanup = True  # type: ignore[attr-defined]
    original_mkdtemp = tempfile.mkdtemp
    original_directory = tempfile.TemporaryDirectory
    created: list[str] = []

    def mkdtemp(*args, **kwargs):  # type: ignore[no-untyped-def]
        path = original_mkdtemp(*args, **kwargs)
        created.append(path)
        return path

    class CleaningTemporaryDirectory(original_directory):  # type: ignore[misc, valid-type]
        def cleanup(self) -> None:
            name = self.name
            try:
                super().cleanup()
            except Exception:
                remove_tree(name, ignore_errors=True)
            else:
                if os.path.exists(name):
                    remove_tree(name, ignore_errors=True)

    def _flush() -> None:
        for path in created:
            remove_tree(path, ignore_errors=True)

    atexit.register(_flush)
    tempfile.mkdtemp = mkdtemp  # type: ignore[assignment]
    tempfile.TemporaryDirectory = CleaningTemporaryDirectory  # type: ignore[misc, assignment]


def unlink_readonly(path: Path) -> None:
    """Supprime une entrée, y compris un fichier de quarantaine.

    Sur POSIX le propriétaire du dossier peut ``unlink`` un 0444. Sur
    Windows ``DeleteFile`` refuse tant que l'attribut lecture seule est
    posé. L'ACL de quarantaine accorde ``FILE_WRITE_ATTRIBUTES`` et
    ``DELETE`` au compte courant, pas ``FILE_WRITE_DATA`` : on retire
    l'attribut, puis on supprime.
    """
    if os.name == "nt":
        os.chmod(path, stat.S_IWRITE)
    path.unlink()


def writable_mode(path: Path) -> bool:
    return bool(path.stat().st_mode & stat.S_IWUSR)


def reported_mode(path: Path) -> int:
    """Bits que le test peut comparer.

    Windows ne distingue que la lecture seule : 0666 ou 0444 (et 0555
    pour un dossier). POSIX renvoie le mode réel.
    """
    mode = stat.S_IMODE(path.stat().st_mode)
    if os.name != "nt":
        return mode
    if path.is_dir():
        return 0o555 if not (mode & 0o222) else 0o777
    return 0o444 if not (mode & 0o222) else 0o666
