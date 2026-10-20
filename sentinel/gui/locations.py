"""Dossiers de données et chemins proposés, selon le système."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath


def data_dir_text(
    *,
    platform: str,
    os_name: str,
    home: str,
    environ: Mapping[str, str],
) -> str:
    """Chemin d'état, sans toucher au disque.

    ``PureWindowsPath`` (pas ``Path``) : sur Linux, construire un
    ``WindowsPath`` lève ``NotImplementedError``.
    """
    if platform == "darwin":
        return str(PurePosixPath(home) / "Library" / "Application Support" / "Sentinel")
    if os_name == "nt":
        local = environ.get("LOCALAPPDATA")
        base = local if local else str(PureWindowsPath(home) / "AppData" / "Local")
        return str(PureWindowsPath(base) / "Sentinel")
    xdg = environ.get("XDG_DATA_HOME")
    root = xdg if xdg else str(PurePosixPath(home) / ".local" / "share")
    return str(PurePosixPath(root) / "sentinel")


def data_dir() -> Path:
    """État de l'application (dernier scan). Jamais la clé HMAC."""
    base = Path(
        data_dir_text(
            platform=sys.platform,
            os_name=os.name,
            home=str(Path.home()),
            environ=os.environ,
        )
    )
    base.mkdir(parents=True, exist_ok=True)
    return base


def default_scan_paths() -> list[Path]:
    """Dossiers utilisateur proposés. On ne propose pas ``/`` ni ``C:\\``."""
    home = Path.home()
    names = ["Desktop", "Documents", "Downloads"]
    if sys.platform.startswith("linux"):
        names.append("bin")
    found = [home]
    for name in names:
        candidate = home / name
        if candidate.is_dir() and candidate not in found:
            found.append(candidate)
    return found


def sensitive_scan_note(path: Path) -> str | None:
    """Avertissement si le dossier ressemble à un chemin de quarantaine interdit.

    Le scan, lui, reste autorisé : inspecter ``/etc`` est un usage normal.
    """
    from sentinel.platform import live_dest_class

    kind = live_dest_class(path)
    if kind == "hard":
        return (
            f"{path} est un chemin critique (compte, secrets, racine). "
            "Le scan est permis, la quarantaine vers cet endroit ne l'est pas."
        )
    if kind == "soft":
        return f"{path} est un répertoire sensible (configuration ou système)."
    return None
