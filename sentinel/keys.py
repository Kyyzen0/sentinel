"""Résolution de la clé HMAC sans la laisser dans l'historique du shell.

Trois sources, mutuellement exclusives :

- ``--key-file PATH`` : sur POSIX, fichier en mode 0600 (refusé s'il est
  lisible par le groupe ou les autres). Sur Windows, l'ACL doit limiter
  la lecture au compte courant, à SYSTEM et aux Administrateurs ;
- variable d'environnement ``SENTINEL_KEY`` ;
- ``--encrypt-key`` : conservé, mais déprécié — la valeur est visible via
  l'historique du shell et la liste des processus.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path

from .platform import resolved_key, windows_key_acl_problem

ENV_NAME = "SENTINEL_KEY"

DEPRECATION_WARNING = (
    "⚠ --encrypt-key est déprécié : la clé apparaît dans l'historique du shell "
    "et dans la liste des processus (ps). Préférez la variable d'environnement "
    f"{ENV_NAME} ou --key-file PATH (chmod 600, ou ACL limitée au compte sur Windows)."
)


class KeySourceError(Exception):
    """La clé n'a pas pu être lue, ou plusieurs sources se contredisent."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def read_key_file(path: Path) -> str:
    """Lit une clé depuis ``path``.

    Refuse un fichier lisible par d'autres comptes. Sur POSIX c'est le
    mode (``S_IRGRP`` / ``S_IROTH``). Sur Windows les bits renvoyés par
    ``stat`` sont fictifs (souvent 0666) : on lit le DACL. Un échec de
    lecture de l'ACL refuse la clé. Un lien symbolique est accepté si
    la cible elle-même est un fichier régulier assez strict (``stat``
    suit le lien ; l'ACL Windows aussi).
    """
    try:
        located = Path(resolved_key(path))
        st = located.stat()
    except OSError as exc:
        raise KeySourceError(f"Fichier de clé illisible ({path}) : {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise KeySourceError(f"Pas un fichier régulier : {path}")
    if os.name == "nt":
        problem = windows_key_acl_problem(located)
        if problem:
            raise KeySourceError(problem)
    elif st.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        mode = oct(st.st_mode & 0o777)
        raise KeySourceError(
            f"Refus : {path} est lisible par le groupe ou les autres (mode {mode}). "
            "Une clé group/world-readable reste exposée. `chmod 600` puis relancez."
        )
    try:
        text = located.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeySourceError(f"Fichier de clé illisible ({path}) : {exc}") from exc
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    if text == "":
        raise KeySourceError(f"Fichier de clé vide : {path}")
    return text


def resolve_key(
    *,
    encrypt_key: str | None,
    key_file: Path | None,
    environ: Mapping[str, str] | None = None,
) -> tuple[str | None, tuple[str, ...]]:
    """Retourne ``(clé, avertissements)``.

    ``clé`` vaut None si aucune source n'est fournie. Lève
    ``KeySourceError`` si deux sources sont définies, si le fichier est
    refusé, ou si ``SENTINEL_KEY`` est présente mais vide.
    """
    env = os.environ if environ is None else environ
    warnings: list[str] = []
    sources: list[str] = []
    if key_file is not None:
        sources.append("--key-file")
    if ENV_NAME in env:
        if env.get(ENV_NAME, "") == "":
            raise KeySourceError(f"{ENV_NAME} est définie mais vide.")
        sources.append(ENV_NAME)
    if encrypt_key is not None:
        sources.append("--encrypt-key")
    if len(sources) > 1:
        raise KeySourceError(
            "Plusieurs sources de clé ("
            + ", ".join(sources)
            + "). Choisissez-en une seule parmi --key-file, "
            f"{ENV_NAME} et --encrypt-key."
        )
    if key_file is not None:
        return read_key_file(key_file), tuple(warnings)
    if ENV_NAME in env:
        return env[ENV_NAME], tuple(warnings)
    if encrypt_key is not None:
        warnings.append(DEPRECATION_WARNING)
        return encrypt_key, tuple(warnings)
    return None, tuple(warnings)
