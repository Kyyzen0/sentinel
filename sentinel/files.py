"""Lecture texte des fichiers à scanner."""

from __future__ import annotations

import codecs
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# Taille d'une fenêtre de scan. Le fichier entier est couvert, fenêtre
# après fenêtre : la mémoire reste bornée par environ deux fenêtres plus
# l'overlap, quelle que soit la taille du fichier.
# `read_text_safely` continue d'échantillonner au plus cette taille pour
# l'anomalie et le réseau (un score, pas une signature).
DEFAULT_MAX_FILE_BYTES = 8_000_000

# None : overlap mesuré sur les signatures au premier scan (au moins 512,
# et au moins le plus long motif borné). Les tests peuvent forcer une valeur.
SIGNATURE_OVERLAP_CHARS: int | None = None
_MEASURED_OVERLAP: int | None = None

# Dossiers techniques jamais analysés (cache Python, etc.).
_IGNORED_DIR_NAMES = frozenset({"__pycache__"})

# Caractères blancs formatés comme « imprimables » malgré leur catégorie Cc.
_BLANK_CONTROL = frozenset("\t\n\r")
# Caractère Unicode produit par UTF-8 `errors="replace"` quand un octet
# ne forme pas une séquence valide — sert de signal pour le binaire.
_REPLACEMENT_CHAR = "\ufffd"

# Seuil : si plus de 30 % des caractères décodés sont non-imprimables, on
# traite le fichier comme binaire. C'est le même seuil qu'avant, mais
# calculé sur la chaîne décodée — pas sur les octets bruts — pour ne pas
# rejeter les textes CJK / emoji / accentués.
_BINARY_RATIO_THRESHOLD = 0.30


def is_ignored(path: Path) -> bool:
    """Vrai si le chemin traverse un dossier ignoré (`__pycache__`, toute profondeur).

    L'ancien test `path.name.startswith("__pycache__")` ne matchait que les
    fichiers *nommés* `__pycache__…`, jamais les fichiers *contenus* dans un
    dossier `__pycache__/` : les `.pyc` étaient donc scannés et indexés.
    """
    return any(part in _IGNORED_DIR_NAMES for part in path.parts)


def _count_unusual_chars(text: str) -> int:
    """Nombre de caractères non-imprimables dans la chaîne DÉCODÉE.

    Couvre :
      - `Cc` : caractères de contrôle (sauf tab/newline/CR, tolérés)
      - `\ufffd` (caractère de remplacement) : indique un octet mal décodé

    Les espaces (catégorie Zs) et tout le reste (lettres, ponctuation,
    idéogrammes, emoji, etc.) sont considérés imprimables.
    """
    n = 0
    for ch in text:
        if ch in _BLANK_CONTROL:
            continue
        if ch == _REPLACEMENT_CHAR:
            n += 1
            continue
        if unicodedata.category(ch) == "Cc":
            n += 1
    return n


def looks_binary(data: bytes) -> bool:
    """Vrai si le contenu est vraiment binaire (à ignorer).

    Trois signaux combinés :

    1. NUL (`\\x00`) répétés — signature forte de binaire. Un NUL *isolé*
       (rare, type padding ou encodage mixte) n'est pas décisif ; on ne
       déclare binaire qu'au-dessus d'un seuil de ratio (5 %).

    2. Sur la chaîne décodée (UTF-8 `errors="replace"`) : on compte les
       caractères non-imprimables (catégorie Unicode `Cc` hors blanc +
       caractère de remplacement `\\ufffd`). On ne travaille **plus** sur
       les octets bruts, ce qui élimine le faux positif sur les textes
       CJK / emoji / latin étendu.

    3. Le ratio seuillé à 30 % : au-delà, on est probablement face à du
       binaire (un fichier UTF-8 légitime a très peu de contrôles).
    """
    if not data:
        return False
    # NUL : un seul est OK (padding, encodage mixte), beaucoup = binaire.
    nul_ratio = data.count(b"\x00") / len(data)
    if nul_ratio > 0.05:
        return True
    text = data.decode("utf-8", errors="replace")
    if not text:
        return False
    unusual = _count_unusual_chars(text)
    return unusual / len(text) > _BINARY_RATIO_THRESHOLD


class BinarySkipped(Exception):
    """Le fichier est binaire : on ne le scanne pas, et ce n'est pas une erreur."""


class UnreadablePath(Exception):
    """Le chemin existe mais n'a pas pu être lu (permissions, EIO, …)."""

    def __init__(self, path: Path, err: OSError) -> None:
        super().__init__(str(err))
        self.path = path
        self.err = err


@dataclass(frozen=True)
class TextWindow:
    """Morceau de texte couvrant une portion du fichier.

    `start_line` est le numéro (1-based) de la première ligne du morceau,
    même si le morceau commence au milieu de cette ligne.
    `overlap_chars` caractères en tête ont déjà été vus dans la fenêtre
    précédente : les lignes qui s'y terminent sont des doublons.
    """

    text: str
    start_line: int
    overlap_chars: int


def signature_overlap_chars() -> int:
    """Overlap entre deux fenêtres.

    Au moins aussi long que le plus long match borné (et que le plus long
    littéral d'un motif non borné), avec un plancher de 512. Les motifs
    `.*` / `\\s+` ne sont pas coupés tant que la ligne tient dans la
    fenêtre : la coupe se fait sur un saut de ligne. Une ligne plus
    longue que la fenêtre est coupée, et l'overlap rattrape un match qui
    chevauche la coupe.
    """
    if SIGNATURE_OVERLAP_CHARS is not None:
        return SIGNATURE_OVERLAP_CHARS
    global _MEASURED_OVERLAP
    if _MEASURED_OVERLAP is None:
        from .signatures import measured_signature_overlap

        _MEASURED_OVERLAP = measured_signature_overlap()
    return _MEASURED_OVERLAP


def read_text_safely(path: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> str | None:
    """Échantillon texte borné. None si illisible ou binaire.

    Utilisé par l'anomalie et l'autoencodeur, qui ont besoin d'un extrait
    et non d'une couverture exhaustive. Le scan de signatures passe par
    `iter_text_windows`, qui couvre tout le fichier.
    """
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return None
    if not data:
        return ""
    if looks_binary(data):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _cut_point(buffer: str, chunk: int, eof: bool) -> int | None:
    """Nombre de caractères neufs à consommer.

    Sur un saut de ligne quand c'est possible, pour ne pas couper une
    signature au milieu d'une ligne courte. Sinon coupe franche : l'overlap
    de la fenêtre suivante couvre le match qui chevauche.
    """
    if eof:
        return len(buffer) if buffer else None
    if len(buffer) < chunk:
        return None
    head = buffer[:chunk]
    nl = head.rfind("\n")
    if nl >= 0:
        return nl + 1
    return chunk


def iter_text_windows(
    path: Path,
    *,
    encoding: str = "utf-8",
    chunk_bytes: int | None = None,
) -> Iterator[TextWindow]:
    """Fenêtres de texte couvrant tout le fichier, mémoire bornée.

    Lève `BinarySkipped` si le début ressemble à du binaire,
    `UnreadablePath` si l'ouverture est refusée, `FileNotFoundError` si
    le fichier disparaît, `UnicodeDecodeError` si `encoding` ne convient
    pas (l'appelant réessaie en latin-1).
    """
    chunk = chunk_bytes if chunk_bytes is not None else DEFAULT_MAX_FILE_BYTES
    chunk = max(1, chunk)
    try:
        fh = path.open("rb")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise UnreadablePath(path, exc) from exc
    try:
        probe = fh.read(min(65536, chunk))
        if looks_binary(probe):
            raise BinarySkipped(path)
        fh.seek(0)
        yield from _iter_windows(fh, encoding, chunk)
    finally:
        fh.close()


def _iter_windows(fh, encoding: str, chunk: int) -> Iterator[TextWindow]:
    dec = codecs.getincrementaldecoder(encoding)(errors="strict")
    overlap = max(0, signature_overlap_chars())
    buffer = ""
    carry = ""
    start_line = 1
    eof = False
    while True:
        if not eof and len(buffer) < chunk:
            block = fh.read(chunk)
            if not block:
                buffer += dec.decode(b"", final=True)
                eof = True
            else:
                buffer += dec.decode(block, final=False)
                if len(buffer) < chunk and not eof:
                    continue
        if eof and not buffer:
            break
        cut = _cut_point(buffer, chunk, eof)
        if cut is None:
            continue
        new = buffer[:cut]
        buffer = buffer[cut:]
        window = carry + new
        yield TextWindow(text=window, start_line=start_line, overlap_chars=len(carry))
        if overlap and window:
            carry = window[-min(overlap, len(window)) :]
        else:
            carry = ""
        dropped = window[: len(window) - len(carry)]
        start_line += dropped.count("\n")
        if eof and not buffer:
            break
