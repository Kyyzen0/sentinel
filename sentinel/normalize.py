"""P0-5 : couche de normalisation des payloads obfusqués.

Stratégie (volontairement minimale mais efficace) :
  1. Décodage des `\\xHH` (hex), `\\uHHHH` (unicode), `\\OOO` (octal).
  2. Résolution des concaténations Python : `"abc" "def"` → `"abcdef"`.
  3. Décodage des littéraux base64 « évidents » (alphabet b64, ≥ 32 chars
     alphanum, padding `=` correct).

Le scanner applique la normalisation à chaque ligne AVANT de la passer
aux règles. Les numéros de ligne sont préservés (1 ligne → 1 ligne) —
c'est un invariant dur : un finding qui pointe sur la mauvaise ligne est
inutilisable, et un attaquant qui contrôle le payload (base64, `\\n`
échappé) pourrait sinon décaler arbitrairement les numéros de ligne du
rapport. Toute séquence décodée qui produirait un saut de ligne est donc
réécrite en espace, jamais en `\\n` réel.

Ce n'est PAS un désobfuscateur complet : on n'essaie PAS de comprendre
du bytecode, de l'AST, ou du chiffrement. C'est juste une passe de
déchiffrement « évident » qui suffit à démasquer les obfuscations
PHP/Bash/Python les plus courantes.
"""

from __future__ import annotations

import base64
import re

# Caractères autorisés dans un littéral base64 (RFC 4648).
_B64_ALPHABET = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
# Séquence d'échappement style C :
#   \xHH (hex)   → 1 octet
#   \uHHHH       → 1 caractère Unicode
#   \OOO (octal) → 1 octet (1 à 3 chiffres)
#   \\, \', \", \n, \t, \r etc. → caractère littéral
_CESC = re.compile(
    r"\\x([0-9A-Fa-f]{2})"
    r"|\\u([0-9A-Fa-f]{4})"
    r"|\\([0-7]{1,3})"
    r"|\\([\\'\"nrt0])"
)

# Caractères que str.splitlines() traite comme un saut de ligne. Un
# décodage qui en produit un (`\x0a`, `\u000a`, octal `\012`) ajoutait
# une ligne au texte normalisé et décalait tous les findings suivants.
_LINE_BREAKS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")


def _flatten_breaks(text: str) -> str:
    """Remplace tout saut de ligne par une espace. Invariant : 1 ligne → 1 ligne."""
    if not any(ch in _LINE_BREAKS for ch in text):
        return text
    return "".join(" " if ch in _LINE_BREAKS else ch for ch in text)


def _decode_c_escapes(text: str) -> str:
    """Remplace les séquences d'échappement style C par leur valeur.

    Les échappements qui produiraient un saut de ligne (`\\n`, `\\r`) sont
    rendus par une **espace** : le payload reste lisible pour les regexes,
    mais la ligne ne se dédouble pas. Sans ça, `x = "a\\nb"` transformait
    une ligne source en deux lignes et décalait tous les findings
    suivants (constaté : 3 lignes → 5).
    """

    def repl(m: re.Match[str]) -> str:
        if m.group(1) is not None:  # \\xHH
            ch = chr(int(m.group(1), 16))
        elif m.group(2) is not None:  # \\uHHHH
            ch = chr(int(m.group(2), 16))
        elif m.group(3) is not None:  # \\OOO
            ch = chr(int(m.group(3), 8) & 0xFF)
        else:
            simple = m.group(4)
            ch = {
                "\\": "\\",
                "'": "'",
                '"': '"',
                "n": " ",
                "r": " ",
                "t": "\t",
                "0": " ",
            }.get(simple, simple)
        return " " if ch in _LINE_BREAKS else ch

    return _CESC.sub(repl, text)


# Concaténation Python entre guillemets : "abc" "def" → 'abcdef'
# On accepte les trois formes de chaînes Python avec le préfixe optionnel r/b/u.
_PY_CONCAT = re.compile(
    r"""(['"])((?:\\.|(?!\1).)*?)\1\s*(['"])((?:\\.|(?!\3).)*?)\3""",
    re.DOTALL,
)


def _resolve_py_concat(text: str) -> str:
    """Fusionne les chaînes Python adjacentes : `"a" "b"` → `"ab"`."""
    prev = None
    while prev != text:
        prev = text
        text = _PY_CONCAT.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), text)
    return text


# Trouve un littéral base64 « évident » : ≥ 32 chars, alphabet strict.
# On le décode et on insère la version décodée à côté pour que les
# regex subséquents matchent.
_B64_CHUNK = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


def _decode_obvious_b64(text: str) -> str:
    """Décode les chunks base64 ≥ 32 chars alphanum, en gardant l'original
    et en suffixant avec la version décodée, sur la MÊME ligne.

    Le décodé est « aplati » (tout blanc → une espace) : un payload qui
    contient des `\\n` ajoutait sinon des lignes au texte normalisé, ce qui
    décalait les numéros de ligne de tous les findings suivants — et
    laissait l'attaquant choisir ce décalage.
    """
    out: list[str] = []
    pos = 0
    for m in _B64_CHUNK.finditer(text):
        chunk = m.group(0)
        if not _B64_ALPHABET.match(chunk):
            continue
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            continue
        # Aplatit les blancs (dont \n / \r) pour préserver 1 ligne = 1 ligne.
        decoded = " ".join(decoded.split())
        if not decoded or len(decoded) < 8:
            continue
        # On insère le décodé APRÈS la ligne originale (donc même numéro
        # de ligne dans le rapport, juste suffixé). On évite ainsi que
        # les findings ne pointent vers une ligne qui n'existe pas.
        out.append(text[pos : m.end()])
        out.append(f" # SENTINEL_DECODED_B64: {decoded}")
        pos = m.end()
    if pos == 0:
        return text
    out.append(text[pos:])
    return "".join(out)


def normalize_line(line: str) -> str:
    """Normalise une ligne : échappements C, concaténations Python, base64.

    L'ordre des passes est important :
      1. D'abord les concaténations (sinon l'étape 2 ne verrait qu'un
         fragment).
      2. Puis les échappements C (\\x → 1 char).
      3. Enfin le base64 (les octets révélés par l'étape 2 peuvent
         former un payload qu'on veut voir aussi décodé).
    """
    s = _resolve_py_concat(line)
    s = _decode_c_escapes(s)
    s = _decode_obvious_b64(s)
    return _flatten_breaks(s)


def normalize_text(text: str) -> list[str]:
    """Normalise ligne par ligne. Préserve le nombre de lignes."""
    return [normalize_line(line) for line in text.split("\n")]


def normalize_for_rules(text: str) -> str:
    """Normalise le texte entier pour les règles, en gardant les numéros
    de ligne. Chaque ligne est remplacée par sa version normalisée
    (sur la même ligne). Le résultat : même nombre de lignes, mais
    contenu obfusqué révélé.
    """
    return "\n".join(normalize_text(text))
