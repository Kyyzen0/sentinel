"""Baseline d'intégrité (hash + mode + uid/gid + capabilities + contenu)
et diff contre une référence.

V4 : la baseline inclut, pour les fichiers de petite taille, le contenu
du fichier au moment de la baseline. Cela permet aux règles augmentées
(SIG-0019 « clé ed25519 ajoutée post-baseline ») de comparer le contenu
historique au contenu actuel.

V4-P0-4 : ajoute uid, gid et capabilities. Un chown ou un setcap
changent l'identité d'exécution d'un binaire sans toucher au binaire lui-même
— d'où l'ajout dans la baseline pour rendre ces changements visibles.

P1-4 : la baseline peut être chiffrée par HMAC. Avec une clé
(`SENTINEL_KEY`, `--key-file` ou `--encrypt-key`), le contenu n'est PAS
stocké en clair — seul le HMAC-SHA256(key, content) est conservé, et le
document lui-même est signé (HMAC-SHA256). La comparaison reste possible
(HMAC vs HMAC), mais le contenu en clair n'est jamais écrit sur disque.

Sans clé, le contenu des petits fichiers ordinaires reste embarqué. Les
fichiers évidemment sensibles (clé privée / SIG-0008, `authorized_keys`,
`.env`, …) ne stockent pas leur contenu. Pour `authorized_keys` jusqu'à
64 Kio, des empreintes des clés publiques permettent la comparaison SIG-0019.

Les fichiers plus gros que `_CONTENT_MAX` ne stockent que le hash. Pour
les lire plus tard, le dossier référencé par `root` doit être accessible.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .files import is_ignored
from .models import IntegrityDiff
from .platform import OperationCancelled, file_owner, is_link, read_link
from .signatures import Sig0008, _extract_all_ssh_keys, _ssh_fingerprint

# Au-delà de cette taille, on n'embarque pas le contenu dans la baseline
# (évite de gonfler le JSON pour des binaires ou de gros logs).
_CONTENT_MAX = 64 * 1024  # 64 KB

# Taille des blocs pour le hachage en flux des gros fichiers. Sans ça,
# `read_bytes()` chargeait le fichier entier en RAM : un disque d'image
# de 4 Go dans le dossier scanné suffisait à faire tomber le process.
_HASH_CHUNK = 1024 * 1024

# Constante hachée dans la baseline chiffrée pour vérifier qu'une clé
# fournie est la bonne, sans jamais stocker la clé elle-même.
_KEY_CHECK_LABEL = b"sentinel-key-check-v1"

# Signature du document baseline (pas du contenu d'un fichier). Couvre
# le JSON canonique hors champs de signature : recopier un nouveau
# sha256 dans une entrée sans la clé ne peut pas recalculer ce HMAC.
_SIGNATURE_ALG = "HMAC-SHA256"
_SIGNATURE_FIELDS = frozenset({"signature", "signature_alg"})

# Noms dont le contenu ne doit jamais être écrit en clair dans une
# baseline non chiffrée. Le SHA-256 du fichier reste, pour l'intégrité.
_SENSITIVE_BASENAMES = frozenset(
    {
        "authorized_keys",
        "authorized_keys2",
        ".env",
        ".netrc",
        ".pgpass",
        "shadow",
        "gshadow",
    }
)
_PRIVATE_KEY_STEMS = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
)
_ENV_EXAMPLE_SUFFIXES = (".example", ".sample", ".template")

UNSIGNED_BASELINE_WARNING = (
    "⚠ Baseline non signée. Sans clé (SENTINEL_KEY, --key-file ou --encrypt-key) "
    "au moment de la création, une modification du JSON n'est pas détectable. "
    "Les baselines déjà produites restent lisibles."
)
UNSIGNED_WITH_KEY_REFUSED = (
    "❌ Baseline non signée alors qu'une clé est fournie ou que le fichier porte "
    "key_check/encrypted : la signature a été retirée ou n'a jamais été produite "
    "avec cette clé (exit 2)."
)
UNVERIFIED_BASELINE_WARNING = (
    "⚠ Baseline signée (HMAC-SHA256) mais aucune clé fournie : signature non "
    "vérifiée. Passez SENTINEL_KEY ou --key-file (ou --encrypt-key, déprécié)."
)
UNVERIFIED_BASELINE_REFUSED = (
    "❌ Baseline signée (HMAC-SHA256) mais aucune clé fournie : impossible de "
    "vérifier l'intégrité (exit 2). Passez SENTINEL_KEY ou --key-file, ou "
    "--allow-unverified-baseline pour continuer quand même."
)
INVALID_BASELINE_SIGNATURE = (
    "❌ Signature HMAC-SHA256 invalide : la baseline a été modifiée ou la clé ne correspond pas."
)
UNSIGNED_BASELINE_REFUSED = (
    "❌ Baseline non signée refusée (--require-signed ou SENTINEL_REQUIRE_SIGNED). "
    "Sans signature, encrypted, key_check ni key_hint, ce fichier est indiscernable "
    "d'une ancienne baseline non signée : l'intégrité du JSON n'est pas vérifiable (exit 2)."
)
UNVERIFIED_REQUIRED_REFUSED = (
    "❌ Baseline signée (HMAC-SHA256) mais aucune clé fournie : impossible de "
    "vérifier l'intégrité (exit 2). --require-signed (ou SENTINEL_REQUIRE_SIGNED) "
    "est actif : --allow-unverified-baseline ne l'emporte pas. "
    "Passez SENTINEL_KEY ou --key-file."
)
SIGNED_POLICY_CONFLICT = (
    "❌ --require-signed et --allow-unverified-baseline sont incompatibles (exit 2). "
    "Les deux drapeaux explicites se contredisent : --require-signed n'est pas "
    "assoupli par --allow-unverified-baseline."
)
SIGNED_POLICY_ENV_WINS = (
    "⚠ SENTINEL_REQUIRE_SIGNED est actif : --allow-unverified-baseline est ignoré. "
    "Une baseline non signée, ou signée sans clé, est refusée (exit 2)."
)
UNSIGNED_RESIGN_WARNING = (
    "⚠ SIGNATURE D'UNE BASELINE NON SIGNÉE — confiance initiale.\n"
    "Signer une baseline non signée est une opération de confiance initiale : "
    "« aucun écart » signifie seulement que le JSON correspond aux fichiers actuels, "
    "pas que l'arbre ou la baseline sont sains. Ne le faites que pour une baseline "
    "que vous avez vous-même générée sur un système connu sain. En cas de doute, "
    "régénérez avec `baseline` depuis cet état plutôt que de resigner."
)
UNSIGNED_RESIGN_NEEDS_TRUST = (
    "❌ Baseline non signée : --yes ne suffit pas. "
    "--resign exige --trust-unsigned pour cette confiance initiale (exit 2). "
    "Le fichier n'a pas été modifié."
)

# Politique opt-in. Seules ces valeurs (casse ignorée, espaces extrêmes
# retirés) activent le refus. ``0``, ``false``, ``no``, ``on`` ou une
# chaîne vide laissent le comportement historique : avertissement seul.
REQUIRE_SIGNED_ENV = "SENTINEL_REQUIRE_SIGNED"
_REQUIRE_SIGNED_TRUTHY = frozenset({"1", "true", "yes"})


# getcap n'est pas garanti disponible (macOS, conteneurs minimalistes).
# On l'invoque via subprocess ; s'il manque, le champ `capabilities` reste
# à None dans l'entry — sans planter le scan.
_getcap_path = shutil.which("getcap")


def _read_capabilities(path: Path) -> str | None:
    """Retourne la sortie texte de `getcap` (ex. `cap_net_bind_service+ep`),
    une chaîne vide si le fichier n'a pas de capabilities, ou None si
    `getcap` n'est pas installé.

    Hors Linux le contrôle n'existe pas : None signifie « non effectué »,
    pas « aucune capability ». On ne lance pas un binaire `getcap` qui
    traînerait sur macOS.
    """
    if not sys.platform.startswith("linux") or _getcap_path is None:
        return None
    try:
        out = subprocess.run(
            [_getcap_path, str(path)],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    # Sortie type : « /tmp/foo cap_net_bind_service+ep\n »
    # ou « /tmp/foo \n » (vide) — on retire le préfixe chemin.
    text = (out.stdout or "").strip()
    if not text:
        return ""
    # Retire le chemin (1er token) et l'espace éventuel.
    parts = text.split(maxsplit=1)
    return parts[1] if len(parts) == 2 else ""


@dataclass
class Entry:
    path: str  # chemin relatif (POSIX)
    sha256: str
    size: int
    mode: int  # st_mode brut (bits de permission)
    content: str | None = field(default=None)  # contenu UTF-8 (avec surrogates d'erreur)
    # P1-4 : HMAC-SHA256 du contenu, calculé avec une clé fournie à
    # `make_baseline(encrypt_key=...)`. Remplace `content` quand la
    # baseline est chiffrée. Permet le diff d'intégrité sans jamais
    # écrire le contenu en clair.
    hmac_sha256: str | None = None
    # "sensitive" : clair omis volontairement (clé, authorized_keys, .env,
    # marqueur SIG-0008). None sur les baselines anciennes et les fichiers
    # ordinaires. Distinct d'un contenu absent parce que le fichier est gros.
    content_redacted: str | None = None
    ssh_key_fingerprints: list[str] | None = None
    # P0-4 : uid/gid du fichier. Sur les liens symboliques, c'est l'uid/gid
    # du lien lui-même (et non de la cible), conformément à `os.lstat()`.
    # None = inconnu (baseline V1 qui ne les stockait pas) : la comparaison
    # est alors ignorée au lieu de signaler tous les fichiers comme
    # « owner_changed » (faux positif constaté à la migration V1 → V2).
    uid: int | None = None
    gid: int | None = None
    # P0-4 : capabilities Linux (sortie de `getcap`). None si l'utilitaire
    # n'est pas disponible. Chaine vide si le fichier n'en a pas.
    capabilities: str | None = None
    # Cible d'un lien symbolique (os.readlink) ou d'une jonction Windows.
    # None pour un fichier normal. Permet de détecter un lien re-ciblé :
    # sans ce champ, tous les liens avaient `sha256=""` et changer leur
    # cible ne produisait aucun diff.
    link_target: str | None = None
    # SID propriétaire Windows. None sur POSIX (uid/gid portent l'info)
    # et None si l'API n'a pas répondu : on ne compare pas, et on ne
    # fait pas passer un 0 fictif pour un propriétaire connu.
    owner: str | None = None


def _sha256_file(path: Path) -> str:
    """SHA-256 d'un fichier lu en flux (mémoire constante)."""
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            h.update(chunk)
    # Convention historique : un fichier vide a `sha256=""`.
    return h.hexdigest() if total else ""


def _sensitive_name(name: str) -> bool:
    """Vrai si le nom de fichier est évidemment un secret."""
    lower = name.lower()
    if lower in _SENSITIVE_BASENAMES:
        return True
    if lower.startswith(".env.") and not lower.endswith(_ENV_EXAMPLE_SUFFIXES):
        return True
    if lower.endswith(".pub"):
        return False
    if lower.endswith((".pem", ".key")):
        return True
    for stem in _PRIVATE_KEY_STEMS:
        if lower == stem or lower.startswith(stem + "."):
            return True
    return False


def _private_key_bytes(raw: bytes) -> bool:
    """Vrai si le contenu porte un marqueur SIG-0008 (clé privée en clair)."""
    return any(marker.encode("ascii") in raw for marker in Sig0008.MARKERS)


def _hmac_content(key: str, content: bytes) -> str:
    """P1-4 (M) : HMAC-SHA256 du contenu avec la clé fournie.

    La clé n'est JAMAIS stockée dans la baseline ni le manifest. Elle
    doit être fournie à chaque comparaison (scan --encrypt-key <key>).
    """
    return hmac.new(key.encode("utf-8"), content, hashlib.sha256).hexdigest()


def _entry_from(p: Path, root: Path, *, encrypt_key: str | None = None) -> Entry:
    st = p.lstat()  # lstat : ne pas suivre les symlinks
    size = st.st_size
    mode = st.st_mode

    link_target: str | None = None
    content: str | None = None
    hmac_sha256: str | None = None
    content_redacted: str | None = None
    ssh_key_fingerprints: list[str] | None = None

    if is_link(p):
        # On ne lit pas la cible (elle peut être hors périmètre), on
        # enregistre seulement le chemin du lien. Une jonction Windows
        # est un point de reparse : la traiter comme un dossier
        # hasherait l'arbre pointé.
        try:
            link_target = read_link(p)
        except OSError:
            link_target = None
        sha = ""
    elif p.is_file():
        if size <= _CONTENT_MAX:
            # Petit fichier : une seule lecture, qui sert au hash ET au contenu.
            try:
                raw = p.read_bytes()
            except OSError:
                sha = ""
            else:
                sha = hashlib.sha256(raw).hexdigest() if raw else ""
                if p.name == "authorized_keys":
                    ssh_key_fingerprints = sorted(
                        _ssh_fingerprint(k)
                        for k in _extract_all_ssh_keys(raw.decode("utf-8", errors="replace"))
                    )
                sensitive = _sensitive_name(p.name) or (bool(raw) and _private_key_bytes(raw))
                if raw:
                    if encrypt_key is not None:
                        hmac_sha256 = _hmac_content(encrypt_key, raw)
                    elif sensitive:
                        # Hash seul : le clair (clé, authorized_keys, .env)
                        # ne sort pas dans le JSON. Les empreintes des clés
                        # publiques permettent la comparaison SIG-0019.
                        content_redacted = "sensitive"
                    else:
                        content = raw.decode("utf-8", errors="replace")
                elif encrypt_key is None and not sensitive:
                    # Fichier vide lu avec succès. `None` veut dire « contenu
                    # indisponible » (V1, chiffré, > 64 KB, sensible, illisible)
                    # et désactive SIG-0019. Laisser None ici faisait passer un
                    # fichier vide *non sensible* pour une baseline sans
                    # historique.
                    content = ""
                elif sensitive:
                    content_redacted = "sensitive"
        else:
            # Gros fichier : hachage en flux, jamais de contenu embarqué.
            try:
                sha = _sha256_file(p)
            except OSError:
                sha = ""
    else:
        # FIFO, socket, device : rien à hacher.
        sha = ""

    return Entry(
        path=p.relative_to(root).as_posix(),
        sha256=sha,
        size=size,
        mode=mode,
        content=content,
        hmac_sha256=hmac_sha256,
        content_redacted=content_redacted,
        ssh_key_fingerprints=ssh_key_fingerprints,
        uid=None if os.name == "nt" else st.st_uid,
        gid=None if os.name == "nt" else st.st_gid,
        capabilities=_read_capabilities(p),
        link_target=link_target,
        owner=file_owner(p),
    )


def _iter_files(
    folder: Path,
    *,
    encrypt_key: str | None = None,
    cancel: Callable[[], bool] | None = None,
):
    """Fichiers et liens, sans descendre dans un symlink ou une jonction.

    ``rglob`` suit les répertoires qui sont des points de reparse. On
    reprend le même ``os.walk(followlinks=False)`` que le scan, et on
    retire en plus les jonctions que Python ne classe pas comme liens.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        if cancel is not None and cancel():
            raise OperationCancelled("baseline interrompue")
        kept: list[str] = []
        for name in dirnames:
            child = Path(dirpath) / name
            if is_ignored(child):
                continue
            if is_link(child):
                found.append(child)
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            child = Path(dirpath) / name
            if is_ignored(child):
                continue
            if is_link(child) or child.is_file():
                found.append(child)
    for p in sorted(found):
        if cancel is not None and cancel():
            raise OperationCancelled("baseline interrompue")
        try:
            yield _entry_from(p, folder, encrypt_key=encrypt_key)
        except OSError:
            continue


def make_baseline(
    folder: Path,
    *,
    encrypt_key: str | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict:
    """Génère la baseline d'un dossier.

    P1-4 : si `encrypt_key` est fourni, le contenu des fichiers n'est
    PAS stocké en clair dans la baseline — seul le HMAC-SHA256 l'est.
    Cela évite qu'un attaquant qui accède au fichier baseline puisse
    lire `authorized_keys`, `/etc/shadow`, etc. directement.
    """
    entries = [asdict(e) for e in _iter_files(folder, encrypt_key=encrypt_key, cancel=cancel)]
    out: dict = {
        "version": 2,
        "root": str(folder),
        "content_max_bytes": _CONTENT_MAX,
        "entries": entries,
    }
    if encrypt_key is not None:
        # P1-4 : tagger la baseline pour signaler qu'elle est chiffrée.
        # Note : on ne stocke PAS la clé, juste un flag.
        out["encrypted"] = True
        # Empreinte de la clé : permet à `scan --encrypt-key` de dire
        # « mauvaise clé » au lieu de continuer silencieusement. C'est un
        # HMAC d'une constante publique, pas un dérivé réversible de la clé.
        out["key_check"] = _hmac_content(encrypt_key, _KEY_CHECK_LABEL)
        out["key_hint"] = "HMAC-SHA256"  # indication, pas la clé
        # Intégrité du document lui-même : sans ça, recopier le nouveau
        # sha256 d'un fichier modifié dans le JSON passe inaperçu.
        sign_baseline(out, encrypt_key)
    return out


def baseline_canonical(baseline: dict) -> bytes:
    """JSON canonique signé : clés triées, sans les champs de signature.

    ``encrypted``, ``key_check`` et ``key_hint`` restent dans le payload :
    les remplacer sans la clé casse le HMAC. ``resigned_at`` et
    ``resigned_from_unsigned`` aussi, quand une resignature les a posés.
    Indépendant de l'indentation du fichier sur disque. Un aller-retour
    ``json.loads(json.dumps(...))`` redonne les mêmes octets.
    """
    payload = {k: v for k, v in baseline.items() if k not in _SIGNATURE_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _baseline_has_key_marker(baseline: dict) -> bool:
    """Vrai si la baseline a été produite avec une clé.

    ``encrypted`` ou un ``key_check`` non vide : retirer ``signature`` ne
    doit pas ramener le document au chemin « baseline ancienne ».
    """
    if baseline.get("encrypted"):
        return True
    key_check = baseline.get("key_check")
    return isinstance(key_check, str) and bool(key_check)


def sign_baseline(baseline: dict, key: str) -> dict:
    """Ajoute ``signature`` / ``signature_alg`` (HMAC-SHA256 de la clé)."""
    baseline.pop("signature", None)
    baseline.pop("signature_alg", None)
    baseline["signature_alg"] = _SIGNATURE_ALG
    baseline["signature"] = _hmac_content(key, baseline_canonical(baseline))
    return baseline


def _utcnow_iso() -> str:
    """Horodatage ISO 8601 UTC. ``timezone.utc`` couvre Python 3.9+."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def note_unsigned_resign(baseline: dict, *, resigned_at: str | None = None) -> dict:
    """Marque une resignature partie d'un document non signé.

    ``resigned_from_unsigned`` et ``resigned_at`` entrent dans le JSON
    canonique signé. Les retirer ou les modifier casse le HMAC. On ne
    prétend pas détecter un arbre déjà compromis qui colle au JSON :
    la marque dit seulement que la signature est une confiance initiale.
    """
    baseline["resigned_from_unsigned"] = True
    baseline["resigned_at"] = resigned_at if resigned_at is not None else _utcnow_iso()
    return baseline


def unsigned_resign_notice(baseline: dict) -> str | None:
    """Avis à afficher quand la signature vérifiée porte la marque.

    ``None`` si le booléen n'est pas exactement ``True`` : une chaîne
    ``"true"`` ou un document non authentifié ne déclenche pas l'avis.
    L'appelant ne l'imprime qu'après une signature ``ok``.
    """
    if baseline.get("resigned_from_unsigned") is not True:
        return None
    when = baseline.get("resigned_at")
    when_txt = when if isinstance(when, str) and when else "date inconnue"
    return (
        "⚠ Baseline resignée depuis un document non signé "
        f"(resigned_from_unsigned, {when_txt}). Confiance initiale : "
        "l'absence d'écart au moment de la resignature ne prouve pas que "
        "l'arbre était sain. En cas de doute, régénérez avec `baseline` "
        "depuis un état connu sain plutôt que de resigner."
    )


def env_requires_signed(environ: Mapping[str, str] | None = None) -> bool:
    """Vrai si ``SENTINEL_REQUIRE_SIGNED`` vaut 1, true ou yes."""
    env = os.environ if environ is None else environ
    raw = env.get(REQUIRE_SIGNED_ENV)
    if raw is None:
        return False
    return raw.strip().lower() in _REQUIRE_SIGNED_TRUTHY


def baseline_is_signed(baseline: dict) -> bool:
    """Vrai si le document porte un champ de signature (même invalide)."""
    return "signature" in baseline or "signature_alg" in baseline


def baseline_signature_status(baseline: dict, key: str | None) -> tuple[str, str]:
    """``(status, message)``.

    - ``ok`` : signature présente et valide (message vide) ;
    - ``unsigned`` : baseline ancienne, sans signature et sans marqueur de
      clé — avertir, ne pas refuser le chargement ;
    - ``unsigned_refused`` : pas de signature, mais une clé est fournie ou
      le fichier porte ``encrypted`` / ``key_check`` (exit 2) ;
    - ``unverified`` : signature présente mais pas de clé (le CLI refuse
      sauf ``--allow-unverified-baseline``) ;
    - ``mismatch`` : la signature ne correspond pas (exit 2).
    """
    signed = baseline_is_signed(baseline)
    if not signed:
        if key is not None or _baseline_has_key_marker(baseline):
            return "unsigned_refused", UNSIGNED_WITH_KEY_REFUSED
        return "unsigned", UNSIGNED_BASELINE_WARNING
    sig = baseline.get("signature")
    alg = baseline.get("signature_alg", _SIGNATURE_ALG)
    if not isinstance(sig, str) or not sig or alg != _SIGNATURE_ALG:
        return "mismatch", INVALID_BASELINE_SIGNATURE
    if key is None:
        return "unverified", UNVERIFIED_BASELINE_WARNING
    expected = _hmac_content(key, baseline_canonical(baseline))
    if len(sig) != len(expected) or not hmac.compare_digest(expected, sig):
        return "mismatch", INVALID_BASELINE_SIGNATURE
    return "ok", ""


def verify_baseline_key(baseline: dict, key: str) -> bool | None:
    """Vrai si `key` est la clé de la baseline, None si la baseline ne
    porte pas d'empreinte (format ancien) — donc invérifiable.
    """
    expected = baseline.get("key_check")
    if not isinstance(expected, str):
        return None
    return hmac.compare_digest(expected, _hmac_content(key, _KEY_CHECK_LABEL))


_ENTRY_FIELDS = frozenset(f.name for f in dataclasses.fields(Entry))


def _entry_from_dict(d: dict) -> Entry:
    """Construit une Entry en ignorant les champs inconnus.

    Une baseline produite par une version plus récente (ou un JSON
    bricolé à la main) ne doit pas faire planter le diff sur un
    `TypeError: unexpected keyword argument`.
    """
    return Entry(**{k: v for k, v in d.items() if k in _ENTRY_FIELDS})


def _by_path(ref: dict) -> dict[str, Entry]:
    return {e["path"]: _entry_from_dict(e) for e in ref.get("entries", [])}


def diff_against_baseline(current: dict, ref: dict) -> IntegrityDiff:
    # `current` provient de make_baseline() : ses entrées sont déjà lues, on les
    # réutilise au lieu de reparcourir le dossier (sinon chaque fichier était lu
    # deux fois par scan avec --baseline).
    entries = current.get("entries")
    if entries is not None:
        cur_map = {e["path"]: _entry_from_dict(e) for e in entries}
    else:
        cur_map = {e.path: e for e in _iter_files(Path(current["root"]))}
    ref_map = _by_path(ref)

    added = sorted(set(cur_map) - set(ref_map))
    removed = sorted(set(ref_map) - set(cur_map))
    modified: list[str] = []
    mode_changed: list[str] = []
    owner_changed: list[str] = []
    cap_changed: list[str] = []

    for p in sorted(set(cur_map) & set(ref_map)):
        c, r = cur_map[p], ref_map[p]
        if c.sha256 != r.sha256 or c.size != r.size:
            modified.append(p)
        if (c.mode & 0o7777) != (r.mode & 0o7777):
            mode_changed.append(p)
        # uid/gid : on ne compare que si les DEUX côtés les connaissent.
        # Une baseline V1 ne les stockait pas (Entry les met à None) ; les
        # comparer à 0 signalait chaque fichier comme owner_changed.
        if None not in (c.uid, r.uid, c.gid, r.gid):
            if c.uid != r.uid or c.gid != r.gid:
                owner_changed.append(p)
        # Capabilities : ne comparer que si les deux sont connues (sinon
        # getcap absent, pas de signal).
        if c.capabilities is not None and r.capabilities is not None:
            if c.capabilities != r.capabilities:
                cap_changed.append(p)
        # Symlink re-ciblé : le sha256 est vide des deux côtés, seul
        # `link_target` porte l'information.
        if c.link_target is not None and r.link_target is not None:
            if c.link_target != r.link_target and p not in modified:
                modified.append(p)
        # SID Windows. None des deux côtés (POSIX, ou API muette) : on
        # ne signale pas un changement imaginaire.
        if c.owner and r.owner and c.owner != r.owner and p not in owner_changed:
            owner_changed.append(p)

    return IntegrityDiff(
        added=added,
        removed=removed,
        modified=modified,
        mode_changed=mode_changed,
        owner_changed=owner_changed,
        cap_changed=cap_changed,
    )


def write_baseline_to(folder: Path, out: Path) -> dict:
    baseline = make_baseline(folder)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2, sort_keys=True))
    return baseline


def format_resign_diff(diff: IntegrityDiff, root: Path) -> str:
    """Texte des écarts montrés avant une resignature.

    Les cinq familles demandées (ajouts, suppressions, contenu, mode,
    propriétaire) sont toujours imprimées, même vides, pour qu'une
    baseline réécrite afin de coller aux fichiers ne se taise pas sur
    une catégorie. ``capabilities`` suit le même diff.
    """

    def cell(items: list[str]) -> str:
        return ", ".join(items) if items else "(aucun)"

    lines = [
        f"Comparaison avec les fichiers actuels de {root} :",
        f"  ajoutés      : {cell(diff.added)}",
        f"  supprimés    : {cell(diff.removed)}",
        f"  modifiés     : {cell(diff.modified)}",
        f"  mode         : {cell(diff.mode_changed)}",
        f"  propriétaire : {cell(diff.owner_changed)}",
        f"  capabilities : {cell(diff.cap_changed)}",
    ]
    drifted = any(
        (
            diff.added,
            diff.removed,
            diff.modified,
            diff.mode_changed,
            diff.owner_changed,
            diff.cap_changed,
        )
    )
    if drifted:
        lines.append(
            "Confirmer fige ces écarts dans la signature. "
            "Le document n'est pas régénéré : seules signature et signature_alg changent."
        )
    else:
        lines.append(
            "Aucun écart sur ces familles. Une baseline déjà réécrite pour coller "
            "aux fichiers actuels reste vide ici : la confirmation est le seul garde-fou."
        )
    return "\n".join(lines)


def _copy_backup(path: Path) -> Path:
    """Copie ``path`` vers ``<nom>.bak`` (remplace un .bak déjà présent)."""
    backup_path = path.with_name(path.name + ".bak")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".bak.tmp", dir=path.parent)
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        shutil.copy2(path, tmp_path)
        os.replace(tmp_path, backup_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return backup_path


def write_baseline_atomic(path: Path, document: dict, *, backup: bool = False) -> Path | None:
    """Écrit le JSON via un temporaire du même dossier, puis ``os.replace``.

    ``os.replace`` est atomique sur le même système de fichiers : un lecteur
    voit l'ancien fichier ou le nouveau, pas un JSON tronqué. Avec
    ``backup``, l'original est d'abord copié vers ``<nom>.bak``. Le mode
    du fichier existant est reporté sur le temporaire avant le remplacement.
    Retourne le chemin de sauvegarde, ou None.
    """
    text = json.dumps(document, indent=2, sort_keys=True)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    backup_path: Path | None = None
    if backup:
        if not path.is_file():
            raise OSError(f"pas de fichier à sauvegarder : {path}")
        backup_path = _copy_backup(path)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_file():
            os.chmod(tmp_path, stat.S_IMODE(path.stat().st_mode))
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return backup_path


def baseline_text_from_entry(entry: dict | None) -> str | None:
    """Contenu baseline d'une entrée déjà résolue, ou None.

    Le scanner dispose déjà de l'entrée (via sa table path → entry) : il
    n'a pas à relancer une recherche linéaire dans toutes les entrées
    pour chaque fichier (c'était O(n²) sur un gros dossier).
    """
    if not isinstance(entry, dict):
        return None
    content = entry.get("content")
    return content if isinstance(content, str) else None


def load_baseline_text(baseline: dict, rel: str) -> str | None:
    """Lit le contenu baseline d'un fichier, ou retourne None.

    Priorité absolue au contenu embarqué dans la baseline. **Pas de
    fallback disque** : une baseline qui n'embarque pas le contenu (V1
    d'origine, baseline chiffrée, ou V2 avec un fichier > `content_max_bytes`)
    ne peut pas servir de référence historique fiable, et lire le fichier
    actuel donnerait à SIG-0019 (et à toute règle augmentée) une
    comparaison « fichier vs lui-même » silencieusement rassurante.
    On retourne None et c'est au caller d'annoncer la dégradation.
    """
    entry = next((e for e in baseline.get("entries", []) if e["path"] == rel), None)
    return baseline_text_from_entry(entry)
