"""Point d'entrée CLI : `python3 -m sentinel <commande> [args]`.

Sous-commandes :
  V1 : baseline <dossier> --out baseline.json
  V1 : baseline --resign baseline.json [--yes] [--backup] [--trust-unsigned]
  V1 : scan <dossier> [--baseline baseline.json] [--anomaly] [--top N] [--format text|json]
  V3 : train <dossier> --out model.json [--epochs N] [--lr X]
  V3 : scan --neural --model model.json ...  (sinon utilise l'heuristique V2)
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

from .integrity import (
    SIGNED_POLICY_CONFLICT,
    SIGNED_POLICY_ENV_WINS,
    UNSIGNED_BASELINE_REFUSED,
    UNSIGNED_BASELINE_WARNING,
    UNSIGNED_RESIGN_NEEDS_TRUST,
    UNSIGNED_RESIGN_WARNING,
    UNVERIFIED_BASELINE_REFUSED,
    UNVERIFIED_REQUIRED_REFUSED,
    _baseline_has_key_marker,
    baseline_is_signed,
    baseline_signature_status,
    diff_against_baseline,
    env_requires_signed,
    format_resign_diff,
    make_baseline,
    note_unsigned_resign,
    sign_baseline,
    unsigned_resign_notice,
    verify_baseline_key,
    write_baseline_atomic,
)
from .keys import KeySourceError, resolve_key
from .neural import AutoencoderScorer
from .platform import UnsafeNtPath, stdin_is_terminal, unsafe_nt_message
from .quarantine import default_journal_path, init_engine, quarantine_paths, restore_paths
from .reporting import render_json, render_text
from .scanner import _iter_text_files, scan_folder
from .watch import has_watchdog, watch_event, watch_polling


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Analyse de sécurité locale orientée fichiers (signatures + intégrité + anomalie).",
    )
    p.add_argument(
        "--version",
        action="store_true",
        help="P3-4 : affiche la version et quitte.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # baseline (V1) — création, ou resignature en place d'un JSON existant.
    b = sub.add_parser("baseline", help="créer une référence d'intégrité d'un dossier")
    b.add_argument(
        "folder",
        type=Path,
        nargs="?",
        help="dossier à indexer (omis avec --resign)",
    )
    b.add_argument(
        "--out",
        type=Path,
        help="fichier baseline de sortie (JSON). Requis sans --resign.",
    )
    b.add_argument(
        "--resign",
        type=Path,
        metavar="BASELINE.json",
        help="signe une baseline existante en place (même fichier). Exige une clé. "
        "Affiche les écarts avec les fichiers du champ root, puis demande "
        "confirmation (y/N). Sans TTY, --yes est obligatoire. Une baseline "
        "non signée exige aussi --trust-unsigned (--yes ne suffit pas). "
        "Une signature déjà présente est vérifiée avant réécriture "
        "(exit 2 si elle ne correspond pas). Les entrées ne sont pas "
        "régénérées et le contenu n'est pas chiffré.",
    )
    b.add_argument(
        "--yes",
        action="store_true",
        help="confirme --resign sans invite. Obligatoire quand stdin n'est pas un TTY. "
        "Ne remplace pas --trust-unsigned sur une baseline non signée.",
    )
    b.add_argument(
        "--trust-unsigned",
        action="store_true",
        help="autorise --resign à signer une baseline qui n'a pas de signature "
        "(confiance initiale). Obligatoire dans ce cas, même avec --yes. "
        "Inutile si la signature actuelle est déjà vérifiée avec la clé.",
    )
    b.add_argument(
        "--backup",
        action="store_true",
        help="avec --resign, copie l'original vers <fichier>.bak avant remplacement.",
    )
    b.add_argument(
        "--encrypt-key",
        type=str,
        default=None,
        help="DÉPRÉCIÉ : clé HMAC sur la ligne de commande (visible dans "
        "l'historique et dans ps). Préférez SENTINEL_KEY ou --key-file. "
        "Si fourni, stocke HMAC-SHA256(key, content) au lieu du clair "
        "et signe la baseline.",
    )
    b.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Clé HMAC lue depuis ce fichier. Refusé s'il est lisible par "
        "le groupe ou les autres (chmod 600). Alternative à SENTINEL_KEY.",
    )

    # scan (V1+ ; V3 ajoute --neural + --model)
    s = sub.add_parser("scan", help="scanner un dossier (signatures [+intégrité] [+anomalie])")
    s.add_argument("folder", type=Path, help="dossier à scanner")
    s.add_argument("--baseline", type=Path, help="comparer contre cette baseline (intégrité)")
    s.add_argument("--anomaly", action="store_true", help="ajouter le score d'anomalie par fichier")
    s.add_argument(
        "--top",
        type=int,
        default=10,
        help="nombre de fichiers à lister dans le rapport texte d'anomalie",
    )
    s.add_argument(
        "--neural",
        action="store_true",
        help="V3 : utiliser l'autoencodeur neuronal (au lieu de l'heuristique)",
    )
    s.add_argument(
        "--model", type=Path, help="V3 : chemin du modèle neuronal pré-entraîné (autoencodeur)"
    )
    s.add_argument(
        "--follow-links",
        action="store_true",
        help="P0-3 : suivre les symlinks (les cibles hors-confinement sont ignorées, audit dans skipped_external)",
    )
    s.add_argument(
        "--strict",
        action="store_true",
        help="P1-5 : exit 2 si la baseline est illisible (manquante, JSON corrompu). "
        "Sans --strict, le scan sort en 0/1 avec un simple warning.",
    )
    s.add_argument(
        "--min-severity",
        choices=("low", "medium", "high", "critical"),
        default="low",
        help="P3-1 : seuil minimal de sévérité pour conserver un finding. "
        "Défaut 'low' = tout garder. Ex: --min-severity high = ne garder que high+critical.",
    )
    s.add_argument(
        "--only",
        type=str,
        default=None,
        help="P3-1 : ne garder que les findings dont le rule_id matche ce préfixe "
        "(ex: SIG-0019 pour ne voir que les ajouts de clés SSH).",
    )
    s.add_argument(
        "--ignore-file",
        type=Path,
        default=Path(".sentinelignore"),
        help="Chemin du fichier d'ignore (règle + chemin ou FINGERPRINT + justification). "
        "Défaut ./.sentinelignore. Vide = pas de filtre.",
    )
    s.add_argument(
        "--encrypt-key",
        type=str,
        default=None,
        help="DÉPRÉCIÉ : clé HMAC sur la ligne de commande (visible dans "
        "l'historique et dans ps). Préférez SENTINEL_KEY ou --key-file. "
        "Avec --baseline, vérifie la clé (exit 2 sinon) et la signature "
        "HMAC-SHA256 du fichier. Une baseline chiffrée ne contient pas le "
        "contenu : SIG-0019 (« clé ajoutée ») est désactivée.",
    )
    s.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Clé HMAC lue depuis ce fichier (chmod 600). Alternative à SENTINEL_KEY.",
    )
    s.add_argument(
        "--allow-unverified-baseline",
        action="store_true",
        help="Accepter une baseline signée sans clé (avertissement seulement). "
        "Par défaut, une signature non vérifiable fait échouer le scan (exit 2). "
        "Incompatible avec --require-signed (exit 2 si les deux drapeaux sont passés). "
        "Ignoré si SENTINEL_REQUIRE_SIGNED est actif.",
    )
    s.add_argument(
        "--require-signed",
        action="store_true",
        help="Refuser une baseline non signée (exit 2), au lieu de l'avertissement "
        "historique. Aussi activé par SENTINEL_REQUIRE_SIGNED=1|true|yes. "
        "N'est pas assoupli par --allow-unverified-baseline. Sans --baseline, "
        "le drapeau n'a rien à vérifier.",
    )
    s.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="format de sortie : text (défaut), json (V1), sarif (P3-2, GitHub Code Scanning)",
    )

    # train (V3) — entraîne un autoencodeur sur un dossier de fichiers normaux.
    t = sub.add_parser("train", help="V3 : entraîner un autoencodeur sur un dossier « normal »")
    t.add_argument("folder", type=Path, help="dossier d'entraînement (fichiers normaux)")
    t.add_argument("--out", type=Path, required=True, help="fichier modèle de sortie (JSON)")
    t.add_argument("--epochs", type=int, default=80, help="nombre d'époques (défaut 80)")
    t.add_argument("--lr", type=float, default=5e-3, help="taux d'apprentissage (défaut 0.005)")
    t.add_argument("--seed", type=int, default=0xC0FFEE, help="graine aléatoire (reproductibilité)")
    t.add_argument(
        "--follow-links",
        action="store_true",
        help="Suivre les symlinks du corpus. Défaut : les ignorer, comme scan. "
        "Une cible hors du dossier d'entraînement est toujours ignorée.",
    )

    # quarantine (V4) — déplace des fichiers dans un dossier de quarantaine read-only.
    q = sub.add_parser(
        "quarantine",
        help="déplacer (mv) des fichiers dans un dossier de quarantaine read-only",
    )
    q.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="un ou plusieurs fichiers/dossiers à mettre en quarantaine",
    )
    q.add_argument(
        "--dest",
        type=Path,
        default=Path(".sentinel-quarantine"),
        help="dossier de destination (défaut ./.sentinel-quarantine)",
    )
    q.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="manifest JSONL des fichiers déplacés (défaut <dest>/manifest.jsonl)",
    )
    q.add_argument(
        "--force",
        action="store_true",
        help="Autoriser une destination sensible non critique (~/.config, "
        "répertoire système) ou contenue dans le dossier source. "
        "Ne lève pas le refus sur /, $HOME, ~/.ssh et ~/.gnupg.",
    )

    # watch (V4) — surveillance temps réel, FSEvents via watchdog si dispo,
    # sinon fallback polling.
    w = sub.add_parser(
        "watch",
        help="surveiller un dossier et re-scanner à chaque modification",
    )
    w.add_argument("folder", type=Path, help="dossier à surveiller")
    w.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="intervalle de polling en secondes (ignoré si watchdog est dispo, défaut 2.0)",
    )
    w.add_argument(
        "--baseline",
        type=Path,
        help="baseline d'intégrité à comparer à chaque tour",
    )
    w.add_argument(
        "--anomaly",
        action="store_true",
        help="inclure le score d'anomalie à chaque tour",
    )
    w.add_argument(
        "--neural",
        action="store_true",
        help="V3 : utiliser l'autoencodeur neuronal (sinon heuristique)",
    )
    w.add_argument(
        "--model",
        type=Path,
        help="V3 : modèle neuronal pré-entraîné (requis pour --neural)",
    )
    w.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help="arrêter après N tours (0 = infini, défaut 0)",
    )
    w.add_argument(
        "--debounce",
        type=float,
        default=0.5,
        help="P3-3 : attendre N secondes de stabilité avant de relancer un scan "
        "(défaut 0.5). Évite la rafale d'événements d'une sauvegarde d'éditeur.",
    )
    w.add_argument(
        "--json-lines",
        action="store_true",
        help="P3-3 : sortie JSON compacte sans indentation (un rapport par ligne, "
        "idéal pour `tail -f` ou l'ingestion streaming).",
    )
    w.add_argument(
        "--encrypt-key",
        type=str,
        default=None,
        help="DÉPRÉCIÉ : clé HMAC sur la ligne de commande. Préférez SENTINEL_KEY "
        "ou --key-file. Sert à vérifier la signature de --baseline.",
    )
    w.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Clé HMAC lue depuis ce fichier (chmod 600). Alternative à SENTINEL_KEY.",
    )
    w.add_argument(
        "--allow-unverified-baseline",
        action="store_true",
        help="Accepter une baseline signée sans clé (avertissement seulement). "
        "Par défaut, une signature non vérifiable fait échouer watch (exit 2). "
        "Incompatible avec --require-signed (exit 2 si les deux drapeaux sont passés). "
        "Ignoré si SENTINEL_REQUIRE_SIGNED est actif.",
    )
    w.add_argument(
        "--require-signed",
        action="store_true",
        help="Refuser une baseline non signée (exit 2), au lieu de l'avertissement "
        "historique. Aussi activé par SENTINEL_REQUIRE_SIGNED=1|true|yes. "
        "N'est pas assoupli par --allow-unverified-baseline. Sans --baseline, "
        "le drapeau n'a rien à vérifier.",
    )

    # restore (P1-1) — remet en place les fichiers depuis le manifest de quarantaine.
    r = sub.add_parser(
        "restore",
        help="restaurer les fichiers d'un manifest de quarantaine à leur emplacement d'origine",
    )
    r.add_argument(
        "--manifest",
        type=Path,
        default=Path(".sentinel-quarantine/manifest.jsonl"),
        help="manifest JSONL à lire (défaut ./.sentinel-quarantine/manifest.jsonl)",
    )
    r.add_argument(
        "--dest",
        type=Path,
        default=Path(".sentinel-quarantine"),
        help="dossier de quarantaine (validation, défaut ./.sentinel-quarantine)",
    )
    r.add_argument(
        "--force",
        action="store_true",
        help="écraser les fichiers d'origine déjà présents",
    )
    r.add_argument(
        "--only",
        type=str,
        nargs="*",
        default=None,
        help="ne restaurer que les chemins listés (par défaut : tout)",
    )

    return p


def _require_directory(folder: Path) -> str | None:
    if not folder.exists():
        return f"Dossier introuvable : {folder}"
    if not folder.is_dir():
        return f"Pas un dossier : {folder}"
    return None


def _resolve_command_key(args: argparse.Namespace) -> tuple[str | None, int]:
    """``(clé ou None, code)``. ``code`` vaut 2 si la source de clé est refusée."""
    try:
        key, warnings = resolve_key(
            encrypt_key=getattr(args, "encrypt_key", None),
            key_file=getattr(args, "key_file", None),
        )
    except KeySourceError as exc:
        print(f"❌ {exc.message}", file=sys.stderr)
        return None, 2
    for warning in warnings:
        print(warning, file=sys.stderr)
    return key, 0


def _enforce_signed_policy(args: argparse.Namespace) -> tuple[bool, int]:
    """``(require_signed, code)``.

    Deux drapeaux explicites contradictoires : exit 2, avant tout
    chargement. ``SENTINEL_REQUIRE_SIGNED`` active la même politique ;
    ``--allow-unverified-baseline`` ne la désarme pas (avertissement,
    puis refus au chargement). L'environnement ne peut pas éteindre
    le drapeau ``--require-signed``.
    """
    flagged = bool(getattr(args, "require_signed", False))
    allow = bool(getattr(args, "allow_unverified_baseline", False))
    if flagged and allow:
        print(SIGNED_POLICY_CONFLICT, file=sys.stderr)
        return True, 2
    require = flagged or env_requires_signed()
    if require and allow:
        print(SIGNED_POLICY_ENV_WINS, file=sys.stderr)
    return require, 0


_CONFIRM_YES = frozenset({"y", "yes", "oui"})


def _confirm_resign(assume_yes: bool, *, unsigned: bool, trust_unsigned: bool) -> int:
    """0 pour signer, 2 pour refuser.

    ``--yes`` court-circuite l'invite. Sans TTY, signer quand même
    serait une confirmation silencieuse : on refuse. Une baseline non
    signée exige en plus ``--trust-unsigned`` : ``--yes`` seul ne
    transforme pas l'absence d'écart en preuve de santé.
    """
    if unsigned:
        # Affiché avant l'invite et aussi avec --yes : la confiance
        # initiale doit être lue, pas seulement cochée.
        print(UNSIGNED_RESIGN_WARNING, file=sys.stderr)
        if not trust_unsigned:
            print(UNSIGNED_RESIGN_NEEDS_TRUST, file=sys.stderr)
            return 2
    if assume_yes:
        return 0
    if not stdin_is_terminal():
        print(
            "❌ stdin n'est pas un TTY : --resign ne signe pas sans confirmation. "
            "Passez --yes pour confirmer explicitement (exit 2).",
            file=sys.stderr,
        )
        return 2
    if unsigned:
        print(
            "Signer cette baseline non signée (confiance initiale) ? [y/N] ",
            file=sys.stderr,
            end="",
            flush=True,
        )
    else:
        print("Resignature de cette baseline ? [y/N] ", file=sys.stderr, end="", flush=True)
    try:
        answer = sys.stdin.readline()
    except KeyboardInterrupt:
        print("\nResignature annulée (exit 2).", file=sys.stderr)
        return 2
    if answer.strip().lower() not in _CONFIRM_YES:
        print("Resignature annulée (exit 2).", file=sys.stderr)
        return 2
    return 0


def _resign_baseline(
    path: Path,
    *,
    key: str | None,
    assume_yes: bool,
    backup: bool,
    trust_unsigned: bool,
) -> int:
    """Signe ``path`` en place après diff et confirmation.

    Une signature déjà présente est vérifiée avec ``key`` avant toute
    écriture : un document retouché ne peut pas être relavé par
    ``--yes``. Une baseline non signée exige ``trust_unsigned``.
    Le contenu des entrées n'est pas recalculé.
    """
    if key is None:
        print(
            "❌ baseline --resign exige une clé (SENTINEL_KEY ou --key-file). "
            "--encrypt-key reste accepté, avec l'avertissement de dépréciation (exit 2).",
            file=sys.stderr,
        )
        return 2
    # On réécrit le fichier lu. Un lien symbolique est suivi : le remplacer
    # par un fichier régulier laisserait la cible non signée.
    from .platform import is_link

    if is_link(path):
        path = path.resolve()
    try:
        loaded = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"❌ Baseline illisible ({exc}).", file=sys.stderr)
        return 2
    if not isinstance(loaded, dict):
        print("❌ Baseline illisible (JSON inattendu).", file=sys.stderr)
        return 2
    root_raw = loaded.get("root")
    if not isinstance(root_raw, str) or not root_raw:
        print(
            "❌ Baseline sans champ root : impossible de comparer aux fichiers actuels.",
            file=sys.stderr,
        )
        return 2
    root = Path(root_raw)
    if not root.is_dir():
        print(f"❌ Racine introuvable ou pas un dossier : {root}", file=sys.stderr)
        return 2

    if baseline_is_signed(loaded):
        status, message = baseline_signature_status(loaded, key)
        if status != "ok":
            if message:
                print(message, file=sys.stderr)
            print(
                "❌ Resignature refusée : la signature existante ne correspond pas à cette clé. "
                "Le fichier n'a pas été modifié.",
                file=sys.stderr,
            )
            return 2
        print("Signature existante vérifiée avec cette clé.", file=sys.stderr)
    else:
        if verify_baseline_key(loaded, key) is False:
            print(
                "❌ Clé incorrecte pour cette baseline (key_check ne correspond pas). "
                "Resignature refusée (exit 2).",
                file=sys.stderr,
            )
            return 2
        print(
            "Baseline non signée : ajout d'une signature HMAC-SHA256 sur le document actuel. "
            "Les entrées ne sont pas régénérées et le contenu n'est pas chiffré.",
            file=sys.stderr,
        )
        if _baseline_has_key_marker(loaded):
            print(
                "⚠ Signature absente alors que la baseline porte encore un marqueur de clé "
                "(encrypted / key_check). L'ancienne signature ne peut plus être vérifiée ; "
                "les écarts ci-dessous sont la seule trace avant resignature.",
                file=sys.stderr,
            )

    try:
        current = make_baseline(root)
        diff = diff_against_baseline(current, loaded)
    except (TypeError, KeyError, ValueError) as exc:
        print(f"❌ Baseline inutilisable pour la comparaison ({exc}).", file=sys.stderr)
        return 2
    print(format_resign_diff(diff, root), file=sys.stderr)

    unsigned = not baseline_is_signed(loaded)
    if _confirm_resign(assume_yes, unsigned=unsigned, trust_unsigned=trust_unsigned):
        return 2

    if unsigned:
        note_unsigned_resign(loaded)
    sign_baseline(loaded, key)
    try:
        backup_path = write_baseline_atomic(path, loaded, backup=backup)
    except OSError as exc:
        print(
            f"❌ Écriture impossible ({exc}). Le fichier d'origine est inchangé.", file=sys.stderr
        )
        return 2
    print(f"Baseline signée : {path}", file=sys.stderr)
    if backup_path is not None:
        print(f"Copie de l'original : {backup_path}", file=sys.stderr)
    return 0


def _load_baseline(
    path: Path,
    *,
    key: str | None,
    strict: bool,
    context: str,
    allow_unverified: bool = False,
    require_signed: bool = False,
) -> tuple[dict | None, int]:
    """Charge une baseline et vérifie clé + signature.

    Retourne ``(baseline, 0)`` pour continuer, ``(None, 0)`` pour
    continuer sans intégrité, ``(None, 2)`` pour arrêter. Une signature
    qui ne correspond pas est toujours un exit 2. Une baseline signée
    sans clé échoue aussi (exit 2), sauf ``allow_unverified`` — et
    ``require_signed`` désarme cet assouplissement. Une baseline
    ancienne, sans signature et sans marqueur de clé, est acceptée
    avec un avertissement, sauf ``require_signed`` (exit 2). Retirer
    la signature d'une baseline produite avec une clé (ou en fournir
    une) est un exit 2. Un fichier illisible avec ``require_signed``
    est aussi un exit 2 : on ne peut pas prouver qu'il était signé.
    """

    def _unreadable(msg: str) -> tuple[dict | None, int]:
        if strict or require_signed:
            reasons: list[str] = []
            if require_signed:
                reasons.append("--require-signed / SENTINEL_REQUIRE_SIGNED")
            if strict:
                reasons.append("--strict")
            print(f"❌ {msg} ({' et '.join(reasons)} : exit 2).", file=sys.stderr)
            return None, 2
        print(msg, file=sys.stderr)
        return None, 0

    try:
        loaded = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return _unreadable(f"Baseline illisible ({exc}), {context} sans intégrité.")
    if not isinstance(loaded, dict):
        return _unreadable(f"Baseline illisible (JSON inattendu), {context} sans intégrité.")

    if loaded.get("encrypted"):
        if key is None:
            print(
                "⚠ Baseline chiffrée : fournissez la clé (SENTINEL_KEY, --key-file "
                "ou --encrypt-key) pour la vérifier. "
                "SIG-0019 (« clé SSH ajoutée ») est désactivée (le contenu "
                "n'est pas récupérable depuis un HMAC).",
                file=sys.stderr,
            )
        else:
            valid = verify_baseline_key(loaded, key)
            if valid is False:
                print(
                    "❌ Clé incorrecte pour cette baseline (key_check ne correspond pas).",
                    file=sys.stderr,
                )
                return None, 2
            print(
                "⚠ Baseline chiffrée : clé validée. SIG-0019 reste désactivée "
                "(contenu non récupérable depuis un HMAC).",
                file=sys.stderr,
            )

    status, message = baseline_signature_status(loaded, key)
    if status in ("mismatch", "unsigned_refused"):
        print(message, file=sys.stderr)
        return None, 2
    if status == "unsigned" and require_signed:
        print(UNSIGNED_BASELINE_REFUSED, file=sys.stderr)
        return None, 2
    if status == "unverified" and (require_signed or not allow_unverified):
        print(
            UNVERIFIED_REQUIRED_REFUSED if require_signed else UNVERIFIED_BASELINE_REFUSED,
            file=sys.stderr,
        )
        return None, 2
    if status == "ok":
        notice = unsigned_resign_notice(loaded)
        if notice:
            print(notice, file=sys.stderr)
    if message:
        print(message, file=sys.stderr)
    return loaded, 0


def _engine_manifests(args: argparse.Namespace) -> list[Path]:
    """Journaux repris au démarrage du CLI, avant la commande."""
    paths = [default_journal_path()]
    if args.command == "quarantine":
        manifest = args.manifest if args.manifest is not None else args.dest / "manifest.jsonl"
        paths.append(manifest)
    elif args.command == "restore":
        paths.append(args.manifest)
    return paths


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée. Un chemin NT non canonisable est un refus, pas une traceback."""
    from .quarantine import JournalLocked

    try:
        return _main_inner(argv)
    except UnsafeNtPath as exc:
        print(f"❌ {unsafe_nt_message(exc)}", file=sys.stderr)
        return 2
    except JournalLocked as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1


def _main_inner(argv: list[str] | None = None) -> int:
    # P3-4 : on parse les args en deux temps pour gérer `--version` avant
    # la sous-commande (sinon `required=True` fait échouer la parse).
    if argv is None:
        argv = sys.argv[1:]
    # P3-4 : `--version` n'est intercepté qu'en première position. L'ancien
    # test `"--version" in argv` répondait à `sentinel scan --version`
    # (et à un dossier nommé `--version`) par la version du binaire.
    if argv[:1] in (["--version"], ["-V"]):
        from . import __version__

        print(f"sentinel {__version__}")
        return 0
    args = _build_parser().parse_args(argv)
    # Moteur : une entrée « en cours » est reprise avant toute commande,
    # y compris scan. Idempotent, rien n'est supprimé.
    init_engine(_engine_manifests(args))
    # `quarantine` ne reçoit pas de dossier mais une liste de chemins :
    # la validation du dossier ne s'applique qu'aux commandes qui en ont un.
    folder = getattr(args, "folder", None)
    if folder is not None:
        err = _require_directory(folder)
        if err:
            print(err, file=sys.stderr)
            return 2

    if args.command == "baseline":
        if args.resign is not None:
            if args.folder is not None or args.out is not None:
                print(
                    "❌ --resign réécrit la baseline en place (la racine est lue dans le JSON). "
                    "Ne passez ni dossier ni --out.",
                    file=sys.stderr,
                )
                return 2
            key, key_err = _resolve_command_key(args)
            if key_err:
                return key_err
            return _resign_baseline(
                args.resign,
                key=key,
                assume_yes=args.yes,
                backup=args.backup,
                trust_unsigned=args.trust_unsigned,
            )
        if args.yes or args.backup or args.trust_unsigned:
            print(
                "❌ --yes, --backup et --trust-unsigned ne s'utilisent qu'avec --resign.",
                file=sys.stderr,
            )
            return 2
        if args.folder is None or args.out is None:
            print(
                "❌ baseline attend un dossier et --out, ou --resign BASELINE.json.",
                file=sys.stderr,
            )
            return 2
        key, key_err = _resolve_command_key(args)
        if key_err:
            return key_err
        document = make_baseline(args.folder, encrypt_key=key)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(document, indent=2, sort_keys=True))
        if key is None:
            print(UNSIGNED_BASELINE_WARNING, file=sys.stderr)
        else:
            print(
                f"⚠ Baseline chiffrée et signée (HMAC-SHA256) — la clé n'est PAS "
                f"stockée dans {args.out}.",
                file=sys.stderr,
            )
        return 0

    if args.command == "scan":
        require_signed, policy_err = _enforce_signed_policy(args)
        if policy_err:
            return policy_err
        key, key_err = _resolve_command_key(args)
        if key_err:
            return key_err
        reference: dict | None = None
        if args.baseline is not None:
            reference, auth = _load_baseline(
                args.baseline,
                key=key,
                strict=args.strict,
                context="scan",
                allow_unverified=args.allow_unverified_baseline,
                require_signed=require_signed,
            )
            if auth:
                return auth

        # P3-1 : applique .sentinelignore si présent.
        from .reporting import render_sarif
        from .sentinelignore import apply_ignore

        report = scan_folder(
            args.folder,
            baseline=reference,
            with_anomaly=args.anomaly,
            top_n=args.top,
            with_neural=args.neural,
            model_path=args.model,
            follow_links=args.follow_links,
            encrypt_key=key,
        )

        # P3-1 : applique les filtres post-scan.
        report = apply_ignore(
            report,
            ignore_file=args.ignore_file,
            min_severity=args.min_severity,
            only=args.only,
        )

        # P3-2 : sortie SARIF pour GitHub Code Scanning.
        if args.format == "sarif":
            sys.stdout.write(render_sarif(report))
        elif args.format == "json":
            sys.stdout.write(render_json(report))
        else:
            sys.stdout.write(render_text(report))
        return report.exit_code

    if args.command == "train":
        scorer = AutoencoderScorer()
        rng = random.Random(args.seed)
        # L'Autoencoder est recréé ici pour appliquer la seed ; sinon le modèle
        # interne garderait sa seed 0xC0FFEE par défaut.
        from .neural import Autoencoder

        scorer.model = Autoencoder(rng=rng)
        # Même parcours que scan : pas de rglob (qui suit les symlinks
        # et lirait un fichier hors du corpus).
        skipped_external: list[str] = []
        files = list(
            _iter_text_files(
                args.folder,
                follow_links=args.follow_links,
                skipped_external=skipped_external,
            )
        )
        if skipped_external:
            print(
                f"⚠ {len(skipped_external)} symlink(s) ignoré(s) (cible hors du corpus).",
                file=sys.stderr,
            )
            for rel in skipped_external:
                print(f"  - {rel}", file=sys.stderr)
        if not files:
            print(f"Aucun fichier lisible trouvé dans {args.folder}", file=sys.stderr)
            return 2
        print(
            f"V3 — entraînement de l'autoencodeur (epochs={args.epochs}, lr={args.lr})",
            file=sys.stderr,
        )
        losses = scorer.train(
            files,
            epochs=args.epochs,
            lr=args.lr,
            verbose=True,
            follow_links=args.follow_links,
            root=args.folder,
        )
        if scorer.n_samples == 0:
            print(f"Aucun fichier texte lisible dans {args.folder}", file=sys.stderr)
            return 2
        print(f"Corpus : {scorer.n_samples} fichiers texte", file=sys.stderr)
        scorer.save(args.out)
        print(f"Modèle sauvegardé dans {args.out}", file=sys.stderr)
        if losses:
            print(f"Loss initiale : {losses[0]:.6f}  |  finale : {losses[-1]:.6f}", file=sys.stderr)
        return 0

    if args.command == "quarantine":
        # P1-2 : le manifest est en JSONL (1 ligne par entrée, append+fsync).
        # Défaut : <dest>/manifest.jsonl.
        if args.manifest is not None:
            manifest = args.manifest
        else:
            manifest = args.dest / "manifest.jsonl"
        records, failures = quarantine_paths(
            args.paths,
            args.dest,
            manifest,
            force=args.force,
        )
        # 0 = tout déplacé, 1 = au moins un échec (mais aucun fichier supprimé),
        # 2 = garde-fou chemin a refusé (dest sensible ou capture le périmètre).
        if failures and not records:
            return 2
        return 1 if failures else 0

    if args.command == "watch":
        require_signed, policy_err = _enforce_signed_policy(args)
        if policy_err:
            return policy_err
        key, key_err = _resolve_command_key(args)
        if key_err:
            return key_err
        # Charge la baseline (si fournie) une fois pour toutes.
        reference = None
        if args.baseline is not None:
            reference, auth = _load_baseline(
                args.baseline,
                key=key,
                strict=False,
                context="watch",
                allow_unverified=args.allow_unverified_baseline,
                require_signed=require_signed,
            )
            if auth:
                return auth
        unreadable_seen: list[str] = []

        def on_change(diff: dict) -> None:
            # Pas de cache sur le triplet de chemins : une deuxième édition
            # du même fichier produit les mêmes listes added/removed/modified
            # et était ignorée, alors que le contenu avait changé.
            print(f"\n=== changement détecté à {time.strftime('%H:%M:%S')} ===", file=sys.stderr)
            print(f"  added    : {diff['added']}", file=sys.stderr)
            print(f"  removed  : {diff['removed']}", file=sys.stderr)
            print(f"  modified : {diff['modified']}", file=sys.stderr)
            if diff.get("unreadable"):
                print(f"  unreadable: {diff['unreadable']}", file=sys.stderr)
            report = scan_folder(
                args.folder,
                baseline=reference,
                with_anomaly=args.anomaly,
                top_n=10,
                with_neural=args.neural,
                model_path=args.model,
                encrypt_key=key,
            )
            if args.json_lines:
                sys.stdout.write(render_json(report, indent=None) + "\n")
            else:
                sys.stdout.write(render_text(report))
            sys.stdout.flush()

        if has_watchdog():
            print(
                "watchdog détecté — surveillance événementielle (FSEvents/inotify).",
                file=sys.stderr,
            )
            try:
                watch_event(
                    args.folder,
                    on_change,
                    max_iterations=args.max_iterations or None,
                    debounce=args.debounce,
                    unreadable_out=unreadable_seen,
                )
            except KeyboardInterrupt:
                pass
        else:
            print(
                f"watchdog absent — fallback polling (intervalle={args.interval:.1f}s).\n"
                "  Astuce : `pip install watchdog` pour la surveillance événementielle.",
                file=sys.stderr,
            )
            try:
                watch_polling(
                    args.folder,
                    args.interval,
                    on_change,
                    max_iterations=args.max_iterations or None,
                    debounce=args.debounce,
                    unreadable_out=unreadable_seen,
                )
            except KeyboardInterrupt:
                pass
        # Même sémantique que le scan : un dossier illisible n'est pas un
        # succès. 3 est prioritaire sur un tour qui n'a rien d'autre à dire.
        return 3 if unreadable_seen else 0

    if args.command == "restore":
        # On vérifie le manifest AVANT d'appeler restore_paths : sinon un
        # manifest absent produisait deux messages (un de restore_paths,
        # un d'ici) pour la même erreur.
        if not args.manifest.is_file():
            print(f"❌ Manifest introuvable : {args.manifest}", file=sys.stderr)
            return 2
        only = set(args.only) if args.only else None
        _restored, failures = restore_paths(
            manifest_path=args.manifest,
            dest_dir=args.dest,
            force=args.force,
            only=only,
        )
        # 0 = tout restauré ; 1 = au moins un échec ; 2 = manifest inexistant.
        return 1 if failures else 0

    return 2  # argparse.required=True devrait empêcher d'arriver ici


if __name__ == "__main__":
    sys.exit(main())
