"""Moteur de scan — assemble les détecteurs de signatures + scoring d'anomalie."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path

from .anomaly import score_autoencoder, score_heuristic
from .files import (
    BinarySkipped,
    TextWindow,
    UnreadablePath,
    is_ignored,
    iter_text_windows,
)
from .integrity import (
    baseline_text_from_entry,
    diff_against_baseline,
    make_baseline,
)
from .models import Report, RuleContext
from .normalize import normalize_for_rules
from .platform import OperationCancelled, is_link
from .signatures import ALL_RULES, _iter_lines


def _line_has_any(line: str, keywords: set[str]) -> bool:
    """P2-3 : vrai si au moins un des sous-chaînes est présent dans la ligne.

    L'implémentation naïve `any(kw in line for kw in keywords)` fait une
    recherche par keyword. Sur un keyword rare (long, discriminant),
    c'est plus rapide qu'une regex ; sur un keyword court et commun,
    c'est à peu près équivalent. C'est une pré-filtrage, pas un
    remplacement de regex.
    """
    for kw in keywords:
        if kw in line:
            return True
    return False


def _rel_posix(folder: Path, raw: str) -> str:
    try:
        rel = os.path.relpath(raw, folder)
    except ValueError:
        rel = raw
    text = Path(rel).as_posix()
    return "." if text == "." else text


def _remember(bucket: list[str], rel: str) -> None:
    if rel not in bucket:
        bucket.append(rel)


def _iter_text_files(
    folder: Path,
    *,
    follow_links: bool = False,
    skipped_external: list[str] | None = None,
    unreadable: list[str] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> Iterable[Path]:
    """Itère les fichiers sous `folder`.

    Politique par défaut : on **ne suit pas** les symlinks, ni les
    jonctions / points de reparse Windows. Un lien dans le dossier
    scanné est ignoré. C'est la position la plus sûre : un attaquant
    qui dépose un symlink ou une jonction vers un fichier sensible
    (ex. `/etc/passwd`) ne fait ainsi plus remonter son contenu.

    Avec `follow_links=True`, on accepte un lien *fichier* SAUF si sa
    cible résolue est hors du dossier scanné (containment). Les cibles
    hors-périmètre sont ajoutées à `skipped_external` pour audit. Un
    dossier jonction ou symlink n'est jamais descendu : ``os.walk``
    suivrait une jonction que ``is_symlink`` ne signale pas.

    Le parcours est `os.walk(onerror=…)` et non `rglob` : un dossier en
    mode 000 est signalé dans `unreadable` au lieu d'être sauté en silence.

    P2-2 : la sortie est **triée par chemin** pour rendre le scan
    déterministe (sinon l'ordre dépend de l'OS sur le FS, et le JSON
    change entre deux runs identiques — diff CI illisible).
    """

    def onerror(err: OSError) -> None:
        # Disparu entre deux lectures : pas une erreur d'accès.
        if isinstance(err, FileNotFoundError):
            return
        raw = err.filename or str(folder)
        if unreadable is not None:
            _remember(unreadable, _rel_posix(folder, raw))

    found: list[Path] = []
    root_resolved = folder.resolve()
    for dirpath, dirnames, filenames in os.walk(
        folder, topdown=True, onerror=onerror, followlinks=False
    ):
        if cancel is not None and cancel():
            raise OperationCancelled("scan interrompu")
        kept_dirs: list[str] = []
        for name in dirnames:
            child = Path(dirpath) / name
            if is_ignored(child):
                continue
            # Jonction ou symlink de dossier : ne jamais descendre.
            # `followlinks=False` ne suffit pas pour une jonction que
            # Python ne classe pas comme symlink.
            if is_link(child):
                if follow_links and skipped_external is not None:
                    try:
                        target = child.resolve()
                        target.relative_to(root_resolved)
                    except (OSError, ValueError):
                        skipped_external.append(child.relative_to(folder).as_posix())
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in filenames:
            p = Path(dirpath) / name
            if is_ignored(p):
                continue
            # `is_file()` suit le lien : on décide avant, pour ne pas stat
            # (et encore moins lire) une cible hors corpus.
            if is_link(p):
                if not follow_links:
                    continue
                # Containment check : la cible résolue doit rester sous `folder`.
                try:
                    target = p.resolve()
                except OSError:
                    # Lien cassé : on skip.
                    continue
                try:
                    target.relative_to(root_resolved)
                except ValueError:
                    # Cible hors-confinement.
                    if skipped_external is not None:
                        skipped_external.append(p.relative_to(folder).as_posix())
                    continue
            if not p.is_file():
                continue
            found.append(p)
    yield from sorted(found)


def _overlap_line_count(text: str, overlap_chars: int) -> int:
    """Lignes (1-based, relatives) qui se terminent dans le préfixe overlap.

    Elles ont déjà été vues en entier dans la fenêtre précédente.
    """
    if overlap_chars <= 0:
        return 0
    return text[:overlap_chars].count("\n")


def _findings_in_window(
    rel: str,
    window: TextWindow,
    context: RuleContext,
    seen: set[tuple[str, str, int, str]],
) -> list:
    """Findings de la fenêtre, numéros de ligne absolus, overlap dédupliqué."""
    overlap_lines = _overlap_line_count(window.text, window.overlap_chars)
    text = normalize_for_rules(window.text)
    lines = [line for _ln, line in _iter_lines(text)]
    out = []
    for rule in ALL_RULES:
        keywords = rule.quick_keywords()
        if keywords is not None and not any(_line_has_any(line, keywords) for line in lines):
            continue
        for finding in rule.scan(rel, text, context):
            if finding.line <= overlap_lines:
                continue
            adjusted = replace(finding, line=window.start_line + finding.line - 1)
            key = (adjusted.rule_id, adjusted.path, adjusted.line, adjusted.evidence)
            if key in seen:
                continue
            seen.add(key)
            out.append(adjusted)
    return out


def _scan_file_rules(path: Path, rel: str, context: RuleContext) -> tuple[list, str | None]:
    """Signatures sur tout le fichier. Retourne (findings, extrait brut).

    L'extrait est la première fenêtre (bornée) pour le cache d'anomalie.
    None si le fichier est binaire. Lève UnreadablePath / FileNotFoundError.
    """
    for encoding in ("utf-8", "latin-1"):
        try:
            findings: list = []
            sample: str | None = None
            seen: set[tuple[str, str, int, str]] = set()
            for window in iter_text_windows(path, encoding=encoding):
                if sample is None:
                    sample = window.text
                findings.extend(_findings_in_window(rel, window, context, seen))
            return findings, "" if sample is None else sample
        except UnicodeDecodeError:
            if encoding == "latin-1":
                raise
            continue
    return [], None


def scan_folder(
    folder: Path,
    *,
    baseline: dict | None = None,
    integrity=None,  # (déprécié) alias pour compat ascendante
    with_anomaly: bool = False,
    top_n: int = 10,
    with_neural: bool = False,
    model_path: Path | None = None,
    follow_links: bool = False,
    encrypt_key: str | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> Report:
    report = Report(root=folder, top_n=max(0, top_n))

    # P2-1 : cache path → text partagé entre la rule loop, l'anomaly et
    # l'autoencodeur. Un fichier n'est lu qu'une fois par scan.
    text_cache: dict[Path, str | None] = {}

    # Si une baseline est fournie, on calcule le diff d'intégrité ET on garde
    # la table des entrées pour bâtir le RuleContext par fichier.
    baseline_map: dict[str, dict] = {}
    if baseline is not None:
        try:
            current = make_baseline(folder, encrypt_key=encrypt_key)
            report.integrity = diff_against_baseline(current, baseline)
        except (OSError, KeyError, TypeError) as exc:
            print(
                f"Baseline illisible ({exc}), scan sans intégrité.", file=__import__("sys").stderr
            )
        baseline_map = {e["path"]: e for e in baseline.get("entries", [])}
    elif integrity is not None:
        # Compat ascendante : l'ancien caller passait déjà un IntegrityDiff.
        report.integrity = integrity

    files = list(
        _iter_text_files(
            folder,
            follow_links=follow_links,
            skipped_external=report.skipped_external,
            unreadable=report.unreadable,
            cancel=cancel,
        )
    )
    # Fichiers dont la baseline n'embarque pas le contenu (V1, ou V2 >64 KB).
    # Les règles augmentées (SIG-0019, etc.) sont silencieusement inactives
    # dessus — on les signale en fin de scan pour que l'utilisateur sache
    # régénérer sa baseline.
    no_baseline_text: list[str] = []
    sensitive_redacted: list[str] = []

    total = len(files)
    for index, path in enumerate(files, start=1):
        if cancel is not None and cancel():
            raise OperationCancelled("scan interrompu")
        rel = path.relative_to(folder).as_posix()
        if on_progress is not None:
            on_progress(rel, index, total)

        # Contexte : mode du fichier, contenu baseline, mode baseline.
        try:
            file_mode = path.stat().st_mode
        except OSError:
            file_mode = None

        b_entry = baseline_map.get(rel)
        # Le contenu baseline peut manquer : baseline V1 (pas de contenu),
        # baseline chiffrée (HMAC irréversible) ou fichier > content_max.
        # On le signale pour que les règles augmentées dépendantes de
        # l'historique (SIG-0019) soient diagnostiquables — un `content`
        # présent mais à None doit déclencher le warning, pas seulement
        # l'absence de la clé.
        baseline_text = baseline_text_from_entry(b_entry)
        fingerprints = b_entry.get("ssh_key_fingerprints") if b_entry else None
        if b_entry is not None and baseline_text is None and fingerprints is None:
            if b_entry.get("content_redacted") == "sensitive":
                sensitive_redacted.append(rel)
            else:
                no_baseline_text.append(rel)
        baseline_mode = b_entry.get("mode") if b_entry else None

        context = RuleContext(
            file_mode=file_mode,
            baseline_text=baseline_text,
            baseline_mode=baseline_mode,
            baseline_ssh_fingerprints=frozenset(fingerprints) if fingerprints is not None else None,
        )

        # P0-5 : la normalisation est appliquée par fenêtre (1 ligne → 1
        # ligne). Un fichier plus gros que la fenêtre est couvert en
        # entier ; l'overlap évite de rater un match à cheval.
        try:
            findings, sample = _scan_file_rules(path, rel, context)
        except FileNotFoundError:
            # Disparu entre le walk et la lecture : pas une erreur d'accès.
            continue
        except UnreadablePath:
            _remember(report.unreadable, rel)
            text_cache[path] = None
            continue
        except BinarySkipped:
            text_cache[path] = None
            continue
        text_cache[path] = sample
        report.findings.extend(findings)

    if with_anomaly:
        if with_neural:
            scores = score_autoencoder(files, model_path=model_path, root=folder)
        else:
            # P2-1 : on passe le cache pour éviter de re-lire.
            scores = score_heuristic(files, root=folder, text_cache=text_cache)
        scores.sort(key=lambda s: s.score, reverse=True)
        report.anomalies = scores

    if sensitive_redacted:
        # Même contrat que la baseline chiffrée : le clair n'est pas là,
        # SIG-0019 ne peut pas comparer, et on le dit au lieu de se taire.
        print(
            f"\n⚠ {len(sensitive_redacted)} fichier(s) sensible(s) : contenu non embarqué "
            "(seul le SHA-256 est conservé — clé privée, authorized_keys, .env, "
            "marqueur SIG-0008). SIG-0019 (« clé ajoutée ») est désactivée pour eux, "
            "comme pour une baseline chiffrée : le clair n'est plus écrit.",
            file=__import__("sys").stderr,
        )
        for rel in sensitive_redacted:
            print(f"  - {rel}", file=__import__("sys").stderr)
    if no_baseline_text:
        why = "baseline V1, baseline chiffrée, ou fichier > 64 KB"
        print(
            f"\n⚠ {len(no_baseline_text)} fichier(s) sans contenu exploitable dans la baseline "
            f"({why}). Les règles augmentées (SIG-0019 « clé ajoutée », etc.) "
            "sont désactivées pour eux. Régénère la baseline avec "
            "`python3 -m sentinel baseline ...` (sans --encrypt-key) pour les réactiver "
            "quand le fichier n'est pas sensible.",
            file=__import__("sys").stderr,
        )
    if report.unreadable:
        report.unreadable.sort()
        # Exit 3 (voir Report.exit_code) : un scan incomplet ne doit pas
        # sortir 0, ni se confondre avec un scan complet qui a des findings.
        print(
            f"\n⚠ {len(report.unreadable)} chemin(s) illisible(s) — scan incomplet "
            "(exit 3). Le contenu n'a pas pu être lu.",
            file=__import__("sys").stderr,
        )
        for rel in report.unreadable:
            print(f"  - {rel}", file=__import__("sys").stderr)
    if report.skipped_external:
        print(
            f"\n⚠ {len(report.skipped_external)} lien(s) ignoré(s) "
            "(symlink, jonction ou point de reparse, cible hors-confinement). "
            "Voir `report.skipped_external` ou relancer avec `--follow-links` "
            "pour les inclure quand même.",
            file=__import__("sys").stderr,
        )
    return report
