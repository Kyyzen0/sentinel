"""P3-1 : `.sentinelignore` — gestion des faux positifs.

Le bug : un scanner interne qui crache 200 findings par run se fait
désactiver par les utilisateurs. C'est la première cause d'abandon.

Le fix : un fichier `.sentinelignore` à la racine du dossier scanné,
qui liste les faux positifs reconnus (avec justification) et un seuil
de sévérité minimal.

Format de `.sentinelignore` (lignes vides et `# commentaire` ignorés) :

  # Format : règle / chemin (relatif au dossier scanné) / justification / date
  SIG-0007                       anywhere       demo signatures        2025-01-10
  SIG-0002                       tests/         reverse shell tests    2025-02-15
  SIG-0007                       vendor/*.php   bibliothèque externe   2025-03-01

La règle ET le chemin doivent matcher. Un motif qui se termine par `/`
est un préfixe de dossier (`tests/` couvre `tests/reverse.sh`). La
justification et la date sont stockées pour audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from .models import Finding, Report

# Ordre canonique de sévérité (P3-1 : --min-severity).
SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass(frozen=True)
class IgnoreRule:
    """Une ligne du `.sentinelignore`."""

    rule_id: str  # "SIG-0007" ou "*" (toutes)
    path_pattern: str  # "anywhere", "vendor/*.php", etc.
    reason: str = ""  # justification humaine
    date: str = ""  # ISO date d'ajout


@dataclass
class IgnoreFile:
    rules: list[IgnoreRule] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # lignes mal formées


def parse_ignore_file(path: Path) -> IgnoreFile:
    """Parse un `.sentinelignore`. Tolérant : les lignes mal formées
    sont ajoutées à `skipped` (avec un warning sur stderr)."""
    out = IgnoreFile()
    if not path.is_file():
        return out
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Format : RULE PATH [REASON] [DATE]
        # La date est détectée si elle matche YYYY-MM-DD en fin de ligne.
        # Le reste est concaténé en `reason`.
        parts = line.split(None, 2)  # max 3 parts (rule, path, reste)
        if len(parts) < 2:
            print(
                f"⚠ .sentinelignore:{lineno} ligne ignorée (format invalide) : {line!r}",
                file=__import__("sys").stderr,
            )
            out.skipped.append(line)
            continue
        rule_id = parts[0]
        path_pat = parts[1]
        reason = parts[2] if len(parts) >= 3 else ""
        # Extrait la date (YYYY-MM-DD) si elle est en fin de `reason`.
        import re as _re

        m = _re.search(r"\b(\d{4}-\d{2}-\d{2})\b\s*$", reason)
        date = m.group(1) if m else ""
        if m:
            reason = reason[: m.start()].rstrip()
        out.rules.append(
            IgnoreRule(
                rule_id=rule_id,
                path_pattern=path_pat,
                reason=reason,
                date=date,
            )
        )
    return out


def _matches(finding: Finding, rule: IgnoreRule) -> bool:
    """Vrai si le finding matche la règle d'ignore."""
    rule_ok = rule.rule_id == finding.rule_id or rule.rule_id == "*"
    if not rule_ok:
        return False
    pat = rule.path_pattern
    if pat in ("anywhere", "*", "**"):
        return True
    path = finding.path
    # `tests/` est un préfixe de dossier, pas un glob : fnmatch("tests/a.sh",
    # "tests/") est faux, donc l'exemple documenté ne filtrait rien.
    if pat.endswith("/"):
        prefix = pat.rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    # Match par glob (fnmatch) sur le path du finding.
    return fnmatch(path, pat) or fnmatch(path, f"**/{pat}")


def apply_ignore(
    report: Report,
    *,
    ignore_file: Path,
    min_severity: str = "low",
    only: str | None = None,
) -> Report:
    """Filtre le rapport selon `.sentinelignore` + `--min-severity` + `--only`.

    Renvoie un NOUVEAU rapport (le rapport original n'est pas muté).
    Les findings filtrés sont stockés dans `report.ignored_findings` (P3-2 :
    visible dans la sortie SARIF / JSON pour audit).
    """
    ignore_data = parse_ignore_file(ignore_file)
    sev_min = SEVERITY_ORDER.get(min_severity, 0)

    kept: list[Finding] = []
    ignored: list[dict] = []  # {finding, reason, rule}

    for f in report.findings:
        # Filtre par sévérité.
        if SEVERITY_ORDER.get(f.severity, 0) < sev_min:
            ignored.append(
                {
                    "finding": f,
                    "reason": f"min-severity={min_severity}",
                    "rule": None,
                }
            )
            continue
        # Filtre par préfixe de rule_id (--only).
        if only is not None and not f.rule_id.startswith(only):
            ignored.append(
                {
                    "finding": f,
                    "reason": f"only={only}",
                    "rule": None,
                }
            )
            continue
        # Filtre par .sentinelignore.
        matched_rule: IgnoreRule | None = None
        for rule in ignore_data.rules:
            if _matches(f, rule):
                matched_rule = rule
                break
        if matched_rule is not None:
            ignored.append(
                {
                    "finding": f,
                    "reason": matched_rule.reason or "(pas de justification)",
                    "rule": matched_rule,
                }
            )
            continue
        kept.append(f)

    # P3-1 : on stocke les findings filtrés pour audit (visible en JSON/SARIF).
    if hasattr(report, "ignored_findings"):
        report.ignored_findings = ignored
    new = Report(
        findings=kept,
        anomalies=report.anomalies,
        integrity=report.integrity,
        root=report.root,
        top_n=report.top_n,
        skipped_external=getattr(report, "skipped_external", []),
        unreadable=list(getattr(report, "unreadable", []) or []),
    )
    # Copie les attributs additionnels.
    if hasattr(report, "ignored_findings"):
        new.ignored_findings = ignored
    return new


def render_ignore_summary(ignored: list[dict]) -> str:
    """Résumé texte des findings filtrés (pour la sortie text)."""
    if not ignored:
        return ""
    by_reason: dict[str, int] = {}
    for entry in ignored:
        by_reason[entry["reason"]] = by_reason.get(entry["reason"], 0) + 1
    lines = ["", f"({len(ignored)} findings filtrés)"]
    for reason, count in sorted(by_reason.items(), key=lambda x: -x[1])[:5]:
        lines.append(f"  - {count} : {reason}")
    return "\n".join(lines)
