"""Renderers pour la sortie humaine (text) et machine (json)."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .guidance import guidance
from .models import Report

# Le rapport texte ne liste que les scores élevés. Le JSON garde tout.
_ANOMALY_TEXT_MIN = 60.0


def _ignored_payload(report: Report) -> list[dict[str, Any]]:
    """Findings filtrés, sérialisables (P3-1).

    `ignored_findings` contient des objets `Finding` et `IgnoreRule` : on
    les aplatit pour que l'audit soit réellement lisible dans le JSON et
    le SARIF, au lieu de rester une structure interne invisible.
    """
    out: list[dict[str, Any]] = []
    for entry in getattr(report, "ignored_findings", []) or []:
        finding = entry.get("finding")
        rule = entry.get("rule")
        out.append(
            {
                "rule_id": getattr(finding, "rule_id", None),
                "severity": getattr(finding, "severity", None),
                "path": getattr(finding, "path", None),
                "line": getattr(finding, "line", None),
                "message": getattr(finding, "message", None),
                "evidence": getattr(finding, "evidence", None),
                "guidance": guidance(finding.rule_id) if finding else None,
                "suppression_fingerprint": finding.suppression_fingerprint() if finding else None,
                "reason": entry.get("reason", ""),
                "ignore_rule": getattr(rule, "rule_id", None),
                "ignore_path": getattr(rule, "path_pattern", None),
                "justification": getattr(rule, "reason", "") if rule else "",
                "date": getattr(rule, "date", "") if rule else "",
            }
        )
    return out


def render_json(report: Report, *, indent: int | None = 2) -> str:
    """Sérialise le rapport en JSON.

    P3-3 : `indent=None` produit une sortie compacte sans newlines,
    utilisable en mode `json-lines` (un rapport par ligne, idéal pour
    `tail -f` ou l'ingestion streaming).
    """
    payload: dict[str, Any] = {
        # P3-2 : version + tool pour permettre l'évolution du format
        # sans casser les consommateurs.
        "tool": "sentinel",
        "version": _TOOL_VERSION,
        "schema": 2,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "path": f.path,
                "line": f.line,
                "message": f.message,
                "evidence": f.evidence,
                "fingerprint": f.fingerprint(),
                "suppression_fingerprint": f.suppression_fingerprint(),
                "guidance": guidance(f.rule_id),
            }
            for f in report.findings
        ],
        "severity_counts": report.severity_counts,
        "overall_severity": report.overall_severity,
        "integrity": {
            "added": list(report.integrity.added),
            "removed": list(report.integrity.removed),
            "modified": list(report.integrity.modified),
            "mode_changed": list(report.integrity.mode_changed),
            "owner_changed": list(getattr(report.integrity, "owner_changed", [])),
            "cap_changed": list(getattr(report.integrity, "cap_changed", [])),
        },
        "integrity_counts": {
            "added": len(report.integrity.added),
            "removed": len(report.integrity.removed),
            "modified": len(report.integrity.modified),
            "mode_changed": len(report.integrity.mode_changed),
            "owner_changed": len(getattr(report.integrity, "owner_changed", [])),
            "cap_changed": len(getattr(report.integrity, "cap_changed", [])),
        },
        "anomalies": [
            {
                "path": a.path,
                "score": a.score,
                "entropy": a.entropy,
                "max_line_len": a.max_line_len,
                "nonprintable_ratio": a.nonprintable_ratio,
                "shell_metachar_ratio": a.shell_metachar_ratio,
                "avg_line_len": a.avg_line_len,
                "method": a.method,
            }
            for a in report.anomalies
        ],
        "coverage": {
            "scanned_files": report.scanned_files,
            "binary_files": list(report.binary_files),
            "excluded_entries": list(report.excluded_entries),
            "disappeared_files": list(report.disappeared_files),
            "unreadable_paths": list(report.unreadable),
        },
        "skipped_external": list(getattr(report, "skipped_external", [])),
        # Chemins non lus (permissions). Exit code 3 si la liste n'est pas vide.
        "unreadable": list(getattr(report, "unreadable", [])),
        # P3-1 : les findings filtrés doivent être audités, pas effacés.
        "ignored_count": len(getattr(report, "ignored_findings", []) or []),
        "ignored_findings": _ignored_payload(report),
    }
    return json.dumps(payload, indent=indent, sort_keys=False)


# P3-2 : exposé pour les consommateurs (CI scripts) qui veulent
# vérifier qu'ils lisent la bonne version.
_TOOL_VERSION = __version__


def render_sarif(report: Report) -> str:
    """P3-2 (M) : sortie SARIF 2.1.0 pour GitHub Code Scanning.

    SARIF = Static Analysis Results Interchange Format. C'est le format
    standard ingéré par l'onglet "Security > Code scanning" de GitHub.
    Format JSON strict, voir https://docs.oasis-open.org/sarif/sarif/v2.1.0/.

    Chaque finding est converti en `result` avec :
      - ruleId (SIG-XXXX)
      - level (error/warning/note) dérivé de la sévérité
      - message.text
      - location.physicalLocation.artifactLocation.uri (relatif)
      - location.physicalLocation.region.startLine
      - partialFingerprints (fingerprint stable d'un run à l'autre)
      - properties.justification / properties.date (si filtré)
    """

    def level(sev: str) -> str:
        return {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }.get(sev, "warning")

    rules_index: dict[str, int] = {}
    sarif_rules: list[dict] = []

    def register(f) -> int:
        if f.rule_id in rules_index:
            return rules_index[f.rule_id]
        rules_index[f.rule_id] = len(sarif_rules)
        sarif_rules.append(
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message},
                "defaultConfiguration": {"level": level(f.severity)},
            }
        )
        return rules_index[f.rule_id]

    results: list[dict] = []
    for f in report.findings:
        idx = register(f)
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": idx,
                "level": level(f.severity),
                "message": {"text": f"{f.message} — {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.line},
                        },
                    }
                ],
                "properties": {
                    "guidance": guidance(f.rule_id),
                    "suppressionFingerprint": f.suppression_fingerprint(),
                },
                "partialFingerprints": {
                    # P3-2 : fingerprint stable pour suivre un constat d'un
                    # run à l'autre dans l'UI GitHub.
                    "sentinelFingerprint/v1": f.fingerprint(),
                },
            }
        )

    # P3-1 : les findings filtrés (.sentinelignore / --min-severity / --only)
    # sont émis en résultats *supprimés* plutôt qu'omis. Sinon un CI qui
    # ingère le SARIF ne voit aucune trace de ce qui a été écarté, et une
    # règle d'ignore trop large passe inaperçue.
    for entry in getattr(report, "ignored_findings", []) or []:
        f = entry.get("finding")
        if f is None:
            continue
        idx = register(f)
        rule = entry.get("rule")
        justification = entry.get("reason") or "filtré"
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": idx,
                "level": level(f.severity),
                "message": {"text": f"{f.message} — {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.line},
                        },
                    }
                ],
                "suppressions": [{"kind": "external", "justification": justification}],
                "partialFingerprints": {"sentinelFingerprint/v1": f.fingerprint()},
                "properties": {
                    "justification": justification,
                    "guidance": guidance(f.rule_id),
                    "suppressionFingerprint": f.suppression_fingerprint(),
                    "date": getattr(rule, "date", "") if rule else "",
                },
            }
        )

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinel",
                        "version": _TOOL_VERSION,
                        "informationUri": "https://github.com/Kyyzen0/sentinel",
                        "rules": sarif_rules,
                    },
                },
                "properties": {
                    "coverage": {
                        "scanned_files": report.scanned_files,
                        "binary_files": list(report.binary_files),
                        "excluded_entries": list(report.excluded_entries),
                        "unreadable_paths": list(report.unreadable),
                        "disappeared_files": list(report.disappeared_files),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_text(report: Report) -> str:
    lines: list[str] = []
    lines.append("SENTINEL")
    lines.append(
        f"overall_severity: {report.overall_severity}\n"
        f"severity_counts: "
        f"critical={report.severity_counts['critical']} "
        f"high={report.severity_counts['high']} "
        f"medium={report.severity_counts['medium']} "
        f"low={report.severity_counts['low']}"
    )
    lines.append(
        "integrity_counts: "
        f"added={len(report.integrity.added)} "
        f"removed={len(report.integrity.removed)} "
        f"modified={len(report.integrity.modified)} "
        f"mode_changed={len(report.integrity.mode_changed)} "
        f"owner_changed={len(report.integrity.owner_changed)} "
        f"cap_changed={len(report.integrity.cap_changed)}"
    )
    lines.append(
        f"coverage: scanned_files={report.scanned_files} binary_files={len(report.binary_files)} "
        f"excluded_entries={len(report.excluded_entries)} unreadable_paths={len(report.unreadable)} "
        f"disappeared_files={len(report.disappeared_files)}"
    )
    for label, paths in (
        ("binary_files", report.binary_files),
        ("excluded_entries", report.excluded_entries),
        ("disappeared_files", report.disappeared_files),
    ):
        if paths:
            lines.append(f"{label}: " + ", ".join(paths))
    unreadable = list(getattr(report, "unreadable", []) or [])
    if unreadable:
        lines.append("")
        lines.append(
            f"unreadable: {len(unreadable)} (exit 3, couverture incomplète — contenu non lu)"
        )
        for rel in unreadable:
            lines.append(f"  - {rel}")
    lines.append("")
    lines.append("findings:")
    if report.findings:
        for f in report.findings:
            lines.append(f"[{f.severity}] {f.rule_id} {f.path}:{f.line}")
            lines.append(f"  {f.message}")
            lines.append(f"  evidence: {f.evidence}")
            lines.append(f"  limite: {guidance(f.rule_id)['limitation']}")
            lines.append(f"  à vérifier: {guidance(f.rule_id)['check']}")
            lines.append(f"  suppression_fingerprint: {f.suppression_fingerprint()}")
    else:
        lines.append("(aucun)")

    shown = [a for a in report.anomalies if a.score >= _ANOMALY_TEXT_MIN][: report.top_n]
    if shown:
        method = shown[0].method
        if method == "autoencoder":
            header = "anomalies : autoencodeur neuronal (V3, score = MSE reconstruit × 100)"
        elif method and method.startswith("autoencoder"):
            header = f"anomalies : autoencodeur neuronal ({method}, non entraîné)"
        else:
            header = "anomalies : heuristique, non neuronal"
        lines.append("")
        lines.append(header)
        for a in shown:
            lines.append(
                f"- {a.path} score={a.score:.0f} — "
                f"entropy={a.entropy:.6f}, max_line_len={a.max_line_len}, "
                f"nonprintable_ratio={a.nonprintable_ratio}, "
                f"shell_metachar_ratio={a.shell_metachar_ratio}, "
                f"avg_line_len={a.avg_line_len:.1f}"
            )

    lines.append("")
    lines.append("integrity:")
    lines.append(
        f"added: {_fmt_list(report.integrity.added)}\n"
        f"removed: {_fmt_list(report.integrity.removed)}\n"
        f"modified: {_fmt_list(report.integrity.modified)}\n"
        f"mode_changed: {_fmt_list(report.integrity.mode_changed)}\n"
        f"owner_changed: {_fmt_list(report.integrity.owner_changed)}\n"
        f"cap_changed: {_fmt_list(report.integrity.cap_changed)}"
    )

    # P3-1 : un finding filtré n'est pas un finding inexistant. On affiche
    # le compte et les raisons, sinon une règle d'ignore trop large rend
    # le scan silencieusement vert.
    ignored = getattr(report, "ignored_findings", []) or []
    if ignored:
        lines.append("")
        lines.append(f"ignored_findings: {len(ignored)} (filtrés, non comptés ci-dessus)")
        for entry in ignored:
            f = entry.get("finding")
            if f is not None:
                lines.append(
                    f"  - {f.rule_id} {f.path}:{f.line} : {entry.get('reason', '')} (empreinte {f.suppression_fingerprint()})"
                )
    return "\n".join(lines) + "\n"


def _fmt_list(xs: list[str]) -> str:
    return ", ".join(xs) if xs else "(aucun)"
