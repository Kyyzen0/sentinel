"""Modèles de données et structures partagées."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Severity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True)
class Finding:
    rule_id: str  # ex. "SIG-0001"
    severity: Severity  # critical | high | medium | low
    path: str  # chemin relatif au dossier scanné
    line: int  # 1-indexed
    message: str  # description courte (FR)
    evidence: str  # extrait déclencheur

    def fingerprint(self) -> str:
        """P3-2 : identifiant stable d'un finding à travers les runs.

        Hash SHA-256 (tronqué) de `(rule_id, path, line, message)`. La
        `evidence` n'est pas incluse : elle peut varier légèrement
        (troncature à 48 chars, normalisations P0-5). Le fingerprint
        suit le **constat**, pas l'extrait.

        Format : 16 chars hexadécimaux (64 bits), compatible avec les
        fingerprints SARIF/GitHub Code Scanning.
        """
        h = hashlib.sha256(
            f"{self.rule_id}|{self.path}|{self.line}|{self.message}".encode()
        ).hexdigest()
        return h[:16]


@dataclass(frozen=True)
class AnomalyScore:
    path: str
    score: float  # 0..100
    entropy: float
    max_line_len: int
    nonprintable_ratio: float
    shell_metachar_ratio: float
    avg_line_len: float
    method: str = "heuristic"  # "heuristic" (V2) | "autoencoder" (V3)


@dataclass
class IntegrityDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    mode_changed: list[str] = field(default_factory=list)
    # P0-4 : uid/gid a changé (chown) — vecteur classique de privesc.
    owner_changed: list[str] = field(default_factory=list)
    # P0-4 : capabilities Linux ont changé (getcap) — plus pertinent que
    # SUID aujourd'hui. Vide sur macOS / si getcap n'est pas installé.
    cap_changed: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RuleContext:
    """Contexte passé à chaque règle pendant un scan.

    Permet aux règles « augmentées » de prendre des décisions qui dépendent
    soit du filesystem (mode du fichier scanné), soit d'un état précédent
    (contenu du même fichier dans la baseline d'intégrité).
    """

    file_mode: int | None = None  # st_mode brut du fichier scanné
    baseline_text: str | None = None  # contenu du même fichier dans la baseline
    baseline_mode: int | None = None  # mode du même fichier dans la baseline


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    anomalies: list[AnomalyScore] = field(default_factory=list)
    integrity: IntegrityDiff = field(default_factory=IntegrityDiff)
    root: Path = field(default_factory=lambda: Path("."))
    top_n: int = 10
    # Chemins (relatifs) des symlinks dont la cible est hors-confinement et
    # qui ont donc été ignorés même avec `follow_links=True`. Sert d'audit
    # pour que l'utilisateur sache ce qui n'a PAS été scanné.
    skipped_external: list[str] = field(default_factory=list)
    # P3-1 : findings filtrés par `.sentinelignore`, `--min-severity`
    # ou `--only`. Stockés pour audit (visibles en SARIF / JSON).
    # Chaque entrée : {finding: Finding, reason: str, rule: IgnoreRule|None}.
    ignored_findings: list[dict] = field(default_factory=list)
    # Chemins relatifs qu'on n'a pas pu lister ou lire (permissions, EIO).
    # Un binaire volontairement ignoré n'y figure pas. Non vide → exit 3.
    unreadable: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            out[f.severity] += 1
        return out

    @property
    def overall_severity(self) -> Severity:
        order: tuple[Severity, ...] = ("critical", "high", "medium", "low")
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "low"

    @property
    def exit_code(self) -> int:
        # 0 : rien ; 1 : au moins un finding OU une modification d'intégrité ;
        # 2 : erreur (gérée en amont) ; 3 : couverture incomplète (chemin
        # illisible). L'anomalie seule ne change pas l'exit code.
        #
        # 3 est prioritaire sur 1 : un exit 1 ressemble à un scan complet
        # qui a trouvé quelque chose, et masquerait un dossier jamais listé.
        # Les findings déjà obtenus restent dans le rapport.
        if self.unreadable:
            return 3
        #
        # owner_changed / cap_changed comptent : un `chown root` ou un
        # `setcap cap_setuid+ep` ne touche ni au contenu ni au mode, mais
        # c'est précisément un signal d'escalade. Les oublier ici faisait
        # sortir le scan en 0 (CI verte) alors que le rapport signalait
        # le changement.
        if (
            self.findings
            or self.integrity.modified
            or self.integrity.added
            or self.integrity.removed
            or self.integrity.mode_changed
            or self.integrity.owner_changed
            or self.integrity.cap_changed
        ):
            return 1
        return 0
