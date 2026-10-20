"""Appels au moteur, sans Qt et sans sous-processus.

La resignature reprend les mêmes refus que ``baseline --resign`` :
signature existante vérifiée, diff affiché, confiance explicite si le
document n'était pas signé.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sentinel.integrity import (
    SIGNED_POLICY_CONFLICT,
    SIGNED_POLICY_ENV_WINS,
    UNSIGNED_BASELINE_REFUSED,
    UNVERIFIED_BASELINE_REFUSED,
    UNVERIFIED_REQUIRED_REFUSED,
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
from sentinel.platform import is_link
from sentinel.quarantine import quarantine_paths, read_manifest, restore_paths
from sentinel.reporting import render_json, render_sarif
from sentinel.scanner import scan_folder


@dataclass
class BaselineView:
    present: bool
    signed: bool
    status: str
    verified: bool
    resigned_from_unsigned: bool
    message: str
    notice: str | None


@dataclass
class ResignPreview:
    diff_text: str
    signed: bool
    status: str
    message: str


def describe_baseline(path: Path | None, key: str | None) -> BaselineView:
    if path is None or not path.is_file():
        return BaselineView(False, False, "absent", False, False, "Aucune baseline.", None)
    try:
        loaded = _read_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return BaselineView(True, False, "illisible", False, False, str(exc), None)
    status, message = baseline_signature_status(loaded, key)
    notice = unsigned_resign_notice(loaded) if status == "ok" else None
    return BaselineView(
        present=True,
        signed=baseline_is_signed(loaded),
        status=status,
        verified=status == "ok",
        resigned_from_unsigned=loaded.get("resigned_from_unsigned") is True,
        message=message,
        notice=notice,
    )


def load_baseline_for_scan(
    path: Path | None,
    key: str | None,
    *,
    require_signed: bool,
    allow_unverified: bool,
) -> tuple[dict | None, str | None, str | None]:
    """Retourne ``(baseline, erreur, avertissement)``.

    Même règles que le CLI. ``--require-signed`` et
    ``--allow-unverified-baseline`` ensemble : erreur, rien n'est chargé.
    ``SENTINEL_REQUIRE_SIGNED`` active le refus même si la case n'est
    pas cochée, et ignore « accepter sans clé ». Une baseline non
    signée acceptée (politique historique) renvoie l'avertissement du
    CLI dans le troisième champ.
    """
    if require_signed and allow_unverified:
        return None, SIGNED_POLICY_CONFLICT, None
    env_on = env_requires_signed()
    require = require_signed or env_on
    notice = SIGNED_POLICY_ENV_WINS if env_on and allow_unverified else None
    allow = allow_unverified and not require
    if path is None:
        return None, None, notice
    if not path.is_file():
        return None, f"Baseline introuvable : {path}", notice
    try:
        loaded = _read_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return None, f"Baseline illisible ({exc}).", notice
    status, message = baseline_signature_status(loaded, key)
    if status == "mismatch":
        return None, message or "Signature invalide.", notice
    if status == "unsigned_refused":
        return None, message or "Baseline non signée refusée.", notice
    if status == "unsigned" and require:
        return None, UNSIGNED_BASELINE_REFUSED, notice
    if status == "unverified" and (require or not allow):
        refused = UNVERIFIED_REQUIRED_REFUSED if require else UNVERIFIED_BASELINE_REFUSED
        return None, message or refused, notice
    if status == "unsigned" and key is not None and verify_baseline_key(loaded, key) is False:
        return None, "Clé incorrecte pour cette baseline.", notice
    warning = message if status == "unsigned" and message else None
    if notice and warning:
        warning = notice + "\n" + warning
    elif notice:
        warning = notice
    return loaded, None, warning


def create_baseline(
    folder: Path,
    out: Path,
    key: str | None,
    *,
    cancel=None,
) -> dict:
    document = make_baseline(folder, encrypt_key=key, cancel=cancel)
    if key is not None:
        sign_baseline(document, key)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    return document


def preview_resign(path: Path, key: str) -> ResignPreview:
    loaded = _read_json(path)
    root = _root_of(loaded)
    _reject_bad_signature(loaded, key)
    current = make_baseline(root)
    diff = diff_against_baseline(current, loaded)
    status, message = baseline_signature_status(loaded, key)
    return ResignPreview(
        diff_text=format_resign_diff(diff, root),
        signed=baseline_is_signed(loaded),
        status=status,
        message=message,
    )


def commit_resign(
    path: Path,
    key: str,
    *,
    trust_unsigned: bool,
    backup: bool,
) -> Path | None:
    """Signe en place. Lève ``ValueError`` si la confirmation manque ou la clé ne va pas."""
    loaded = _read_json(path)
    _root_of(loaded)
    _reject_bad_signature(loaded, key)
    unsigned = not baseline_is_signed(loaded)
    if unsigned and not trust_unsigned:
        raise ValueError(
            "Baseline non signée : la confiance initiale (--trust-unsigned) est requise. "
            "Le fichier n'a pas été modifié."
        )
    if unsigned:
        note_unsigned_resign(loaded)
    sign_baseline(loaded, key)
    try:
        return write_baseline_atomic(path, loaded, backup=backup)
    except OSError as exc:
        raise ValueError(
            f"Écriture impossible ({exc}). Le fichier d'origine est inchangé."
        ) from exc


def run_scan(folder: Path, **kwargs):
    return scan_folder(folder, **kwargs)


def quarantine(paths: list[Path], dest: Path, manifest: Path, *, force: bool = False):
    return quarantine_paths(paths, dest, manifest, force=force)


def restore(manifest: Path, dest: Path, *, force: bool = False, only: set[str] | None = None):
    return restore_paths(manifest, dest, force=force, only=only)


def manifest_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return read_manifest(path)


def export_report(report, path: Path, kind: str) -> None:
    if kind == "sarif":
        text = render_sarif(report)
    elif kind == "json":
        text = render_json(report)
    else:
        raise ValueError(f"format inconnu : {kind}")
    path.write_text(text, encoding="utf-8")


def _read_json(path: Path) -> dict:
    if is_link(path):
        path = path.resolve()
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("JSON inattendu")
    return loaded


def _root_of(loaded: dict) -> Path:
    root_raw = loaded.get("root")
    if not isinstance(root_raw, str) or not root_raw:
        raise ValueError("Baseline sans champ root.")
    root = Path(root_raw)
    if not root.is_dir():
        raise ValueError(f"Racine introuvable ou pas un dossier : {root}")
    return root


def _reject_bad_signature(loaded: dict, key: str) -> None:
    if baseline_is_signed(loaded):
        status, message = baseline_signature_status(loaded, key)
        if status != "ok":
            raise ValueError(message or "Resignature refusée : signature invalide.")
        return
    if verify_baseline_key(loaded, key) is False:
        raise ValueError("Clé incorrecte pour cette baseline (key_check).")


__all__ = [
    "BaselineView",
    "ResignPreview",
]
