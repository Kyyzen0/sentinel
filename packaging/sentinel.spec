# -*- mode: python ; coding: utf-8 -*-
"""Gel PyInstaller de l'interface.

Lancer depuis la racine du dépôt : ``pyinstaller packaging/sentinel.spec``.
Les chemins sont ancrés sur ce fichier (``SPECPATH``), pas sur le cwd :
un script ``sentinel/gui/__main__.py`` relatif au spec n'existe pas.
Sur macOS le résultat est ``dist/Sentinel.app``. Ailleurs, un dossier
``dist/sentinel/`` avec l'exécutable.
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

spec_dir = Path(SPECPATH).resolve()
repo = spec_dir.parent
hidden = collect_submodules("sentinel")

a = Analysis(
    [str(spec_dir / "launcher.py")],
    pathex=[str(repo)],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="sentinel",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Sentinel.app",
        icon=None,
        bundle_identifier="dev.sentinel.desktop",
    )
