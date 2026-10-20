"""Construit l'application bureau avec PyInstaller, puis signe sur macOS.

Prérequis : ``pip install -e ".[gui,bundle]"`` puis, depuis la racine :

    python packaging/build.py

Produit ``dist/Sentinel.app`` sur macOS, ``dist/sentinel/sentinel`` sur
Linux et ``dist/sentinel/sentinel.exe`` sur Windows.

Sur macOS, la signature et la notarisation tiennent dans la même commande.
Guide : ``docs/signature-macos.md``.

    python packaging/build.py --check
    python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


def _sign_module() -> Any:
    """Charge ``macos_sign`` sans faire de ``packaging`` un paquet.

    Le répertoire s'appelle ``packaging/``, mais la bibliothèque PyPI du
    même nom est déjà importée par les outils. Un ``__init__.py`` ici
    casserait ces imports.
    """
    name = "_sentinel_macos_sign"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    path = Path(__file__).resolve().parent / "macos_sign.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Module introuvable : {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python packaging/build.py",
        description=(
            "Gèle Sentinel avec PyInstaller. Sur macOS, --sign et --notarize "
            "produisent une app Developer ID acceptée par Gatekeeper."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
exemples :
  python packaging/build.py
  python packaging/build.py --check
  python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize
  python packaging/build.py --sign --notarize --dmg
""",
    )
    parser.add_argument(
        "--sign",
        nargs="?",
        const="",
        default=None,
        metavar="IDENTITE",
        help=(
            "Signe dist/Sentinel.app (Hardened Runtime, de l'intérieur vers "
            "l'extérieur). Sans valeur, utilise SENTINEL_CODESIGN_IDENTITY."
        ),
    )
    parser.add_argument(
        "--notarize",
        action="store_true",
        help=(
            "Envoie l'app (ou le .dmg) à Apple, agrafe le ticket et vérifie "
            "Gatekeeper. Sur votre Mac : profil trousseau sentinel-notary, "
            "ou clé d'API. APPLE_ID ouvre une invite (pas de --password)."
        ),
    )
    parser.add_argument(
        "--keychain-profile",
        default=None,
        metavar="NOM",
        help=(
            "Profil notarytool (défaut : SENTINEL_NOTARY_PROFILE ou "
            "sentinel-notary). Ce drapeau gagne sur la clé d'API et sur APPLE_ID."
        ),
    )
    parser.add_argument(
        "--dmg",
        action="store_true",
        help="Produit aussi dist/Sentinel.dmg (signée si --sign, notarisé si --notarize).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Diagnostic : outils, certificat Developer ID, profil notaire. Ne construit rien.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def _run_pyinstaller(
    root: Path,
    pyinstaller: Callable[[list[str]], None] | None,
) -> int:
    spec = root / "packaging" / "sentinel.spec"
    args = [
        "--noconfirm",
        "--distpath",
        str(root / "dist"),
        "--workpath",
        str(root / "build"),
        str(spec),
    ]
    if pyinstaller is not None:
        pyinstaller(args)
        return 0
    try:
        from PyInstaller.__main__ import run
    except ImportError:
        print("PyInstaller manquant. pip install -e '.[gui,bundle]'", file=sys.stderr)
        return 2
    try:
        run(args)
    except SystemExit as exc:
        code = exc.code
        if code not in (0, None):
            return code if isinstance(code, int) else 1
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    runner: Callable[..., object] | None = None,
    pyinstaller: Callable[[list[str]], None] | None = None,
    root: Path | None = None,
) -> int:
    sign = _sign_module()
    try:
        return _main(
            argv,
            sign=sign,
            platform=platform if platform is not None else sys.platform,
            env=env if env is not None else sign_env(),
            runner=runner,
            pyinstaller=pyinstaller,
            root=root if root is not None else Path(__file__).resolve().parents[1],
        )
    except sign.MacSignError as exc:
        print(str(exc), file=sys.stderr)
        return int(exc.code)


def sign_env() -> Mapping[str, str]:
    return os.environ


def _main(
    argv: Sequence[str] | None,
    *,
    sign: Any,
    platform: str,
    env: Mapping[str, str],
    runner: Callable[..., object] | None,
    pyinstaller: Callable[[list[str]], None] | None,
    root: Path,
) -> int:
    args = parse_args(argv)
    module = sign
    if args.check:
        return int(
            module.run_doctor(
                platform=platform,
                env=env,
                sign_arg=args.sign,
                profile_arg=args.keychain_profile,
                run=runner if runner is not None else module.run_command,
            )
        )

    wants_macos = args.sign is not None or args.notarize or args.dmg
    if wants_macos and platform != "darwin":
        print(
            "La signature, la notarisation et l'image disque se font sur macOS.\n"
            "Sur cette machine, le gel seul suffit :\n"
            "  python packaging/build.py\n"
            "Sur le Mac :\n"
            "  python packaging/build.py --check",
            file=sys.stderr,
        )
        return 2

    identity = None
    notary = None
    if args.notarize and args.sign is None:
        print(
            "La notarisation exige --sign (certificat Developer ID Application).\n"
            'Exemple : python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize\n'
            "Ou, si SENTINEL_CODESIGN_IDENTITY est déjà exportée :\n"
            "  python packaging/build.py --sign --notarize",
            file=sys.stderr,
        )
        return 2
    if args.sign is not None:
        identity = module.resolve_identity(args.sign, env)
        entitlements = module.entitlements_path()
        if not entitlements.is_file():
            print(f"Fichier d'entitlements introuvable : {entitlements}", file=sys.stderr)
            return 1
    if args.notarize:
        notary = module.resolve_notary(args.keychain_profile, env)
        if identity and "Developer ID Application:" not in identity:
            print(
                "La notarisation exige un certificat « Developer ID Application ».\n"
                f"Identité fournie : {identity}\n"
                "Un certificat « Apple Development » ne peut pas notarier une app publique.\n"
                + module.XCODE_CERT_STEPS,
                file=sys.stderr,
            )
            return 2

    code = _run_pyinstaller(root, pyinstaller)
    if code != 0:
        return code

    if not wants_macos:
        return 0

    app = root / "dist" / module.APP_BUNDLE_NAME
    if platform == "darwin" and not app.is_dir():
        print(
            f"{app} est introuvable. Le gel PyInstaller n'a pas produit l'application.",
            file=sys.stderr,
        )
        return 1
    module.distribute(
        app=app,
        dist_dir=root / "dist",
        identity=identity,
        notarize=bool(args.notarize),
        dmg=bool(args.dmg),
        notary=notary,
        entitlements=module.entitlements_path(),
        run=runner if runner is not None else module.run_command,
        env=env,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
