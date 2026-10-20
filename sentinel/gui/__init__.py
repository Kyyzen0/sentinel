"""Interface bureau optionnelle (PySide6).

Le moteur n'importe pas ce paquet. Installation : ``pip install sentinel[gui]``.
"""

from __future__ import annotations

__all__ = ["main"]


def missing_gui_message() -> str:
    return (
        "Interface indisponible : PySide6 n'est pas installé.\n"
        'Installez-la avec : pip install "sentinel[gui]"'
    )


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée paresseux : PySide6 n'est importé qu'au lancement.

    ``--version`` et ``--self-check`` ne chargent pas Qt, pour qu'un
    binaire gelé puisse répondre dans la CI sans écran.
    """
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["--version"], ["-V"]):
        from sentinel import __version__

        print(f"sentinel {__version__}")
        return 0
    if args[:1] == ["--self-check"]:
        # Importer prouve que le gel embarque le moteur. Ne pas retirer
        # les attributs du paquet : Python 3.10 ne les rattache pas, et
        # ``unittest.mock`` cherche ``sentinel.quarantine`` par getattr.
        import sentinel.integrity
        import sentinel.quarantine

        assert sentinel.integrity and sentinel.quarantine
        print("sentinel-gui ok")
        return 0
    try:
        from .app import main as _main
    except ImportError as exc:
        name = getattr(exc, "name", "") or ""
        if name == "PySide6" or name.startswith("PySide6."):
            print(missing_gui_message(), file=sys.stderr)
            return 2
        raise
    from sentinel.platform import UnsafeNtPath, unsafe_nt_message

    try:
        return _main(argv)
    except UnsafeNtPath as exc:
        print(f"❌ {unsafe_nt_message(exc)}", file=sys.stderr)
        return 2
