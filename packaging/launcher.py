"""Point d'entrée du binaire PyInstaller.

Le spec exécute ce fichier comme script. Un import relatif
(``sentinel/gui/__main__.py``) n'a alors pas de paquet parent et le
binaire ne démarre pas.
"""

from __future__ import annotations


def main() -> int:
    from sentinel.gui import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
