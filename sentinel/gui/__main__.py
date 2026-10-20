"""``python -m sentinel.gui``.

PyInstaller n'utilise pas ce fichier : il lancerait un import relatif
sans paquet parent. Le binaire passe par ``packaging/launcher.py``.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and __package__ in (None, ""):
    from sentinel.gui import main
else:
    from . import main

if __name__ == "__main__":
    sys.exit(main())
