"""Nettoyage des dossiers temporaires de la suite.

Importé en premier par ``unittest discover`` (préfixe ``test_00_``).
Les ``mkdtemp`` sont retirés à la fin du processus, après avoir rendu
les dossiers de quarantaine de nouveau inscriptibles.
"""

from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from tests.osutil import install_temp_cleanup, remove_tree

install_temp_cleanup()


class TestRemoveTree(unittest.TestCase):
    def test_readonly_quarantine_tree_is_removed(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="sentinel-cleanup-"))
        locked = root / "evil_dir"
        locked.mkdir()
        payload = locked / "payload.sh"
        payload.write_text("x\n", encoding="utf-8")
        payload.chmod(0o444)
        locked.chmod(0o555)
        self.assertEqual(stat.S_IMODE(locked.stat().st_mode) & 0o222, 0)
        remove_tree(root)
        self.assertFalse(root.exists())
        self.assertFalse(locked.exists())
