"""Clé HMAC tenue en mémoire pour la session.

``keyring`` est optionnel. S'il manque, ou s'il échoue, on demande la clé
à chaque session. Elle n'est jamais écrite dans QSettings ni dans un
fichier de configuration de l'interface.
"""

from __future__ import annotations


def normalize_key_text(value: str | None) -> str | None:
    """Retire un unique saut de ligne final, comme ``read_key_file``."""
    text = value or ""
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    return text or None


class SessionKey:
    def __init__(self) -> None:
        self._value: str | None = None

    @property
    def value(self) -> str | None:
        return self._value

    def set(self, value: str | None) -> None:
        # Comme le CLI : ``SENTINEL_KEY`` est pris tel quel, un fichier
        # de clé ne perd que le saut de ligne final. Pas de strip global,
        # qui changerait une clé contenant des espaces.
        self._value = normalize_key_text(value)

    def clear(self) -> None:
        self._value = None

    def load_keyring(self) -> str | None:
        """Retourne la clé du trousseau, ou None si indisponible."""
        try:
            import keyring
        except ImportError:
            return None
        try:
            found = keyring.get_password("sentinel", "hmac")
        except Exception:
            return None
        if isinstance(found, str) and found:
            self._value = found
            return found
        return None

    def store_keyring(self, value: str) -> str | None:
        """Enregistre dans le trousseau. None si ok, sinon le message d'erreur.

        N'écrit rien d'autre : pas de repli vers un fichier de réglages.
        """
        text = normalize_key_text(value)
        if not text:
            return "Clé vide."
        try:
            import keyring
        except ImportError:
            return "Le module keyring n'est pas installé. La clé reste en mémoire seulement."
        try:
            keyring.set_password("sentinel", "hmac", text)
        except Exception as exc:
            return f"Trousseau indisponible ({exc}). La clé n'a pas été enregistrée."
        self._value = text
        return None

    def keyring_available(self) -> bool:
        try:
            import keyring  # noqa: F401
        except ImportError:
            return False
        return True
