"""ACL et points de reparse Windows, via ctypes uniquement.

Importé seulement quand ``os.name == "nt"``. Un échec d'API lève
``OSError`` : l'appelant refuse l'opération au lieu de continuer.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

_FILE_READ = 0x120089  # FILE_GENERIC_READ
_FILE_EXEC = 0x1200A0  # FILE_GENERIC_EXECUTE
_FILE_ALL = 0x001F01FF  # FILE_ALL_ACCESS
_READ_EXEC = _FILE_READ | _FILE_EXEC
_WRITE_DAC = 0x00040000
_READ_CONTROL = 0x00020000
_DELETE = 0x00010000
_FILE_WRITE_ATTRIBUTES = 0x0100
_SYNCHRONIZE = 0x00100000
_UNLOCK = _WRITE_DAC | _READ_CONTROL | _DELETE | _FILE_WRITE_ATTRIBUTES | _SYNCHRONIZE

_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_USERS = "S-1-5-32-545"
_AUTH = "S-1-5-11"
_EVERYONE = "S-1-1-0"
# FILE_WRITE_DATA | FILE_APPEND_DATA. Sur un dossier, les mêmes bits
# sont FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY.
_NO_CONTENT_WRITE = 0x0002 | 0x0004

_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x4
_OWNER_SECURITY_INFORMATION = 0x1
_PROTECTED_DACL = 0x80000000
_ACL_REVISION = 2

# ``WinDLL`` n'existe pas dans les stubs Linux : on le charge par nom
# pour que mypy reste propre, et ce module n'est importé que sur Windows.
_windll = getattr(ctypes, "WinDLL")  # noqa: B009
_kernel32 = _windll("kernel32", use_last_error=True)
_advapi32 = _windll("advapi32", use_last_error=True)


class _AclSize(ctypes.Structure):
    _fields_ = (
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    )


def _path_name(api: str, path: str) -> str:
    """``GetLongPathNameW`` ou ``GetShortPathNameW``. Échoue fermé."""
    function = getattr(_kernel32, api)
    function.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    function.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(1)
    size = 0
    for _ in range(2):
        size = int(function(path, buffer, len(buffer)))
        if size == 0:
            _check(0, api)
        if size <= len(buffer):
            text = buffer.value or ""
            if not text:
                raise OSError(f"{api} a renvoyé un nom vide")
            return text
        buffer = ctypes.create_unicode_buffer(size)
    raise OSError(f"{api} n'a pas renvoyé de nom (taille {size})")


def long_path_name(path: str) -> str:
    """Nom long d'un chemin qui existe. Lève ``OSError`` sinon."""
    return _path_name("GetLongPathNameW", path)


def short_path_name(path: str) -> str:
    """Nom court 8.3 d'un chemin qui existe. Lève ``OSError`` sinon."""
    return _path_name("GetShortPathNameW", path)


def _check(ok: int, what: str) -> None:
    if ok:
        return
    _last_error = getattr(ctypes, "get_last_error")  # noqa: B009
    err = int(_last_error())
    raise OSError(err, f"{what} a échoué (Win32 {err})")


def _sid(text: str) -> ctypes.c_void_p:
    out = ctypes.c_void_p()
    _advapi32.ConvertStringSidToSidW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    )
    _advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _check(_advapi32.ConvertStringSidToSidW(text, ctypes.byref(out)), "ConvertStringSidToSidW")
    return out


def _free_sid(sid: ctypes.c_void_p) -> None:
    _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.LocalFree(sid)


def _sid_string(sid: ctypes.c_void_p) -> str:
    out = ctypes.c_wchar_p()
    _advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _check(
        _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(out)),
        "ConvertSidToStringSidW",
    )
    try:
        return out.value or ""
    finally:
        _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        _kernel32.LocalFree.restype = ctypes.c_void_p
        _kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))


def current_user_sid() -> str:
    """SID du jeton du processus (``TokenUser``)."""
    token = ctypes.c_void_p()
    _kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    _advapi32.OpenProcessToken.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    )
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _check(
        _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)),
        "OpenProcessToken",
    )
    try:
        needed = wintypes.DWORD(0)
        _advapi32.GetTokenInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        _advapi32.GetTokenInformation.restype = wintypes.BOOL
        _advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value <= 0:
            raise OSError("GetTokenInformation n'a pas indiqué de taille")
        buf = ctypes.create_string_buffer(needed.value)
        _check(
            _advapi32.GetTokenInformation(token, 1, buf, needed.value, ctypes.byref(needed)),
            "GetTokenInformation",
        )
        user_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        return _sid_string(ctypes.c_void_p(user_sid))
    finally:
        _kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        _kernel32.CloseHandle.restype = wintypes.BOOL
        _kernel32.CloseHandle(token)


def _set_dacl(path: Path, entries: list[tuple[str, int, str]]) -> None:
    """Remplace le DACL. ``entries`` = ``(sid, masque, "allow"|"deny")``.

    Le DACL est protégé : l'héritage du dossier parent ne ré-ouvre pas
    le fichier derrière le contrôle.
    """
    sids: list[ctypes.c_void_p] = []
    try:
        sized: list[tuple[ctypes.c_void_p, int, str, int]] = []
        total = 8
        _advapi32.GetLengthSid.argtypes = (ctypes.c_void_p,)
        _advapi32.GetLengthSid.restype = wintypes.DWORD
        for text, mask, kind in entries:
            sid = _sid(text)
            sids.append(sid)
            length = int(_advapi32.GetLengthSid(sid))
            total += 8 + length
            sized.append((sid, mask, kind, length))
        buf = ctypes.create_string_buffer(total)
        _advapi32.InitializeAcl.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD)
        _advapi32.InitializeAcl.restype = wintypes.BOOL
        _check(_advapi32.InitializeAcl(buf, total, _ACL_REVISION), "InitializeAcl")
        _advapi32.AddAccessDeniedAce.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        )
        _advapi32.AddAccessDeniedAce.restype = wintypes.BOOL
        _advapi32.AddAccessAllowedAce.argtypes = _advapi32.AddAccessDeniedAce.argtypes
        _advapi32.AddAccessAllowedAce.restype = wintypes.BOOL
        for sid, mask, kind, _length in sized:
            if kind == "deny":
                _check(
                    _advapi32.AddAccessDeniedAce(buf, _ACL_REVISION, mask, sid),
                    "AddAccessDeniedAce",
                )
        for sid, mask, kind, _length in sized:
            if kind != "deny":
                _check(
                    _advapi32.AddAccessAllowedAce(buf, _ACL_REVISION, mask, sid),
                    "AddAccessAllowedAce",
                )
        _advapi32.SetNamedSecurityInfoW.argtypes = (
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        _advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        name = ctypes.create_unicode_buffer(str(path))
        status = _advapi32.SetNamedSecurityInfoW(
            name,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL,
            None,
            None,
            buf,
            None,
        )
        if status != 0:
            raise OSError(status, f"SetNamedSecurityInfoW a échoué (Win32 {status}) pour {path}")
    finally:
        for sid in sids:
            _free_sid(sid)


def read_dacl(path: Path) -> tuple[list[tuple[int, int, str]], bool]:
    """``(aces, null_dacl)``. ``aces`` = ``(type, masque, sid)``."""
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    _advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    status = _advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION | _OWNER_SECURITY_INFORMATION,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(sd),
    )
    if status != 0:
        raise OSError(status, f"GetNamedSecurityInfoW a échoué (Win32 {status}) pour {path}")
    try:
        if not dacl.value:
            return [], True
        info = _AclSize()
        _advapi32.GetAclInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        _advapi32.GetAclInformation.restype = wintypes.BOOL
        _check(
            _advapi32.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2),
            "GetAclInformation",
        )
        _advapi32.GetAce.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        )
        _advapi32.GetAce.restype = wintypes.BOOL
        aces: list[tuple[int, int, str]] = []
        for index in range(int(info.AceCount)):
            ace = ctypes.c_void_p()
            _check(_advapi32.GetAce(dacl, index, ctypes.byref(ace)), "GetAce")
            header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
            ace_type = int(header[0])
            words = ctypes.cast(ace, ctypes.POINTER(wintypes.DWORD))
            mask = int(words[1])
            sid_text = ""
            if ace_type in (0, 1):
                sid_ptr = ctypes.c_void_p((ace.value or 0) + 8)
                sid_text = _sid_string(sid_ptr)
            aces.append((ace_type, mask, sid_text))
        return aces, False
    finally:
        if sd.value:
            _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
            _kernel32.LocalFree.restype = ctypes.c_void_p
            _kernel32.LocalFree(sd)


def file_owner_sid(path: Path) -> str | None:
    """SID propriétaire, ou ``None`` si l'API ne répond pas.

    ``None`` n'est pas un propriétaire : la comparaison d'intégrité
    ignore le champ, et la baseline ne prétend pas avoir vérifié.
    """
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    _advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    status = _advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(sd),
    )
    if status != 0 or not owner.value:
        if sd.value:
            _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
            _kernel32.LocalFree.restype = ctypes.c_void_p
            _kernel32.LocalFree(sd)
        return None
    try:
        return _sid_string(owner)
    finally:
        _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        _kernel32.LocalFree.restype = ctypes.c_void_p
        _kernel32.LocalFree(sd)


def protect_key_file(path: Path) -> None:
    user = current_user_sid()
    _set_dacl(
        path,
        [
            (user, _FILE_ALL, "allow"),
            (_SYSTEM, _READ_EXEC, "allow"),
            (_ADMINS, _READ_EXEC, "allow"),
        ],
    )


def loosen_key_file(path: Path) -> None:
    user = current_user_sid()
    _set_dacl(
        path,
        [
            (user, _FILE_ALL, "allow"),
            (_AUTH, _READ_EXEC, "allow"),
        ],
    )


def apply_readonly_dacl(path: Path, *, directory: bool) -> None:
    """Lecture, pas d'écriture du contenu, y compris pour Administrateurs.

    Un compte du groupe Administrateurs hériterait autrement de
    ``FILE_ALL`` et pourrait modifier le fichier mis en quarantaine.
    Un ACE deny sur Everyone bloque ``FILE_WRITE_DATA`` pour tout le
    monde, SYSTEM compris. Le compte courant garde ``WRITE_DAC`` pour
    que ``restore`` puisse remplacer l'ACL.
    """
    del directory  # le masque d'écriture de contenu est le même
    user = current_user_sid()
    _set_dacl(
        path,
        [
            (_EVERYONE, _NO_CONTENT_WRITE, "deny"),
            (user, _READ_EXEC | _UNLOCK, "allow"),
            (_USERS, _READ_EXEC, "allow"),
            (_SYSTEM, _READ_EXEC, "allow"),
            (_ADMINS, _READ_EXEC, "allow"),
        ],
    )


def grant_user_full(path: Path) -> None:
    user = current_user_sid()
    _set_dacl(
        path,
        [
            (user, _FILE_ALL, "allow"),
            (_SYSTEM, _FILE_ALL, "allow"),
            (_ADMINS, _FILE_ALL, "allow"),
        ],
    )


def protect_directory(path: Path) -> None:
    grant_user_full(path)


def deny_user_read(path: Path) -> None:
    """Interdit la lecture au compte courant, garde de quoi annuler l'ACL."""
    user = current_user_sid()
    _set_dacl(
        path,
        [
            (user, _READ_EXEC, "deny"),
            (user, _UNLOCK, "allow"),
            (_SYSTEM, _FILE_ALL, "allow"),
        ],
    )


def read_reparse_target(path: Path) -> str | None:
    """Nom affiché d'un symlink ou d'une jonction (``FSCTL_GET_REPARSE_POINT``)."""
    generic_read = 0x80000000
    share_read = 0x1
    open_existing = 3
    backup = 0x02000000
    open_reparse = 0x00200000
    _kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    _kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = _kernel32.CreateFileW(
        str(path),
        generic_read,
        share_read,
        None,
        open_existing,
        backup | open_reparse,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        return None
    try:
        buf = ctypes.create_string_buffer(16 * 1024)
        returned = wintypes.DWORD(0)
        _kernel32.DeviceIoControl.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        )
        _kernel32.DeviceIoControl.restype = wintypes.BOOL
        ok = _kernel32.DeviceIoControl(
            handle,
            0x000900A8,
            None,
            0,
            buf,
            len(buf),
            ctypes.byref(returned),
            None,
        )
        if not ok or returned.value < 16:
            return None
        tag = int.from_bytes(buf.raw[0:4], "little")
        symlink = 0xA000000C
        mount = 0xA0000003
        if tag not in (symlink, mount):
            return None
        print_off = int.from_bytes(buf.raw[12:14], "little")
        print_len = int.from_bytes(buf.raw[14:16], "little")
        name_base = 20 if tag == symlink else 16
        start = name_base + print_off
        raw = buf.raw[start : start + print_len]
        if not raw and tag == symlink:
            sub_off = int.from_bytes(buf.raw[8:10], "little")
            sub_len = int.from_bytes(buf.raw[10:12], "little")
            raw = buf.raw[name_base + sub_off : name_base + sub_off + sub_len]
        text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if text.startswith("\\??\\"):
            text = text[4:]
        return text or None
    finally:
        _kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        _kernel32.CloseHandle.restype = wintypes.BOOL
        _kernel32.CloseHandle(handle)
