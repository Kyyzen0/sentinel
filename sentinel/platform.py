"""Équivalents multi-plateformes des contrôles qui, sur POSIX, sont des
modes Unix, des symlinks et des chemins ``/``.

Le cœur reste 100 % bibliothèque standard. Sur Windows, les ACL et les
points de reparse passent par ``ctypes`` (``sentinel._winapi``), jamais
par un paquet tiers. Un contrôle qui ne peut pas s'exécuter échoue
fermé : message explicite, jamais un succès silencieux.

Choix documentés :

- Comparaison de chemins **insensible à la casse** sur Windows et macOS
  (APFS/HFS+ par défaut, NTFS). Linux reste sensible à la casse.
- uid/gid numériques : significatifs sur Linux et macOS. Sur Windows ils
  valent toujours 0 ; on les stocke ``None`` et on compare le SID
  propriétaire (``owner``) à la place.
- Capabilities Linux (``getcap``) : non disponibles ailleurs. Le champ
  reste ``None``. Ce n'est pas un « aucune capability » : le contrôle
  n'a pas été fait.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path

# Bits d'un ACE qui ne donnent pas accès au contenu. READ_CONTROL lit
# le descripteur, SYNCHRONIZE est un droit d'attente.
BENIGN_ACE_MASK = 0x00020000 | 0x00100000

# Lecture ou modification du contenu (fichier ou dossier).
CONTENT_ACE_MASK = (
    0x0001
    | 0x0002
    | 0x0004
    | 0x0008
    | 0x0010
    | 0x0020
    | 0x0040
    | 0x0080
    | 0x0100
    | 0x00010000
    | 0x00040000
    | 0x00080000
    | 0x02000000
    | 0x10000000
    | 0x20000000
    | 0x40000000
    | 0x80000000
)

# Équivalent root : le propriétaire POSIX n'empêche pas root de lire un
# fichier 0600. On tolère ces SID, pas Everyone / Users.
WINDOWS_PRIVILEGED_SIDS = frozenset(
    {
        "S-1-5-18",  # NT AUTHORITY\SYSTEM
        "S-1-5-32-544",  # BUILTIN\Administrators
    }
)

_REPARSE_ATTRIBUTE = 0x400


class OperationCancelled(Exception):
    """L'appelant (interface) a demandé l'arrêt. Le CLI ne l'envoie pas."""


def paths_are_casefold() -> bool:
    """Vrai là où le système de fichiers par défaut ignore la casse."""
    return os.name == "nt" or sys.platform == "darwin"


class UnsafeNtPath(OSError):
    """Chemin Windows qui ne se ramène pas à un lecteur ou un UNC sûr.

    ``\\\\?\\C:\\...`` et ``\\\\?\\UNC\\...`` se canonisent. ``\\\\.\\``,
    ``\\\\?\\GLOBALROOT``, ``\\\\?\\Volume{GUID}``, le préfixe NT ``\\??\\``,
    un chemin relatif à un lecteur (``C:Users\\...``) et tout flux autre
    que ``::$DATA`` / ``:$INDEX_ALLOCATION`` ne se comparent pas de façon
    sûre : on refuse.
    """


class UncHostError(UnsafeNtPath):
    """Hôte UNC inutilisable : la résolution a échoué ou dépassé le délai.

    On ne classe pas « autorisé » un partage dont on ne sait pas s'il
    désigne cette machine. Le message est celui montré à l'utilisateur.
    """


def unsafe_nt_message(exc: BaseException) -> str:
    """Texte montré à la place d'une traceback :class:`UnsafeNtPath`."""
    return f"Chemin Windows refusé ({exc})."


def _separator(os_name: str) -> str:
    return "\\" if os_name == "nt" else "/"


def strip_extended_prefix(path: str) -> str:
    """Retire ``\\\\?\\`` / ``//?/`` d'un chemin Windows.

    ``\\\\?\\X:\\...`` devient ``X:\\...``. ``\\\\?\\UNC\\srv\\share``
    devient ``\\\\srv\\share``. Les barres obliques et la casse du
    préfixe sont acceptées. Un préfixe périphérique ou inconnu lève
    :class:`UnsafeNtPath`.
    """
    text = path.replace("/", "\\")
    if len(text) < 4 or text[:2] != "\\\\" or text[3] != "\\":
        return text
    marker = text[2]
    if marker == ".":
        raise UnsafeNtPath(f"chemin périphérique refusé : {path}")
    if marker != "?":
        return text
    rest = text[4:]
    if rest[:4].upper() == "UNC\\":
        body = rest[4:]
        if not body or body.startswith("\\"):
            raise UnsafeNtPath(f"UNC étendu incomplet : {path}")
        return "\\\\" + body
    if len(rest) >= 2 and rest[0].isalpha() and rest[1] == ":":
        return rest
    raise UnsafeNtPath(f"préfixe NT non canonisable : {path}")


_STATIC_LOCAL_HOSTS = frozenset({"localhost", ".", "?", "0.0.0.0", "::", "::1"})
_ADS_DATA = "::$data"
_ADS_INDEX = ":$index_allocation"
_IPV6_LITERAL_SUFFIX = ".ipv6-literal.net"

# ``socket.getaddrinfo`` n'a pas de délai. Au-delà, l'hôte UNC est refusé.
UNC_DNS_TIMEOUT = 2.0
# Au plus quatre résolutions à la fois. Au-delà, l'hôte est refusé.
UNC_RESOLVER_WORKERS = 4
# Un succès reste valable 5 minutes, un échec 60 secondes.
UNC_DNS_SUCCESS_TTL = 300.0
UNC_DNS_FAILURE_TTL = 60.0

_dns_lock = threading.Lock()
# kind, adresses, expiration, budget (secondes) qui a produit l'entrée.
_DnsStored = tuple[str, tuple[str, ...], float, float]
_dns_cache: dict[str, _DnsStored] = {}
_fqdn_cache: str | None = None
# Échéance d'un FQDN vide, en erreur ou expiré. ``None`` : pas d'échec.
_fqdn_failure_until: float | None = None
_own_ips: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None
# Échéance d'un échec de liste locale. ``None`` : pas d'échec en cours.
_own_failure_until: float | None = None
_resolver_slots = threading.BoundedSemaphore(UNC_RESOLVER_WORKERS)
_IPV4_THIS_NET = ipaddress.IPv4Network("0.0.0.0/8")
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_PREFIX = ipaddress.IPv6Network("64:ff9b:1::/48")
_IPV4_TRANSLATED = ipaddress.IPv6Network("::ffff:0:0:0/96")
_6TO4_PREFIX = ipaddress.IPv6Network("2002::/16")


class _Inflight:
    """Une résolution en cours, partagée par tous les appelants du même hôte."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.stored: _DnsStored | None = None


_inflight: dict[str, _Inflight] = {}


class _OwnFlight:
    """Un seul calcul des adresses de la machine à la fois."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.outcome: (
            frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] | UncHostError | None
        ) = None


_own_flight: _OwnFlight | None = None

# Au-delà, la liste d'adaptateurs est refusée plutôt que tronquée.
_ADAPTER_WALK_LIMIT = 4096


def _unc_now() -> float:
    """Horloge du cache DNS. Les tests la remplacent."""
    return time.monotonic()


def _clear_unc_dns_cache() -> None:
    """Oublie les résolutions d'hôtes UNC. Les tests s'en servent."""
    global _fqdn_cache, _fqdn_failure_until, _own_ips, _own_failure_until, _own_flight
    with _dns_lock:
        _dns_cache.clear()
        _fqdn_cache = None
        _fqdn_failure_until = None
        _own_ips = None
        _own_failure_until = None
        if _own_flight is not None and _own_flight.done.is_set():
            _own_flight = None


def _remaining(deadline: float | None) -> float:
    """Secondes encore disponibles. ``None`` : le délai plein d'un appelant."""
    if deadline is None:
        return UNC_DNS_TIMEOUT
    left = deadline - time.monotonic()
    if left < 0:
        return 0.0
    return left


def _budget_was_short(left: float) -> bool:
    """Vrai si ``left`` n'est plus le délai plein : un pas précédent l'a entamé."""
    return left + 0.1 < UNC_DNS_TIMEOUT


def _run_bounded(func: Callable[[], object], timeout: float) -> tuple[str, object]:
    """Exécute ``func`` sur un des ``UNC_RESOLVER_WORKERS`` fils daemon.

    ``ok`` porte le retour. ``timeout``, ``busy`` et ``error`` sont des
    échecs : l'appelant refuse le chemin. ``busy`` veut dire qu'aucun
    travailleur n'était libre avant le délai. L'attente du créneau et
    l'exécution partagent le même délai : les deux ensemble ne dépassent
    pas ``timeout``. Le fil qui dépasse ce délai continue en
    arrière-plan et garde son créneau jusqu'à la fin.
    """
    if timeout < 0:
        timeout = 0.0
    deadline = time.monotonic() + timeout
    if not _resolver_slots.acquire(timeout=timeout):
        return "busy", None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _resolver_slots.release()
        return "timeout", None
    box: list[tuple[str, object]] = []
    finished = threading.Event()

    def target() -> None:
        try:
            box.append(("ok", func()))
        except OSError as exc:
            box.append(("error", exc))
        finally:
            finished.set()
            _resolver_slots.release()

    thread = threading.Thread(target=target, name="sentinel-unc-dns", daemon=True)
    thread.start()
    if not finished.wait(remaining):
        return "timeout", None
    if not box:
        return "error", None
    return box[0]


def _bare_host_names() -> frozenset[str]:
    """Nom court et ``COMPUTERNAME``. Pas de DNS."""
    names: set[str] = set()
    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    if host:
        names.add(host.casefold().rstrip("."))
    computer = os.environ.get("COMPUTERNAME")
    if computer:
        names.add(computer.casefold().rstrip("."))
    return frozenset(names)


def _machine_fqdn(deadline: float | None = None) -> str:
    """FQDN de la machine. Succès gardé ; échec 60 s ; saturation non mémorisée.

    Un délai d'appelant déjà épuisé ne grave pas un échec : le DNS n'a
    pas eu son budget. ``deadline`` est une heure ``time.monotonic``.
    """
    global _fqdn_cache, _fqdn_failure_until
    with _dns_lock:
        now = _unc_now()
        if _fqdn_failure_until is not None and _fqdn_failure_until <= now:
            _fqdn_failure_until = None
        if _fqdn_cache:
            return _fqdn_cache
        if _fqdn_failure_until is not None:
            return ""
    left = _remaining(deadline)
    if left <= 0:
        return ""
    status, value = _run_bounded(socket.getfqdn, left)
    if status == "busy" or (status == "timeout" and _budget_was_short(left)):
        return ""
    fqdn = ""
    if status == "ok" and isinstance(value, str):
        fqdn = value.strip().casefold().rstrip(".")
    with _dns_lock:
        if _fqdn_cache:
            return _fqdn_cache
        if fqdn:
            _fqdn_cache = fqdn
            _fqdn_failure_until = None
            return _fqdn_cache
        if _fqdn_failure_until is None:
            _fqdn_failure_until = _unc_now() + UNC_DNS_FAILURE_TTL
        return ""


def _machine_dns_domain(deadline: float | None = None) -> str:
    """Suffixe DNS de cette machine (``exemple.com``), ou une chaîne vide."""
    try:
        host = socket.gethostname().casefold().rstrip(".")
    except OSError:
        host = ""
    fqdn = _machine_fqdn(deadline)
    if host and fqdn.startswith(host + "."):
        return fqdn[len(host) + 1 :]
    return ""


def _local_host_names() -> frozenset[str]:
    """Hôtes UNC qui désignent cette machine, sans résoudre un tiers.

    ``localhost``, ``.`` et ``?`` sont toujours locaux. ``COMPUTERNAME``
    est relu à chaque appel : un test peut le poser.
    """
    names = set(_STATIC_LOCAL_HOSTS)
    names.update(_bare_host_names())
    fqdn = _machine_fqdn()
    if fqdn:
        names.add(fqdn)
    return frozenset(names)


def _normalize_unc_host(host: str) -> str:
    """Crochets, point final, casse, et suffixe ``ipv6-literal.net``."""
    token = host.strip()
    if len(token) >= 2 and token[0] == "[" and token[-1] == "]":
        token = token[1:-1].strip()
    token = token.rstrip(".").casefold()
    if token.endswith(_IPV6_LITERAL_SUFFIX):
        token = _decode_ipv6_literal(token[: -len(_IPV6_LITERAL_SUFFIX)])
    return token


def _decode_ipv6_literal(body: str) -> str:
    """``0--1`` devient ``0::1``, ``fe80--1s4`` devient ``fe80::1%4``."""
    scope = ""
    if "s" in body:
        body, zone = body.split("s", 1)
        scope = "%" + zone
    return body.replace("-", ":") + scope


def _parse_ipv4_part(part: str, limit: int) -> int | None:
    """Un champ ``inet_aton`` : décimal, ``0`` octal, ``0x`` hexadécimal.

    ``int(texte, 0)`` ne lit plus l'octal hérité (``0177``) : on le fait
    ici, pour le même résultat sur chaque OS.
    """
    if not part or any(char in "+-_" for char in part):
        return None
    try:
        if part.startswith("0x"):
            if len(part) == 2:
                return None
            value = int(part, 16)
        elif len(part) > 1 and part[0] == "0":
            if any(char not in "01234567" for char in part):
                return None
            value = int(part, 8)
        else:
            if any(char not in "0123456789" for char in part):
                return None
            value = int(part, 10)
    except ValueError:
        return None
    if value < 0 or value > limit:
        return None
    return value


def _parse_legacy_ipv4(text: str) -> ipaddress.IPv4Address | None:
    """Sémantique de ``inet_aton`` : octal, hex, forme courte, entier 32 bits.

    Pur Python, identique sur chaque OS. ``None`` si ce n'est pas une
    IPv4 héritée.
    """
    parts = text.split(".")
    if not parts or len(parts) > 4:
        return None
    limits = {
        1: (0xFFFFFFFF,),
        2: (0xFF, 0xFFFFFF),
        3: (0xFF, 0xFF, 0xFFFF),
        4: (0xFF, 0xFF, 0xFF, 0xFF),
    }[len(parts)]
    values: list[int] = []
    for part, limit in zip(parts, limits):
        value = _parse_ipv4_part(part, limit)
        if value is None:
            return None
        values.append(value)
    if len(values) == 1:
        packed = values[0]
    elif len(values) == 2:
        packed = (values[0] << 24) | values[1]
    elif len(values) == 3:
        packed = (values[0] << 24) | (values[1] << 16) | values[2]
    else:
        packed = (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
    return ipaddress.IPv4Address(packed)


def _parse_ip_literal(token: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    legacy = _parse_legacy_ipv4(token)
    if legacy is not None:
        return legacy
    return _parse_numeric_ip(token)


def _parse_numeric_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    token = text.strip()
    if len(token) >= 2 and token[0] == "[" and token[-1] == "]":
        token = token[1:-1]
    if "%" in token:
        token = token.split("%", 1)[0]
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def _parse_if_inet6(text: str) -> set[ipaddress.IPv6Address]:
    """Adresses de ``/proc/net/if_inet6`` (32 chiffres hexadécimaux)."""
    found: set[ipaddress.IPv6Address] = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts or len(parts[0]) != 32:
            continue
        try:
            found.add(ipaddress.IPv6Address(int(parts[0], 16)))
        except ValueError:
            continue
    return found


def _parse_fib_trie_local(text: str) -> set[ipaddress.IPv4Address]:
    """Adresses ``host LOCAL`` de la section ``Local:`` de ``/proc/net/fib_trie``."""
    found: set[ipaddress.IPv4Address] = set()
    in_local = False
    pending: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "Local:":
            in_local = True
            pending = None
            continue
        if stripped == "Main:":
            in_local = False
            pending = None
            continue
        if not in_local:
            continue
        if "|--" in line:
            pending = line.split("|--", 1)[1].strip().split()[0]
            continue
        if pending is not None and "host LOCAL" in stripped:
            try:
                found.add(ipaddress.IPv4Address(pending))
            except ValueError:
                pass
            pending = None
    return found


class _IpAdapterAddresses(ctypes.Structure):
    """Début de ``IP_ADAPTER_ADDRESSES`` : assez pour suivre la liste.

    ``Length`` + ``IfIndex`` occupent les 8 octets de l'union
    ``Alignment``. Les pointeurs qui suivent sont ceux du binaire
    Windows, 32 ou 64 bits selon le processus.
    """


_IpAdapterAddresses._fields_ = [
    ("Length", ctypes.c_uint32),
    ("IfIndex", ctypes.c_uint32),
    ("Next", ctypes.c_void_p),
    ("AdapterName", ctypes.c_void_p),
    ("FirstUnicastAddress", ctypes.c_void_p),
]


class _IpAdapterUnicastAddress(ctypes.Structure):
    """Début de ``IP_ADAPTER_UNICAST_ADDRESS`` jusqu'à ``SOCKET_ADDRESS``."""

    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Next", ctypes.c_void_p),
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int32),
    ]


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_char * 8),
    ]


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_ubyte * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


_AF_INET = 2
_AF_INET6 = 23


def _ip_from_sockaddr(
    address: int, length: int
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Lit une ``sockaddr`` Windows (``AF_INET`` / ``AF_INET6``)."""
    if address <= 0 or length < 2:
        return None
    family = ctypes.c_ushort.from_address(address).value
    if family == _AF_INET and length >= 8:
        raw = ctypes.string_at(address + 4, 4)
        return ipaddress.IPv4Address(raw)
    if family == _AF_INET6 and length >= 24:
        raw = ctypes.string_at(address + 8, 16)
        return ipaddress.IPv6Address(raw)
    return None


def _parse_adapter_unicast(head: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Adresses unicast d'une liste ``IP_ADAPTER_ADDRESSES``.

    ``head`` est l'adresse du premier adaptateur. Les tests passent un
    tampon fabriqué avec les mêmes structures.
    """
    found: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    seen_adapters: set[int] = set()
    current = head
    for _ in range(_ADAPTER_WALK_LIMIT):
        if current <= 0 or current in seen_adapters:
            break
        seen_adapters.add(current)
        adapter = ctypes.cast(current, ctypes.POINTER(_IpAdapterAddresses)).contents
        uni_addr = int(adapter.FirstUnicastAddress or 0)
        seen_uni: set[int] = set()
        for _ in range(_ADAPTER_WALK_LIMIT):
            if uni_addr <= 0 or uni_addr in seen_uni:
                break
            seen_uni.add(uni_addr)
            uni = ctypes.cast(uni_addr, ctypes.POINTER(_IpAdapterUnicastAddress)).contents
            parsed = _ip_from_sockaddr(int(uni.lpSockaddr or 0), int(uni.iSockaddrLength))
            if parsed is not None:
                found.add(parsed)
            uni_addr = int(uni.Next or 0)
        else:
            raise OSError("liste d'adresses unicast trop longue")
        current = int(adapter.Next or 0)
    else:
        raise OSError("liste d'adaptateurs trop longue")
    return found


def _query_adapter_addresses() -> ctypes.Array[ctypes.c_char] | None:
    """Tampon rempli par ``GetAdaptersAddresses``. ``None`` s'il n'y a pas d'adaptateur.

    Lève :class:`OSError` si l'appel échoue. Réservé à Windows.
    """
    windll = getattr(ctypes, "WinDLL")  # noqa: B009
    iphlpapi = windll("iphlpapi", use_last_error=True)
    get = iphlpapi.GetAdaptersAddresses
    get.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    get.restype = ctypes.c_ulong
    flags = 0x0002 | 0x0004 | 0x0008  # skip anycast, multicast, dns
    size = ctypes.c_ulong(16 * 1024)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        ret = int(get(0, flags, None, buf, ctypes.byref(size)))
        if ret == 0:
            return buf
        if ret == 232:  # ERROR_NO_DATA
            return None
        if ret != 111:  # ERROR_BUFFER_OVERFLOW
            raise OSError(ret, "GetAdaptersAddresses")
    raise OSError("GetAdaptersAddresses")


def _windows_adapter_ips() -> tuple[set[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
    """Adresses des adaptateurs Windows. ``failed`` si l'appel échoue.

    Hors Windows, la liste est vide et ce n'est pas un échec : ``/proc``
    ou le nom d'hôte couvrent les autres systèmes.
    """
    if os.name != "nt":
        return set(), False
    try:
        buf = _query_adapter_addresses()
    except (OSError, AttributeError):
        return set(), True
    if buf is None:
        return set(), False
    try:
        return _parse_adapter_unicast(ctypes.addressof(buf)), False
    except (OSError, AttributeError, ValueError, OverflowError):
        return set(), True


def _interface_ips() -> tuple[set[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
    """Adresses vues dans ``/proc`` et, sur Windows, via ``GetAdaptersAddresses``.

    ``failed`` est vrai si un fichier présent n'a pas pu être lu, ou si
    l'appel Windows échoue : la liste serait incomplète, l'appelant refuse.
    """
    found: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    failed = False
    sources = (
        ("/proc/net/if_inet6", _parse_if_inet6),
        ("/proc/net/fib_trie", _parse_fib_trie_local),
    )
    for path, parser in sources:
        # ``open`` sur une chaîne : ``Path`` suivrait ``os.name`` et, sous
        # Python 3.10, un nom ``nt`` refuserait ``/proc`` (WindowsPath).
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except FileNotFoundError:
            continue
        except OSError:
            failed = True
            continue
        found.update(parser(text))
    win_found, win_failed = _windows_adapter_ips()
    if win_failed:
        failed = True
    found.update(win_found)
    return found, failed


def _local_addresses_message(until: float) -> str:
    """Cause montrée quand la liste des adresses de la machine manque."""
    remaining = until - _unc_now()
    seconds = 0 if remaining <= 0 else int(remaining + 0.999999)
    return f"adresses locales indisponibles, nouvel essai dans {seconds} s"


def _remember_own_failure() -> UncHostError:
    """Mémorise l'échec 60 s et renvoie le message à montrer."""
    global _own_failure_until
    until = _unc_now() + UNC_DNS_FAILURE_TTL
    with _dns_lock:
        if _own_ips is not None:
            return UncHostError(_local_addresses_message(until))
        _own_failure_until = until
    return UncHostError(_local_addresses_message(until))


def _budget_seconds(seconds: float) -> float:
    """Délai affiché. Un reste négatif est un délai déjà épuisé."""
    if seconds < 0:
        return 0.0
    return seconds


def _time_waited(caller_budget: float, deadline: float | None, slice_len: float) -> float:
    """Secondes réellement passées à attendre, pas seulement la dernière tranche.

    Un follower qui réessaie a déjà consommé une partie de son délai : le
    message doit montrer le total (souvent 2,0 s), pas le reste (1,6 s).
    Si l'horloge du délai est figée, la tranche qui vient d'expirer est
    le temps d'attente.
    """
    used = caller_budget - _remaining(deadline)
    if used < 0:
        used = 0.0
    if used + 0.05 < slice_len:
        if caller_budget <= slice_len + 1e-9:
            return slice_len
        return caller_budget
    return used


def _own_budget_message(budget: float) -> str:
    """Délai d'appelant épuisé avant d'avoir une liste locale. Pas de cache."""
    return f"résolution des adresses locales expirée ({_budget_seconds(budget):.1f} s)"


def _collect_own_ips(
    deadline: float | None,
) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Calcule les adresses locales. Le délai DNS est celui de l'appelant."""
    global _own_ips
    found: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    try:
        iface, iface_failed = _interface_ips()
    except OSError:
        iface = set()
        iface_failed = True
    found.update(iface)
    try:
        hostname = socket.gethostname().strip().rstrip(".")
    except OSError:
        hostname = ""
        iface_failed = True
    host_ok = False
    status = ""
    left = 0.0
    if hostname:
        left = _remaining(deadline)
        if left <= 0:
            status = "budget"
        else:
            status, value = _run_bounded(
                lambda: _addresses_from_getaddrinfo(hostname),
                left,
            )
            if status == "timeout" and _budget_was_short(left):
                status = "budget"
            elif status == "ok" and isinstance(value, tuple):
                host_ok = True
                for item in value:
                    parsed = _parse_numeric_ip(str(item))
                    if parsed is not None:
                        found.add(parsed)
    # Saturation, ou délai déjà consommé : on ne grave pas 60 s.
    if status == "busy" and not iface_failed and not found:
        raise UncHostError("résolution des adresses locales impossible (résolveur saturé)")
    if status == "budget" and not iface_failed and not found:
        raise UncHostError(_own_budget_message(left))
    failed = iface_failed or (not found and not host_ok)
    if failed:
        with _dns_lock:
            if _own_ips is not None:
                return _own_ips
        raise _remember_own_failure()
    frozen = frozenset(found)
    with _dns_lock:
        now = _unc_now()
        if _own_failure_until is not None and _own_failure_until > now:
            raise UncHostError(_local_addresses_message(_own_failure_until))
        if _own_ips is None:
            _own_ips = frozen
        return _own_ips


def _machine_ips(
    deadline: float | None = None,
) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Adresses de cette machine : nom d'hôte et, si possible, toutes les interfaces.

    Une lecture d'interface ratée, ou aucune adresse du tout, est un
    échec fermé pendant ``UNC_DNS_FAILURE_TTL`` (60 s). Une saturation
    du résolveur, ou un délai d'appelant déjà épuisé, n'est pas
    mémorisée. Un seul calcul à la fois : les suivants attendent le
    temps qu'il leur reste. L'échec lève :class:`UncHostError`.
    """
    global _own_failure_until, _own_flight
    with _dns_lock:
        now = _unc_now()
        if _own_failure_until is not None and _own_failure_until <= now:
            _own_failure_until = None
        if _own_failure_until is not None:
            raise UncHostError(_local_addresses_message(_own_failure_until))
        if _own_ips is not None:
            return _own_ips
        flight = _own_flight
        if flight is None:
            left = _remaining(deadline)
            if deadline is not None and left <= 0:
                raise UncHostError(_own_budget_message(left))
            flight = _OwnFlight()
            _own_flight = flight
            leader = True
        else:
            leader = False
    if not leader:
        left = _remaining(deadline)
        if not flight.done.wait(left):
            raise UncHostError(_own_budget_message(left))
        outcome = flight.outcome
        if isinstance(outcome, frozenset):
            return outcome
        if isinstance(outcome, UncHostError):
            raise outcome
        raise UncHostError(_own_budget_message(_remaining(deadline)))
    try:
        frozen = _collect_own_ips(deadline)
    except UncHostError as exc:
        flight.outcome = exc
        raise
    else:
        flight.outcome = frozen
        return frozen
    finally:
        with _dns_lock:
            if _own_flight is flight:
                _own_flight = None
        flight.done.set()


def _ipv4_from_prefix(ip: ipaddress.IPv6Address, prefix_len: int) -> ipaddress.IPv4Address:
    """IPv4 embarquée selon RFC 6052 (l'octet ``u`` en bits 64–71 est sauté)."""
    raw = int(ip)
    value = 0
    pos = prefix_len
    copied = 0
    while copied < 32:
        if prefix_len < 96 and 64 <= pos < 72:
            pos = 72
            continue
        value = (value << 1) | ((raw >> (127 - pos)) & 1)
        copied += 1
        pos += 1
    return ipaddress.IPv4Address(value)


def _embedded_ipv4(
    ip: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """IPv4 portée par une IPv6 mappée, traduite, compatible, NAT64 ou 6to4.

    ``::ffff:a.b.c.d``, ``::ffff:0:a.b.c.d`` (traduite), ``::a.b.c.d``,
    ``64:ff9b::/96``, ``64:ff9b:1::/48`` et ``2002::/16``. ``::`` et
    ``::1`` ne sont pas des IPv4 compatibles utiles : ils sont déjà
    boucle ou non spécifiés.
    """
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    raw = int(ip)
    if ip in _IPV4_TRANSLATED:
        return ipaddress.IPv4Address(raw & 0xFFFFFFFF)
    if raw >> 32 == 0:
        tail = raw & 0xFFFFFFFF
        if tail != 0:
            return ipaddress.IPv4Address(tail)
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(raw & 0xFFFFFFFF)
    if ip in _NAT64_LOCAL_PREFIX:
        return _ipv4_from_prefix(ip, 48)
    if ip in _6TO4_PREFIX:
        return ipaddress.IPv4Address((raw >> 80) & 0xFFFFFFFF)
    return None


def _ipv4_flags_local(ip: ipaddress.IPv4Address) -> bool:
    return bool(ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip in _IPV4_THIS_NET)


def _ip_is_local(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    deadline: float | None = None,
) -> bool:
    """Boucle, lien local, ``0.0.0.0/8``, IPv4 embarquée, ou adresse de la machine.

    ``fe80::/10`` et ``169.254.0.0/16`` sont refusés sans DNS. Si les
    adresses locales n'ont pas pu être listées, :class:`UncHostError`
    porte la cause (liste indisponible, ou résolveur saturé).
    """
    if isinstance(ip, ipaddress.IPv4Address):
        if _ipv4_flags_local(ip):
            return True
    elif ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        return True
    embedded = _embedded_ipv4(ip) if isinstance(ip, ipaddress.IPv6Address) else None
    if embedded is not None and _ipv4_flags_local(embedded):
        return True
    own = _machine_ips(deadline)
    if embedded is not None and embedded in own:
        return True
    return ip in own


def _name_is_local(token: str, deadline: float | None = None) -> bool:
    """Nom d'hôte lexicalement local. Pas de résolution du nom lui-même."""
    if token in _STATIC_LOCAL_HOSTS or token in _bare_host_names():
        return True
    candidate = token
    if candidate.endswith(".local"):
        short = candidate[: -len(".local")]
        if short in _STATIC_LOCAL_HOSTS or short in _bare_host_names():
            return True
        candidate = short
    if "." not in token and "." not in candidate:
        return False
    domain = _machine_dns_domain(deadline)
    if domain and candidate.endswith("." + domain):
        short = candidate[: -(len(domain) + 1)]
        if short in _STATIC_LOCAL_HOSTS or short in _bare_host_names():
            return True
    fqdn = _machine_fqdn(deadline)
    return bool(fqdn) and (token == fqdn or candidate == fqdn)


def _addresses_from_getaddrinfo(host: str) -> tuple[str, ...]:
    infos = socket.getaddrinfo(host, None)
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        addr = str(sockaddr[0])
        if "%" in addr:
            addr = addr.split("%", 1)[0]
        if addr:
            found.append(addr)
    if not found:
        raise OSError(f"aucune adresse pour {host}")
    return tuple(found)


def _query_addrinfo(host: str) -> tuple[str, ...]:
    """Résolution d'un hôte UNC. Les tests remplacent cette fonction."""
    return _addresses_from_getaddrinfo(host)


def _cache_ttl(kind: str) -> float:
    if kind == "ok":
        return UNC_DNS_SUCCESS_TTL
    return UNC_DNS_FAILURE_TTL


def _fresh_unc(key: str) -> _DnsStored | None:
    """Entrée encore dans son délai. À appeler sous ``_dns_lock``."""
    cached = _dns_cache.get(key)
    if cached is None:
        return None
    if cached[2] <= _unc_now():
        _dns_cache.pop(key, None)
        return None
    return cached


def _unc_timeout_message(host: str, budget: float) -> str:
    """Le nombre est le budget réellement consommé, pas la constante de 2 s."""
    return f"résolution de l'hôte UNC expirée ({_budget_seconds(budget):.1f} s) : {host}"


def _unc_from_stored(host: str, stored: _DnsStored) -> tuple[str, ...]:
    kind, addresses, _expires, budget = stored
    if kind == "ok":
        return addresses
    if kind == "timeout":
        raise UncHostError(_unc_timeout_message(host, budget))
    if kind == "busy":
        raise UncHostError(f"résolution de l'hôte UNC impossible (résolveur saturé) : {host}")
    raise UncHostError(f"résolution de l'hôte UNC impossible : {host}")


def _lookup_unc_host(
    host: str,
    deadline: float | None = None,
    *,
    retried: bool = False,
    caller_budget: float | None = None,
) -> tuple[str, ...]:
    """Adresses de ``host``. Un seul vol par hôte, au plus quatre en parallèle.

    Succès gardé ``UNC_DNS_SUCCESS_TTL`` (5 min), échec ``UNC_DNS_FAILURE_TTL``
    (60 s). Le délai est celui de l'appelant (``deadline``), pas un nouveau
    budget de 2 s. Un dépassement dû seulement à ce budget déjà épuisé
    n'est pas mémorisé. Délai, erreur, ou aucun travailleur libre :
    :class:`UncHostError`.

    Un waiter qui hérite l'échec du vol en cours réessaie une fois s'il
    lui reste du temps sur son propre délai (``UNC_DNS_TIMEOUT``, 2 s).
    L'échec du meneur peut venir d'un budget déjà entamé ou d'un
    résolveur saturé : ce n'est pas forcément le résultat de ce waiter.
    """
    key = host.casefold()
    if caller_budget is None:
        caller_budget = _remaining(deadline)
    with _dns_lock:
        cached = _fresh_unc(key)
        if cached is not None:
            return _unc_from_stored(host, cached)
        flight = _inflight.get(key)
        if flight is None:
            left = _remaining(deadline)
            if left <= 0:
                raise UncHostError(
                    _unc_timeout_message(host, _time_waited(caller_budget, deadline, left))
                )
            flight = _Inflight()
            _inflight[key] = flight
            leader = True
        else:
            leader = False
    if not leader:
        left = _remaining(deadline)
        if not flight.done.wait(left):
            raise UncHostError(
                _unc_timeout_message(host, _time_waited(caller_budget, deadline, left))
            )
        inherited = flight.stored
        inherited_failure = inherited is None or inherited[0] != "ok"
        if inherited_failure and not retried and _remaining(deadline) > 0:
            return _lookup_unc_host(host, deadline, retried=True, caller_budget=caller_budget)
        if inherited is None:
            raise UncHostError(f"résolution de l'hôte UNC impossible : {host}")
        return _unc_from_stored(host, inherited)
    try:
        left = _remaining(deadline)
        status = "timeout"
        value: object = None
        cache = True
        if left <= 0:
            cache = False
        else:
            status, value = _run_bounded(lambda: _query_addrinfo(host), left)
        if status == "ok" and isinstance(value, tuple) and value:
            stored: _DnsStored = (
                "ok",
                tuple(str(item) for item in value),
                _unc_now() + _cache_ttl("ok"),
                UNC_DNS_TIMEOUT,
            )
            with _dns_lock:
                _dns_cache[key] = stored
        elif status == "busy" or (status == "timeout" and (left <= 0 or _budget_was_short(left))):
            # Pas de cache : créneau bientôt libre, ou budget déjà mangé.
            cache = False
            kind = "busy" if status == "busy" else "timeout"
            budget = _time_waited(caller_budget, deadline, left) if kind == "timeout" else left
            stored = (kind, (), _unc_now(), budget)
        else:
            kind = "timeout" if status == "timeout" else "error"
            budget = (
                _time_waited(caller_budget, deadline, left)
                if kind == "timeout"
                else UNC_DNS_TIMEOUT
            )
            stored = (kind, (), _unc_now() + _cache_ttl(kind), budget)
            if cache:
                with _dns_lock:
                    _dns_cache[key] = stored
        flight.stored = stored
        return _unc_from_stored(host, stored)
    finally:
        with _dns_lock:
            _inflight.pop(key, None)
        flight.done.set()


def _unc_host_refused(host: str) -> bool:
    """Vrai si ``host`` est cette machine. Lève :class:`UncHostError` sinon si le DNS échoue.

    Le contrôle lexical (boucle, nom, forme héritée, ``ipv6-literal.net``)
    passe avant toute résolution : ces hôtes ne touchent pas le DNS.
    FQDN, adresses de la machine et résolution de l'hôte partagent un
    seul délai ``UNC_DNS_TIMEOUT``.
    """
    deadline = time.monotonic() + UNC_DNS_TIMEOUT
    token = _normalize_unc_host(host)
    if not token or token in _STATIC_LOCAL_HOSTS:
        return True
    parsed = _parse_ip_literal(token)
    if parsed is not None:
        return _ip_is_local(parsed, deadline)
    if _name_is_local(token, deadline):
        return True
    for addr in _lookup_unc_host(token, deadline):
        numeric = _parse_numeric_ip(addr)
        if numeric is None or _ip_is_local(numeric, deadline):
            return True
    return False


def _unc_refused(text: str) -> bool:
    """UNC local, ou partage d'admin (nom terminé par ``$``), sur n'importe quel hôte.

    ``\\\\localhost\\C$\\Users\\…\\.ssh`` et ``\\\\fileserver\\C$\\…`` ne
    sont pas des chemins qu'on sait comparer à ``C:\\`` sans se tromper.
    Un UNC incomplet est refusé aussi. Un nom qu'on ne peut pas résoudre
    lève :class:`UncHostError` (délai ou échec) : échec fermé.
    """
    if not text.startswith("\\\\") or text.startswith("\\\\?\\") or text.startswith("\\\\.\\"):
        return False
    parts = text[2:].split("\\")
    host = parts[0] if parts else ""
    share = parts[1] if len(parts) > 1 else ""
    if not host or not share:
        return True
    if share.casefold().endswith("$"):
        return True
    return _unc_host_refused(host)


def _clean_component(part: str, *, allow_colon: bool = False) -> str:
    """Retire points/espaces finaux et les flux par défaut. Refuse le reste.

    ``.`` et ``..`` sont conservés. Un composant réduit à rien (``...``,
    espaces) disparaît. ``fichier::$DATA`` et ``dossier:$INDEX_ALLOCATION``
    redeviennent le fichier. Tout autre ``:`` est un flux qu'on ne sait
    pas classer.
    """
    cleaned = part
    while True:
        if cleaned in (".", ".."):
            return cleaned
        folded = cleaned.casefold()
        if folded.endswith(_ADS_DATA):
            cleaned = cleaned[: -len(_ADS_DATA)]
            continue
        if folded.endswith(_ADS_INDEX):
            cleaned = cleaned[: -len(_ADS_INDEX)]
            continue
        stripped = cleaned.rstrip(" .")
        if stripped == cleaned:
            break
        cleaned = stripped
    if cleaned in (".", ".."):
        return cleaned
    if not cleaned:
        return ""
    if ":" in cleaned and not allow_colon:
        raise UnsafeNtPath(f"flux NT refusé : {part}")
    return cleaned


def canonicalize_nt_text(path: str) -> str:
    """Réduit un chemin Windows à un lecteur ou un UNC, sans toucher au disque.

    ``\\\\?\\X:\\`` et ``\\\\?\\UNC\\`` sont retirés (barres ``/`` et casse
    du préfixe acceptées). Les points et espaces finaux de chaque
    composant aussi, ainsi que ``::$DATA`` et ``:$INDEX_ALLOCATION``.
    ``\\??\\``, ``\\\\.\\``, un chemin ``C:relatif`` et tout autre flux
    lèvent :class:`UnsafeNtPath`.
    """
    text = path.replace("/", "\\")
    if text[:4].casefold() == "\\??\\" or text[:5].casefold() == "\\\\??\\":
        raise UnsafeNtPath(f"préfixe NT refusé : {path}")
    stripped = strip_extended_prefix(text)
    if stripped != text:
        stripped = strip_extended_prefix(stripped)
    text = stripped
    drive_relative = (
        len(text) >= 2
        and text[0].isalpha()
        and text[1] == ":"
        and (len(text) == 2 or text[2] != "\\")
    )
    if drive_relative:
        raise UnsafeNtPath(f"chemin relatif à un lecteur refusé : {path}")
    if text.startswith("\\\\"):
        parts = text[2:].split("\\")
        # L'hôte peut être une IPv6 (``::1``, ``[::ffff:127.0.0.1]``).
        # Les deux-points d'un autre composant restent un flux refusé.
        cleaned = [
            _clean_component(part, allow_colon=(index == 0)) for index, part in enumerate(parts)
        ]
        return "\\\\" + "\\".join(cleaned)
    parts = text.split("\\")
    if parts and len(parts[0]) == 2 and parts[0][0].isalpha() and parts[0][1] == ":":
        cleaned = [parts[0]] + [_clean_component(part) for part in parts[1:]]
        return "\\".join(cleaned)
    return "\\".join(_clean_component(part) for part in parts)


def _collapse_parts(parts: list[str], *, keep: int) -> list[str]:
    """Retire ``.`` et applique ``..`` sans remonter au-dessus de ``keep`` ancres.

    ``keep`` conserve le serveur et le partage UNC, ou la lettre de
    lecteur. ``/tmp/../etc`` devient ``/etc`` ; ``/tmpfoo`` ne change pas.
    """
    out: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if len(out) > keep:
                out.pop()
            continue
        out.append(part)
    return out


def normalize_path_text(path: str, *, os_name: str, fold: bool) -> str:
    """Normalise un chemin déjà absolu pour une comparaison de préfixe.

    Ne touche pas au disque : les tests Windows/macOS tournent aussi
    sur Linux en passant ``os_name`` explicitement. ``..`` et ``.`` sont
    réduits lexicalement. Les liens et jonctions sont résolus avant
    l'appel (``Path.resolve``), pas ici.
    """
    if os_name == "nt":
        text = canonicalize_nt_text(path)
        if text.startswith("\\\\"):
            raw = list(text[2:].split("\\"))
            parts = _collapse_parts(raw, keep=2)
            text = "\\\\" + "\\".join(parts) if parts else "\\\\"
        else:
            raw = list(text.split("\\"))
            drive = ""
            if raw and len(raw[0]) == 2 and raw[0][1] == ":":
                drive = raw[0]
                raw = raw[1:]
            parts = _collapse_parts(raw, keep=0)
            if drive:
                text = drive + "\\" + "\\".join(parts) if parts else drive + "\\"
            elif text.startswith("\\"):
                text = "\\" + "\\".join(parts) if parts else "\\"
            else:
                text = "\\".join(parts)
    else:
        parts = _collapse_parts(path.replace("\\", "/").split("/"), keep=0)
        text = "/" + "/".join(parts)
    if fold:
        text = text.casefold()
    return text


def path_is_within(child: str, parent: str, *, os_name: str, fold: bool) -> bool:
    """Vrai si ``child`` est ``parent`` ou un descendant.

    Le préfixe est coupé sur un séparateur : ``/tmp/foo`` n'est pas sous
    ``/tmp/fo``, et ``/tmpfoo`` n'est pas sous ``/tmp``. ``..`` est
    réduit avant la comparaison.
    """
    sep = _separator(os_name)
    c = normalize_path_text(child, os_name=os_name, fold=fold)
    p = normalize_path_text(parent, os_name=os_name, fold=fold)
    if not p:
        return False
    if c == p:
        return True
    base = p if p.endswith(sep) else p + sep
    return c.startswith(base)


def is_volume_root_text(path: str, *, os_name: str, fold: bool) -> bool:
    """Racine de volume : ``/``, ``C:\\``, ou la racine UNC ``\\\\server\\share``."""
    text = normalize_path_text(path, os_name=os_name, fold=fold)
    if os_name == "nt":
        if len(text) == 3 and text[1] == ":" and text[2] == "\\":
            return True
        if text.startswith("\\\\"):
            parts = [part for part in text.split("\\") if part]
            return len(parts) <= 2
        return False
    return text == "/"


def classify_dest_text(
    dest: str,
    *,
    os_name: str,
    platform: str,
    home: str | None,
    extras: Mapping[str, str] | None = None,
    temp: str | None = None,
) -> str:
    """``hard`` (refus définitif), ``soft`` (``--force``) ou ``allow``.

    ``dest``, ``home`` et ``extras`` sont des chemins absolus. La casse
    est ignorée sur Windows et macOS uniquement. Un hôte UNC qu'on ne
    peut pas résoudre lève :class:`UncHostError`.
    """
    fold = os_name == "nt" or platform == "darwin"
    env = dict(extras or {})
    if os_name == "nt":
        try:
            dest = canonicalize_nt_text(dest)
            if home:
                home = canonicalize_nt_text(home)
            if temp:
                temp = canonicalize_nt_text(temp)
            env = {key: canonicalize_nt_text(value) for key, value in env.items()}
        except UnsafeNtPath:
            return "hard"
        # Partages d'admin et UNC de cette machine : on ne les ramène pas
        # à une lettre de lecteur (échec fermé, source comme destination).
        if _unc_refused(dest):
            return "hard"
    if is_volume_root_text(dest, os_name=os_name, fold=fold):
        return "hard"

    def within(child: str, parent: str | None) -> bool:
        if not parent:
            return False
        return path_is_within(child, parent, os_name=os_name, fold=fold)

    home_text = home or ""
    if (
        home_text
        and within(dest, home_text)
        and normalize_path_text(dest, os_name=os_name, fold=fold)
        == normalize_path_text(home_text, os_name=os_name, fold=fold)
    ):
        return "hard"

    hard_rel = [".ssh", ".gnupg"]
    if platform == "darwin":
        hard_rel.append("Library/Keychains")
    if home_text:
        for rel in hard_rel:
            if within(dest, _join(home_text, rel, os_name=os_name)):
                return "hard"

    soft_rels = [".config"]
    if platform == "darwin":
        soft_rels.append("Library")
    if home_text:
        for rel in soft_rels:
            if within(dest, _join(home_text, rel, os_name=os_name)):
                return "soft"

    # L'exemption du dossier temporaire ne s'applique que si, après
    # résolution, ce dossier est *dans* un emplacement temporaire connu
    # (/tmp, /var/tmp, /private/var/folders, %LOCALAPPDATA%\Temp, …).
    # TMPDIR=~/.config ou TMPDIR=/etc ne retire aucune protection.
    # La racine elle-même (/tmp, et le dossier temporaire du processus)
    # n'est jamais exemptée : on ne quarantine pas tout /tmp.
    # Les chemins durs et ~/.config ont déjà été décidés, sans exemption.
    roots = platform_temp_roots(os_name=os_name, platform=platform, extras=env)
    for root in roots:
        if within(dest, root) and _same_path(dest, root, os_name=os_name, fold=fold):
            return "soft"
    # TMPDIR peut viser un dossier ordinaire, ou un sous-dossier de
    # /tmp. Ce dossier-là, quel qu'il soit, ne se quarantine pas en
    # entier sans --force. Seul son contenu reste autorisé.
    # Chaque ancêtre non plus, jusqu'à la racine temporaire qui le
    # contient : quarantainer ``/tmp/x`` emporterait ``/tmp/x/sub``.
    # Hors racine connue, tous les ancêtres sont souples (``work``
    # contient ``work/sub``). Au-dessus de la racine connue, on ne
    # marque rien de plus.
    temp_in_known = False
    if temp:
        for root in roots:
            if within(temp, root):
                temp_in_known = True
                break
    if temp and (_same_path(dest, temp, os_name=os_name, fold=fold) or within(temp, dest)):
        if not temp_in_known:
            return "soft"
        for root in roots:
            if within(temp, root) and within(dest, root):
                return "soft"

    trusted: str | None = None
    if temp_in_known:
        trusted = temp

    def exempt(prefix: str | None) -> bool:
        if not trusted or not prefix or not within(dest, trusted):
            return False
        if _same_path(dest, trusted, os_name=os_name, fold=fold):
            return False
        return within(trusted, prefix)

    if os_name == "nt":
        for key in (
            "APPDATA",
            "LOCALAPPDATA",
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
        ):
            prefix = env.get(key)
            if not within(dest, prefix) or exempt(prefix):
                continue
            return "soft"
        return "allow"

    soft_system = [
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/usr",
        "/etc",
        "/boot",
        "/opt",
        "/var",
        "/sys",
        "/proc",
        "/dev",
        "/run",
        "/srv",
        "/System",
        "/Volumes",
    ]
    if platform == "darwin":
        soft_system.extend(("/Library", "/Applications", "/private/etc", "/private/var"))
    for raw in soft_system:
        if not within(dest, raw) or exempt(raw):
            continue
        # Un préfixe qui contient $HOME (HOME sous /var, ou le volume
        # de données macOS) ne marque pas l'arbre du compte. Seul le
        # préfixe lui-même reste sensible.
        same = normalize_path_text(dest, os_name=os_name, fold=fold) == normalize_path_text(
            raw, os_name=os_name, fold=fold
        )
        if home_text and within(home_text, raw) and not same:
            continue
        return "soft"
    return "allow"


def _same_path(left: str, right: str, *, os_name: str, fold: bool) -> bool:
    return normalize_path_text(left, os_name=os_name, fold=fold) == normalize_path_text(
        right, os_name=os_name, fold=fold
    )


def platform_temp_roots(
    *,
    os_name: str,
    platform: str,
    extras: Mapping[str, str] | None = None,
) -> list[str]:
    """Emplacements temporaires du système, pas la valeur de ``TMPDIR``.

    Seul un dossier temporaire qui, une fois résolu, est à l'intérieur
    de l'une de ces racines peut bénéficier de l'exemption. La racine
    elle-même n'est pas une destination autorisée.
    """
    env = extras or {}
    if os_name == "nt":
        roots: list[str] = []
        local = env.get("LOCALAPPDATA")
        if local:
            roots.append(_join(local, "Temp", os_name="nt"))
        system = env.get("SystemRoot") or env.get("SYSTEMROOT") or env.get("WINDIR")
        if system:
            roots.append(_join(system, "Temp", os_name="nt"))
        return roots
    roots = ["/tmp", "/var/tmp"]
    if platform == "darwin":
        roots.extend(
            (
                "/private/tmp",
                "/private/var/tmp",
                "/private/var/folders",
                "/var/folders",
            )
        )
    return roots


def _join(parent: str, rel: str, *, os_name: str) -> str:
    sep = _separator(os_name)
    rel_text = rel.replace("/", sep).replace("\\", sep)
    if parent.endswith(sep):
        return parent + rel_text
    return parent + sep + rel_text


def path_exists_strict(path: Path) -> bool:
    """Vrai si l'entrée existe.

    ``FileNotFoundError`` veut dire absente. ``PermissionError`` et les
    autres erreurs ne sont pas une absence : on les relance pour refuser
    (``Path.exists`` avale tout et répondrait ``False``).
    """
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OSError(f"accès refusé : {path}") from exc
    return True


def resolved_key(path: Path) -> str:
    """Clé de comparaison : préfixe NT, realpath, puis nom long Windows.

    Sur Windows la comparaison textuelle laisserait passer un nom court
    8.3 (``C:\\Users\\RUNNER~1\\.ssh``) ou un préfixe ``\\\\?\\``.
    ``\\\\?\\X:\\`` et ``\\\\?\\UNC\\`` sont ramenés à un chemin
    ordinaire. ``\\\\.\\`` et les autres objets NT lèvent
    :class:`UnsafeNtPath`. ``GetLongPathNameW`` est appliqué au plus
    long ancêtre qui existe, puis les composants absents sont recollés.
    Un échec lève ``OSError`` : l'appelant refuse.
    """
    text = os.fspath(path)
    try:
        if os.name == "nt":
            text = canonicalize_nt_text(text)
        resolved = Path(text).expanduser().resolve()
    except UnsafeNtPath:
        raise
    except OSError as exc:
        raise OSError(f"chemin non résolu : {path}") from exc
    if os.name != "nt":
        return str(resolved)
    try:
        return canonicalize_nt_text(_windows_long_path(resolved))
    except UnsafeNtPath:
        raise
    except OSError as exc:
        raise OSError(f"chemin non résolu : {path}") from exc


def _windows_long_path(path: Path) -> str:
    from ._winapi import long_path_name

    current = path
    pending: list[str] = []
    while True:
        if path_exists_strict(current):
            long_root = long_path_name(str(current))
            if not long_root:
                raise OSError(f"nom long vide : {current}")
            for part in reversed(pending):
                long_root = _join(long_root, part, os_name="nt")
            return long_root
        parent = current.parent
        if parent == current:
            raise OSError(f"nom long introuvable : {path}")
        pending.append(current.name)
        current = parent


def resolved_process_temp() -> str | None:
    """Dossier temporaire du processus, après realpath et nom long.

    ``TMPDIR``, ``TEMP`` puis ``TMP`` sont lus à chaque appel : le cache
    de ``tempfile.gettempdir`` ignorerait un changement, et un attaquant
    peut faire pointer ces variables n'importe où. Un chemin absent ou
    qui n'est pas un dossier est ignoré, comme ``tempfile``. Les liens,
    jonctions et ``..`` sont résolus avant le retour. Si le nom long
    Windows échoue, l'exception sort : aucune exemption n'est accordée
    à la place.
    """
    for key in ("TMPDIR", "TEMP", "TMP"):
        raw = os.environ.get(key)
        if not raw:
            continue
        text = resolved_key(Path(raw))
        try:
            if Path(text).is_dir():
                return text
        except OSError:
            return None
    try:
        fallback = resolved_key(Path(tempfile.gettempdir()))
    except OSError:
        return None
    try:
        if Path(fallback).is_dir():
            return fallback
    except OSError:
        return None
    return None


def _windows_extras() -> dict[str, str]:
    extras: dict[str, str] = {}
    if os.name != "nt":
        return extras
    for key in (
        "APPDATA",
        "LOCALAPPDATA",
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "USERPROFILE",
    ):
        raw = os.environ.get(key) or os.environ.get(key.upper())
        if not raw:
            continue
        extras[key] = resolved_key(Path(raw))
    return extras


def live_dest_class(dest: Path) -> str:
    """Politique de quarantaine pour le système qui exécute le processus.

    Un échec de résolution (realpath ou nom long) est ``hard`` : on ne
    classe pas « autorisé » un chemin qu'on n'a pas pu normaliser.
    Sur Windows, l'hôte UNC est classé avant tout accès disque : une
    boucle lexicale ne touche pas le DNS, et un délai de résolution
    lève :class:`UncHostError` au lieu d'attendre le réseau.
    """
    if os.name == "nt":
        try:
            lexical = canonicalize_nt_text(os.fspath(dest))
        except UnsafeNtPath:
            return "hard"
        if _unc_refused(lexical):
            return "hard"
    try:
        dest_text = resolved_key(dest)
        home_text = _live_home_text()
        extras = _windows_extras()
        if extras.get("USERPROFILE"):
            home_text = extras["USERPROFILE"]
        temp_text = resolved_process_temp()
        return classify_dest_text(
            dest_text,
            os_name=os.name,
            platform=sys.platform,
            home=home_text,
            extras=extras,
            temp=temp_text,
        )
    except UncHostError:
        raise
    except OSError:
        return "hard"


def _live_home_text() -> str | None:
    if os.name == "nt":
        raw = os.environ.get("USERPROFILE") or os.environ.get("HOME")
        if raw:
            return resolved_key(Path(raw))
    return resolved_key(Path(os.path.expanduser("~")))


def source_class(path: Path) -> str:
    """Classe d'un chemin *source* à déplacer.

    Même listes que la destination. Un dossier qui contient une zone
    dure (``~/.ssh``, ``~/.gnupg``, Keychains, ou le dossier du compte)
    est dur même s'il n'est pas lui-même dans la liste : quarantainer
    ``/home`` emporterait les clés.
    """
    kind = live_dest_class(path)
    if kind == "hard":
        return "hard"
    if _contains_hard_zone(path):
        return "hard"
    return kind


def _contains_hard_zone(path: Path) -> bool:
    if is_link(path):
        return False
    try:
        if not path.is_dir():
            return False
        root = resolved_key(path)
        home = _live_home_text()
    except OSError:
        return True
    if not home:
        return False
    fold = paths_are_casefold()
    zones = [
        _join(home, ".ssh", os_name=os.name),
        _join(home, ".gnupg", os_name=os.name),
        home,
    ]
    if sys.platform == "darwin":
        zones.append(_join(home, "Library/Keychains", os_name=os.name))
    for zone in zones:
        if path_is_within(zone, root, os_name=os.name, fold=fold) and not _same_path(
            zone, root, os_name=os.name, fold=fold
        ):
            return True
    return False


def shared_destination(path: Path) -> bool:
    """Vrai si ``path`` existe et est sticky ou modifiable par tous.

    ``/tmp`` est 1777. Le resserrer en 1755 casse le bit sticky pour
    tout le système. Windows n'a pas ce mode : on ne refuse pas sur
    l'attribut synthétique ``S_IWOTH``.
    """
    if os.name == "nt" or not path.exists():
        return False
    try:
        mode = path.stat().st_mode
    except OSError:
        return True
    return bool(mode & (stat.S_IWOTH | stat.S_ISVTX))


def stdin_is_terminal(stream=None) -> bool:
    """Vrai si ``stream`` est une console interactive.

    Sur Windows, ``isatty()`` répond parfois vrai pour le périphérique
    ``NUL`` (``subprocess.DEVNULL``). ``GetConsoleMode`` échoue alors :
    on refuse, comme pour un pipe. Un faux positif signerait une
    baseline sans confirmation.
    """
    target = sys.stdin if stream is None else stream
    try:
        if target is None or target.closed or not target.isatty():
            return False
        fileno = target.fileno()
    except (AttributeError, ValueError, OSError):
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt

        get_handle = getattr(msvcrt, "get_osfhandle")  # noqa: B009
        handle = get_handle(fileno)
        mode = ctypes.c_uint()
        kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)  # noqa: B009
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)))
    except (AttributeError, OSError, ValueError, ImportError):
        return False


def is_link(path: Path) -> bool:
    """Symlink POSIX, symlink Windows, jonction ou autre point de reparse.

    ``Path.is_symlink`` suffit pour un lien Unix. Sur Windows une jonction
    (``IO_REPARSE_TAG_MOUNT_POINT``) et les fichiers nuage sont des points
    de reparse : ``is_symlink`` ne les voit pas tous, et ``os.walk`` les
    suivrait. On les traite comme des liens : on ne traverse pas.
    """
    try:
        if path.is_symlink():
            return True
    except OSError:
        return False
    if os.name != "nt":
        return False
    try:
        st = os.lstat(path)
    except OSError:
        return False
    attrs = int(getattr(st, "st_file_attributes", 0) or 0)
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", _REPARSE_ATTRIBUTE))
    if attrs & flag:
        return True
    tag = int(getattr(st, "st_reparse_tag", 0) or 0)
    return tag != 0


def read_link(path: Path) -> str:
    """Cible d'un lien ou d'une jonction. Lève ``OSError`` si illisible.

    Ne suit pas la cible. Un échec n'est pas converti en « pas un lien » :
    l'appelant doit refuser l'opération.
    """
    try:
        return os.readlink(path)
    except OSError:
        if os.name != "nt":
            raise
    from ._winapi import read_reparse_target

    target = read_reparse_target(path)
    if not target:
        raise OSError(f"point de reparse sans cible lisible : {path}")
    return target


def file_owner(path: Path) -> str | None:
    """SID propriétaire sur Windows, ``None`` ailleurs (uid/gid suffisent)."""
    if os.name != "nt":
        return None
    from ._winapi import file_owner_sid

    return file_owner_sid(path)


def windows_key_acl_problem(path: Path) -> str | None:
    """``None`` si l'ACL de la clé est limitée à l'utilisateur et aux comptes privilégiés.

    Échoue fermé si l'API refuse de répondre ou si un ACE n'est pas compris.
    """
    if os.name != "nt":
        return None
    from ._winapi import current_user_sid, read_dacl

    try:
        user = current_user_sid()
        aces, null_dacl = read_dacl(path)
    except OSError as exc:
        return (
            f"Refus : impossible de lire l'ACL de {path} ({exc}). "
            "La clé n'est pas acceptée tant que le contrôle n'a pas abouti."
        )
    return describe_key_acl(aces, user_sid=user, null_dacl=null_dacl)


def describe_key_acl(
    aces: list[tuple[int, int, str]],
    *,
    user_sid: str,
    null_dacl: bool,
) -> str | None:
    """Décision pure, testée aussi sur Linux.

    ``aces`` : ``(type, masque, sid)``. Type 0 = allow, 1 = deny.
    Un DACL NULL (tout le monde) est refusé. Un ACE allow d'un type
    inconnu est refusé. Un SID hors utilisateur / SYSTEM / Administrators
    qui obtient autre chose que READ_CONTROL+SYNCHRONIZE est refusé.
    """
    if null_dacl:
        return (
            "Refus : ACL absente (DACL NULL) — le fichier est lisible par "
            "tout le monde. Restreignez-le au compte courant."
        )
    allowed = {user_sid, *WINDOWS_PRIVILEGED_SIDS}
    saw_read = False
    for ace_type, mask, sid in aces:
        if ace_type == 1:
            continue
        if ace_type != 0:
            return (
                f"Refus : ACE de type {ace_type} non interprétée sur {sid or '?'}. "
                "Par précaution la clé est refusée."
            )
        grants = bool(mask & CONTENT_ACE_MASK)
        if sid == user_sid and grants:
            saw_read = True
        if sid in WINDOWS_PRIVILEGED_SIDS and grants:
            saw_read = True
        if sid not in allowed and mask & ~BENIGN_ACE_MASK:
            return (
                f"Refus : {sid or 'SID inconnu'} peut lire ou modifier la clé "
                "(ACL trop ouverte, fichier lisible par un autre compte). "
                "Limitez-le au compte courant (équiv. chmod 600)."
            )
    if not saw_read:
        return (
            "Refus : aucun ACE de lecture pour l'utilisateur courant, SYSTEM "
            "ou Administrateurs. L'ACL n'a pas pu être validée."
        )
    return None


def restrict_key_file(path: Path) -> None:
    """Pose une ACL privée (Windows) ou chmod 0600 (POSIX)."""
    if os.name == "nt":
        from ._winapi import protect_key_file

        protect_key_file(path)
        return
    path.chmod(0o600)


def expose_key_file(path: Path) -> None:
    """Rend la clé lisible par d'autres comptes. Sert aux tests de refus."""
    if os.name == "nt":
        from ._winapi import loosen_key_file

        loosen_key_file(path)
        return
    path.chmod(0o644)


def lock_quarantine_path(path: Path, *, directory: bool) -> None:
    """0444/0555, et sur Windows une ACL sans écriture pour le compte courant.

    L'utilisateur garde WRITE_DAC pour pouvoir restaurer. Les autres
    comptes peuvent lire (comme 0444) mais pas modifier.
    """
    path.chmod(0o555 if directory else 0o444)
    if os.name != "nt":
        return
    from ._winapi import apply_readonly_dacl

    apply_readonly_dacl(path, directory=directory)


def unlock_quarantine_path(path: Path) -> None:
    """Redonne l'écriture au compte courant pour un déplacement."""
    if os.name == "nt":
        from ._winapi import grant_user_full

        grant_user_full(path)
        os.chmod(path, 0o666 if not path.is_dir() else 0o777)
        return
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IWUSR)


def apply_saved_mode(path: Path, mode: int) -> None:
    """Réapplique ``mode_before``.

    POSIX : ``chmod`` du mode stocké. Windows : le bit d'écriture du
    propriétaire pilote l'attribut lecture seule et l'ACL (les autres
    bits Unix n'existent pas).
    """
    if os.name != "nt":
        path.chmod(mode)
        return
    if mode & stat.S_IWUSR:
        unlock_quarantine_path(path)
        return
    lock_quarantine_path(path, directory=path.is_dir() and not is_link(path))


def protect_storage_dir(path: Path) -> None:
    """Le dossier de quarantaine n'est pas modifiable par les autres comptes.

    POSIX : retire l'écriture groupe/autres (le propriétaire garde la
    sienne). Windows : ACL protégée, compte courant + SYSTEM + Administrateurs.
    Un échec est une erreur, pas un dossier laissé ouvert.
    """
    if os.name == "nt":
        from ._winapi import protect_directory

        protect_directory(path)
        return
    mode = path.stat().st_mode
    tightened = mode & ~stat.S_IWGRP & ~stat.S_IWOTH
    if stat.S_IMODE(tightened) != stat.S_IMODE(mode):
        path.chmod(tightened)


def make_unreadable(path: Path) -> int:
    """Retire la lecture au compte courant. Retourne le mode POSIX précédent.

    Windows : ACE deny de lecture, WRITE_DAC conservé pour l'annuler.
    """
    previous = stat.S_IMODE(path.stat().st_mode)
    if os.name == "nt":
        from ._winapi import deny_user_read

        deny_user_read(path)
        return previous
    path.chmod(0)
    return previous


def restore_access(path: Path, previous_mode: int) -> None:
    """Annule :func:`make_unreadable`."""
    if os.name == "nt":
        from ._winapi import grant_user_full

        grant_user_full(path)
        return
    path.chmod(previous_mode)
