"""Signature Developer ID, notarisation et diagnostic pour ``Sentinel.app``.

Le gel PyInstaller (``packaging/sentinel.spec``) est un bundle **onedir** :
les dylibs, ``.so`` et frameworks restent dans ``Sentinel.app``. On les
signe de l'intérieur vers l'extérieur. ``--deep`` signe dans le mauvais
sens et Apple le déconseille ; il n'est pas utilisé.

Entitlement : voir ``packaging/entitlements.plist``. Un seul droit est
nécessaire sous Hardened Runtime, ``allow-unsigned-executable-memory``.
"""

from __future__ import annotations

import os
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.parsers.expat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_NOTARY_PROFILE = "sentinel-notary"
APP_BUNDLE_NAME = "Sentinel.app"
APP_DISPLAY_NAME = "Sentinel"
# Compte Keychain créé par ``notarytool store-credentials``.
# ``security`` ne voit que les trousseaux fichier ; le trousseau iCloud
# (défaut de notarytool) se vérifie avec ``notarytool history``.
NOTARY_KEYCHAIN_ACCOUNT_PREFIX = "com.apple.gke.notary.tool.saved-creds."

BUNDLE_SUFFIXES = {".framework", ".app", ".xpc", ".bundle", ".plugin", ".kext", ".appex"}

# Magics Mach-O (thin). Le fat 32 bits cafebabe est aussi le magic Java :
# on ne l'accepte que si nfat_arch est petit.
_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
}
_FAT_MAGIC = b"\xca\xfe\xba\xbe"
_FAT_CIGAM = b"\xbe\xba\xfe\xca"

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IDENTITY_RE = re.compile(r'^\s*\d+\)\s+[0-9A-Fa-f]+\s+"(?P<name>[^"]+)"\s*$')
# Dernier statut reconnu. « In Progress » peut précéder « Accepted » pendant
# --wait : seule la dernière occurrence compte, et elle doit être Accepted.
_STATUS_RE = re.compile(
    r"status:\s*(Accepted|In Progress|Invalid|Rejected)\b",
    re.IGNORECASE,
)
NOTARY_KEYCHAIN_ENV = "SENTINEL_NOTARY_KEYCHAIN"

CODESIGN_TIMEOUT = 180.0
ARCHIVE_TIMEOUT = 600.0
NOTARY_TIMEOUT = 3600.0
STAPLE_TIMEOUT = 180.0
SPCTL_TIMEOUT = 120.0
DOCTOR_TIMEOUT = 30.0
NOTARY_HISTORY_TIMEOUT = 90.0

XCODE_CERT_STEPS = """\
1. Ouvrez Xcode → Réglages… → Comptes (Settings → Accounts).
2. Ajoutez votre compte Apple Developer s'il n'y est pas.
3. Sélectionnez le compte → « Manage Certificates… ».
4. Cliquez sur + → « Developer ID Application ».
5. Vérifiez ensuite :
     security find-identity -v -p codesigning
   Une ligne doit commencer par « Developer ID Application: ».
   S'il n'y a que « Apple Development », la notarisation publique échouera."""

Runner = Callable[..., "CommandResult"]


class MacSignError(Exception):
    """Échec explicable, message en français. ``code`` 2 = usage, 1 = opération."""

    def __init__(self, message: str, *, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SignTarget:
    path: Path
    entitlements: bool


@dataclass(frozen=True)
class NotaryAuth:
    """Identifiants notaire. Le mot de passe n'apparaît pas dans ``repr``."""

    kind: str
    profile: str = ""
    apple_id: str = ""
    team_id: str = ""
    password: str = ""
    keychain: str = ""
    api_key: str = ""
    api_key_id: str = ""
    api_issuer: str = ""

    def __repr__(self) -> str:
        if self.kind == "profile":
            return f"NotaryAuth(kind='profile', profile={self.profile!r})"
        if self.kind == "api_key":
            return (
                "NotaryAuth(kind='api_key', "
                f"api_key={self.api_key!r}, api_key_id={self.api_key_id!r}, "
                f"api_issuer={self.api_issuer!r})"
            )
        hidden = ", password='********'" if self.password else ""
        return (
            "NotaryAuth(kind='apple_id', "
            f"apple_id={self.apple_id!r}, team_id={self.team_id!r}{hidden})"
        )

    def secrets(self) -> tuple[str, ...]:
        return (self.password,) if self.password else ()


@dataclass
class DoctorCheck:
    title: str
    ok: bool
    summary: str
    fix: str = ""


@dataclass
class DoctorReport:
    checks: list[DoctorCheck]
    commands: list[str]
    # Faux hors macOS : le diagnostic ne propose alors aucune commande.
    offer_commands: bool = True

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)


def entitlements_path() -> Path:
    return Path(__file__).resolve().parent / "entitlements.plist"


def redact(text: str, secrets: Iterable[str]) -> str:
    """Remplace les secrets par des étoiles. Ignore les chaînes vides."""
    redacted = text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        redacted = redacted.replace(secret, "********")
    return redacted


def redact_argv(args: Sequence[str], secrets: Iterable[str]) -> str:
    return " ".join(shlex.quote(redact(arg, secrets)) for arg in args)


def run_command(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    echo: bool = True,
    secrets: Sequence[str] = (),
) -> CommandResult:
    """Lance une commande sans shell. N'écrit jamais un secret sur la sortie."""
    shown = redact_argv(args, secrets)
    if echo:
        print(f"+ {shown}", flush=True)
    try:
        completed = subprocess.run(
            list(args),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise MacSignError(f"Délai dépassé ({timeout:g} s) : {shown}") from exc
    except FileNotFoundError as exc:
        raise MacSignError(
            f"Commande introuvable : {args[0]}.\n"
            "Sur un Mac, installez les outils Apple :\n"
            "  xcode-select --install"
        ) from exc
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    return CommandResult(completed.returncode, stdout, stderr)


def is_macho_bytes(blob: bytes) -> bool:
    """Vrai pour un Mach-O thin ou fat. Un ``.class`` Java (cafebabe) est rejeté."""
    if len(blob) < 4:
        return False
    head = blob[:4]
    if head in _THIN_MAGICS:
        return True
    if head not in {_FAT_MAGIC, _FAT_CIGAM} or len(blob) < 8:
        return False
    if head == _FAT_MAGIC:
        nfat = int.from_bytes(blob[4:8], "big")
    else:
        nfat = int.from_bytes(blob[4:8], "little")
    return 1 <= nfat <= 16


def _read_magic(path: Path) -> bytes:
    # Les liens sont écartés par l'appelant. On ne lit que 8 octets.
    try:
        with path.open("rb") as handle:
            return handle.read(8)
    except OSError as exc:
        raise MacSignError(f"Lecture impossible : {path} ({exc.strerror}).") from exc


def path_is_macho(path: Path) -> bool:
    return is_macho_bytes(_read_magic(path))


def bundle_executable_name(app: Path) -> str:
    plist_path = app / "Contents" / "Info.plist"
    if not plist_path.is_file() or plist_path.is_symlink():
        return "sentinel"
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (
        OSError,
        ValueError,
        plistlib.InvalidFileException,
        xml.parsers.expat.ExpatError,
    ) as exc:
        raise MacSignError(
            f"Info.plist illisible ({plist_path}) : {exc}. Le gel PyInstaller est incomplet."
        ) from exc
    exe = info.get("CFBundleExecutable", "sentinel")
    if not isinstance(exe, str) or not exe.strip():
        return "sentinel"
    name = exe.strip()
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise MacSignError(
            f"CFBundleExecutable invalide dans {plist_path} : {name!r}. "
            "Le nom ne doit pas être un chemin."
        )
    return name


def main_executable(app: Path) -> Path:
    name = bundle_executable_name(app)
    path = app / "Contents" / "MacOS" / name
    if path.is_symlink() or not path.is_file():
        raise MacSignError(
            f"Exécutable principal introuvable : {path}. "
            "Attendu après « python packaging/build.py » sur macOS : dist/Sentinel.app."
        )
    if not path_is_macho(path):
        raise MacSignError(f"L'exécutable principal n'est pas un binaire Mach-O : {path}.")
    return path


def plan_signing(app: Path) -> list[SignTarget]:
    """Cibles de l'intérieur vers l'extérieur. Le bundle est en dernier.

    Les liens symboliques sont ignorés (PyInstaller croise Frameworks et
    Resources ; signer le lien casserait le lien ou signerait deux fois).
    """
    if not app.is_dir() or app.is_symlink():
        raise MacSignError(f"Bundle introuvable : {app}")
    main = main_executable(app)
    found: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        key = str(path)
        if key in seen or path == app:
            return
        seen.add(key)
        found.append(path)

    for dirpath, dirnames, filenames in os.walk(app, followlinks=False):
        kept: list[str] = []
        for dirname in dirnames:
            candidate = Path(dirpath) / dirname
            if candidate.is_symlink():
                continue
            kept.append(dirname)
            if candidate.suffix in BUNDLE_SUFFIXES:
                add(candidate)
        dirnames[:] = kept
        for filename in filenames:
            candidate = Path(dirpath) / filename
            if candidate.is_symlink():
                continue
            if path_is_macho(candidate):
                add(candidate)

    if main not in found:
        add(main)

    found.sort(key=lambda path: (path == main, -len(path.parts), str(path)))
    # Même plist pour chaque .app (le bundle racine et tout .app imbriqué)
    # et pour l'exécutable principal de ce bundle. Une dylib n'en reçoit pas.
    entitled_exes = {main}
    for bundle in found:
        if bundle.suffix != ".app":
            continue
        exe = bundle / "Contents" / "MacOS" / bundle_executable_name(bundle)
        entitled_exes.add(exe)
    targets = [
        SignTarget(path, entitlements=path.suffix == ".app" or path in entitled_exes)
        for path in found
    ]
    targets.append(SignTarget(app, entitlements=True))
    return targets


def codesign_command(identity: str, path: Path, entitlements: Path | None) -> list[str]:
    """Signature unitaire. Pas de ``--deep`` : l'appelant parcourt l'arbre."""
    command = [
        "codesign",
        "--force",
        "--sign",
        identity,
        "--timestamp",
        "--options",
        "runtime",
        "--all-architectures",
    ]
    if entitlements is not None:
        command.extend(["--entitlements", str(entitlements)])
    command.append(str(path))
    return command


def codesign_disk_image_command(identity: str, path: Path) -> list[str]:
    # Une image disque n'est pas un exécutable : pas de Hardened Runtime.
    return ["codesign", "--force", "--sign", identity, "--timestamp", str(path)]


def verify_command(path: Path) -> list[str]:
    return ["codesign", "--verify", "--strict", "--verbose=2", str(path)]


def display_command(path: Path) -> list[str]:
    return ["codesign", "--display", "--verbose=2", str(path)]


def ditto_zip_command(app: Path, zip_path: Path) -> list[str]:
    # ``ditto -k`` conserve les liens (``zip`` sans ``-y`` les copie en dur
    # et casse la signature PyInstaller).
    return ["ditto", "-c", "-k", "--keepParent", str(app), str(zip_path)]


def hdiutil_command(app: Path, dmg_path: Path, volume_name: str = APP_DISPLAY_NAME) -> list[str]:
    return [
        "hdiutil",
        "create",
        "-volname",
        volume_name,
        "-srcfolder",
        str(app),
        "-ov",
        "-format",
        "UDZO",
        str(dmg_path),
    ]


def stapler_command(path: Path) -> list[str]:
    return ["xcrun", "stapler", "staple", str(path)]


def spctl_app_command(path: Path) -> list[str]:
    # ``-t exec`` évalue une application. ``-t install`` est réservé au .pkg.
    return ["spctl", "-a", "-vv", "-t", "exec", str(path)]


def spctl_open_command(path: Path) -> list[str]:
    # Sans ``--context context:primary-signature``, spctl refuse un .dmg
    # pourtant notarié. ``-t open`` est le type d'une image disque.
    return [
        "spctl",
        "-a",
        "-vv",
        "-t",
        "open",
        "--context",
        "context:primary-signature",
        str(path),
    ]


def _argv_leaks_secret(command: Sequence[str], secret: str) -> bool:
    if not secret:
        return False
    if secret in command:
        return True
    return len(secret) >= 8 and any(secret in arg for arg in command)


def _refuse_if_secret_in_argv(command: Sequence[str], secret: str) -> None:
    if _argv_leaks_secret(command, secret):
        raise MacSignError(
            "Refus : le mot de passe d'application serait visible dans les arguments (ps).",
            code=1,
        )


def notary_auth_args(auth: NotaryAuth) -> list[str]:
    """Arguments de submit/log. Jamais ``--password``.

    Une clé d'API passe par ``--key`` (un chemin), ``--key-id`` et
    ``--issuer``. Un mot de passe d'application a déjà été enregistré
    dans un profil : submit ne reçoit que ``--keychain-profile``.
    """
    if auth.kind == "api_key":
        if not (auth.api_key and auth.api_key_id and auth.api_issuer):
            raise MacSignError("Clé d'API App Store Connect incomplète.", code=2)
        args = [
            "--key",
            auth.api_key,
            "--key-id",
            auth.api_key_id,
            "--issuer",
            auth.api_issuer,
        ]
        _refuse_if_secret_in_argv(args, auth.password)
        return args
    if auth.kind != "profile" or not auth.profile:
        raise MacSignError(
            "La notarisation par identifiant Apple passe par un profil trousseau. "
            "store-credentials est appelé sans --password (invite du Terminal). "
            "submit ne reçoit pas le mot de passe.",
            code=2,
        )
    _refuse_if_secret_in_argv(["--keychain-profile", auth.profile, auth.keychain], auth.password)
    args = ["--keychain-profile", auth.profile]
    if auth.keychain:
        args.extend(["--keychain", auth.keychain])
    return args


def store_credentials_argv(
    profile: str,
    apple_id: str,
    team_id: str,
    keychain: str = "",
) -> list[str]:
    """``store-credentials`` sans ``--password``.

    ``NOTARYTOOL(1)`` : omettre ``--password`` ouvre une invite sécurisée
    dans le Terminal. Le préfixe ``@env:`` est une option d'``altool``,
    pas de ``notarytool``. Le mot de passe d'application n'est jamais un
    argument (il serait visible dans ``ps`` et dans l'historique).

    ``keychain`` vide : trousseau par défaut de la session. On ne crée pas
    de trousseau temporaire. ``security create-keychain -p`` puis
    ``unlock-keychain -p`` demandaient un mot de passe deux fois ; ce
    mot de passe aléatoire ne servait qu'à un CI sans Terminal. La
    signature se fait sur le Mac, pas dans CI.
    """
    args = [
        "xcrun",
        "notarytool",
        "store-credentials",
        profile,
        "--apple-id",
        apple_id,
        "--team-id",
        team_id,
    ]
    if keychain:
        args.extend(["--keychain", keychain])
    return args


def _hand_store_message(profile: str) -> str:
    return (
        "La notarisation par identifiant Apple demande le mot de passe dans "
        "le Terminal : notarytool store-credentials, sans --password. "
        "Cette session n'a pas de Terminal.\n"
        "Enregistrez le profil une fois à la main :\n"
        f"  xcrun notarytool store-credentials {profile}\n"
        f"Puis relancez avec --keychain-profile {profile}.\n"
        "La signature se fait sur votre Mac. GitHub Actions ne signe pas. "
        "Guide : docs/signature-macos.md."
    )


def _terminal_can_prompt() -> bool:
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _run_prompt(
    command: Sequence[str],
    *,
    timeout: float,
    secrets: Sequence[str],
) -> CommandResult:
    """Hérite du Terminal pour que notarytool puisse demander le mot de passe."""
    shown = redact_argv(command, secrets)
    print(f"+ {shown}", flush=True)
    print(
        "notarytool demande le mot de passe d'application dans ce Terminal. "
        "Il n'est pas un argument.",
        flush=True,
    )
    try:
        completed = subprocess.run(list(command), check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise MacSignError(f"Délai dépassé ({timeout:g} s) : {shown}") from exc
    except FileNotFoundError as exc:
        raise MacSignError(
            f"Commande introuvable : {command[0]}.\n"
            "Sur un Mac, installez les outils Apple :\n"
            "  xcode-select --install"
        ) from exc
    if completed.returncode != 0:
        raise MacSignError(
            "Échec de l'enregistrement du profil notaire.\n"
            "Relancez la commande à la main, sans --password :\n"
            f"  {shown}"
        )
    return CommandResult(completed.returncode, "", "")


def final_notary_status(text: str) -> str | None:
    """Dernier statut Accepted / In Progress / Invalid / Rejected, ou None."""
    found = _STATUS_RE.findall(text)
    if not found:
        return None
    return found[-1]


def notary_submit_command(archive: Path, auth: NotaryAuth) -> list[str]:
    return ["xcrun", "notarytool", "submit", str(archive), "--wait", *notary_auth_args(auth)]


def notary_log_command(submission_id: str, auth: NotaryAuth) -> list[str]:
    return ["xcrun", "notarytool", "log", submission_id, *notary_auth_args(auth)]


def notary_history_command(profile: str) -> list[str]:
    return ["xcrun", "notarytool", "history", "--keychain-profile", profile]


def notary_profile_keychain_command(profile: str) -> list[str]:
    # Pas de ``-g`` ni ``-w`` : ces drapeaux affichent le mot de passe.
    return [
        "security",
        "find-generic-password",
        "-a",
        f"{NOTARY_KEYCHAIN_ACCOUNT_PREFIX}{profile}",
    ]


def find_identity_command() -> list[str]:
    return ["security", "find-identity", "-v", "-p", "codesigning"]


def parse_submission_id(text: str) -> str | None:
    match = _UUID_RE.search(text)
    return match.group(0) if match else None


def parse_code_signing_identities(output: str) -> list[str]:
    names: list[str] = []
    for line in output.splitlines():
        match = _IDENTITY_RE.match(line)
        if match:
            names.append(match.group("name"))
    return names


def developer_id_applications(names: Sequence[str]) -> list[str]:
    return [name for name in names if name.startswith("Developer ID Application:")]


def signature_summary(text: str) -> list[str]:
    prefixes = ("Authority=", "Timestamp=", "TeamIdentifier=", "Identifier=")
    return [line.strip() for line in text.splitlines() if line.strip().startswith(prefixes)]


def resolve_identity(sign_arg: str | None, env: Mapping[str, str]) -> str | None:
    """``None`` si ``--sign`` est absent. L'argument prime sur l'environnement."""
    if sign_arg is None:
        return None
    identity = sign_arg.strip() or env.get("SENTINEL_CODESIGN_IDENTITY", "").strip()
    if not identity:
        raise MacSignError(
            "Aucune identité de signature.\n"
            'Passez --sign "Developer ID Application: NOM (TEAMID)" '
            "ou exportez SENTINEL_CODESIGN_IDENTITY.\n"
            "Certificats installés :\n"
            "  security find-identity -v -p codesigning",
            code=2,
        )
    return identity


def _env_group(env: Mapping[str, str], names: Sequence[str]) -> dict[str, str]:
    return {name: env.get(name, "").strip() for name in names}


def _require_complete(values: Mapping[str, str], hint: str) -> bool:
    """Vrai si tout le groupe est rempli. Erreur si une partie seulement l'est."""
    present = {name: bool(value) for name, value in values.items()}
    if any(present.values()) and not all(present.values()):
        missing = [name for name, ok in present.items() if not ok]
        raise MacSignError(
            "Identifiants de notarisation incomplets. Variables manquantes : "
            + ", ".join(missing)
            + ".\n"
            + hint,
            code=2,
        )
    return all(present.values())


def resolve_notary(profile_arg: str | None, env: Mapping[str, str]) -> NotaryAuth:
    """Profil, clé d'API, ou identifiant Apple.

    ``--keychain-profile`` explicite gagne. Sinon une clé d'API complète
    (``APPLE_API_KEY``, ``APPLE_API_KEY_ID``, ``APPLE_API_ISSUER``) gagne
    sur l'identifiant Apple. Un groupe à moitié rempli est une erreur :
    on ne bascule pas en silence vers l'autre méthode ni vers le profil.
    """
    if profile_arg is not None:
        profile = profile_arg.strip()
        if not profile:
            raise MacSignError("Le nom de profil --keychain-profile est vide.", code=2)
        return NotaryAuth(kind="profile", profile=profile)

    api = _env_group(env, ("APPLE_API_KEY", "APPLE_API_KEY_ID", "APPLE_API_ISSUER"))
    if _require_complete(
        api,
        "Renseignez le chemin du fichier .p8 (APPLE_API_KEY), APPLE_API_KEY_ID "
        "et APPLE_API_ISSUER, ou retirez ces variables.",
    ):
        return NotaryAuth(
            kind="api_key",
            api_key=api["APPLE_API_KEY"],
            api_key_id=api["APPLE_API_KEY_ID"],
            api_issuer=api["APPLE_API_ISSUER"],
        )

    # Le mot de passe d'application n'est pas lu ici. notarytool le demande
    # dans le Terminal, ou il est déjà dans le profil du trousseau.
    apple = _env_group(env, ("APPLE_ID", "APPLE_TEAM_ID"))
    if _require_complete(
        apple,
        "Renseignez APPLE_ID et APPLE_TEAM_ID, ou retirez-les et utilisez un "
        "profil trousseau (--keychain-profile, ou SENTINEL_NOTARY_PROFILE) "
        "ou une clé d'API. Le mot de passe d'application n'est pas une "
        "variable d'environnement : notarytool le demande dans le Terminal, "
        "ou il est déjà dans le profil.",
    ):
        return NotaryAuth(
            kind="apple_id",
            apple_id=apple["APPLE_ID"],
            team_id=apple["APPLE_TEAM_ID"],
        )
    profile = env.get("SENTINEL_NOTARY_PROFILE", "").strip() or DEFAULT_NOTARY_PROFILE
    return NotaryAuth(kind="profile", profile=profile)


def _failure_text(command: Sequence[str], result: CommandResult, secrets: Sequence[str]) -> str:
    shown = redact_argv(command, secrets)
    output = redact(f"{result.stdout}\n{result.stderr}".strip(), secrets)
    return f"Commande : {shown}\nSortie :\n{output or '(vide)'}"


def _keychain_hint(text: str) -> str:
    if "errSecInternalComponent" in text or "errSecInternal" in text:
        return (
            "\nmacOS n'a pas pu utiliser la clé privée (errSecInternalComponent). "
            "Ouvrez « Trousseau d'accès », déverrouillez la session, et relancez "
            "dans Terminal.app. À la demande du trousseau, choisissez « Toujours autoriser »."
        )
    return ""


def sign_bundle(
    app: Path,
    identity: str,
    entitlements: Path,
    run: Runner,
    *,
    secrets: Sequence[str] = (),
) -> None:
    if not entitlements.is_file():
        raise MacSignError(f"Fichier d'entitlements introuvable : {entitlements}")
    targets = plan_signing(app)
    total = len(targets)
    for index, target in enumerate(targets, start=1):
        print(f"Signature ({index}/{total}) : {target.path}", flush=True)
        command = codesign_command(
            identity,
            target.path,
            entitlements if target.entitlements else None,
        )
        result = run(command, timeout=CODESIGN_TIMEOUT, echo=False, secrets=secrets)
        if result.returncode != 0:
            detail = _failure_text(command, result, secrets)
            raise MacSignError(
                f"Échec de la signature de {target.path}.\n{detail}{_keychain_hint(detail)}"
            )
    print("Vérification : codesign --verify --strict", flush=True)
    for path in (app, main_executable(app)):
        command = verify_command(path)
        result = run(command, timeout=CODESIGN_TIMEOUT, echo=False, secrets=secrets)
        if result.returncode != 0:
            detail = _failure_text(command, result, secrets)
            raise MacSignError(
                f"La signature de {path} ne passe pas codesign --verify --strict.\n{detail}"
            )
    info = run(display_command(app), timeout=CODESIGN_TIMEOUT, echo=False, secrets=secrets)
    lines = signature_summary(info.stdout + "\n" + info.stderr)
    if lines:
        print("Signature enregistrée :", flush=True)
        for line in lines:
            print(f"  {redact(line, secrets)}", flush=True)
    print(f"Signature terminée : {app}", flush=True)


def _checked(
    run: Runner,
    command: Sequence[str],
    *,
    timeout: float,
    secrets: Sequence[str],
    apple_password: str,
) -> CommandResult:
    _refuse_if_secret_in_argv(command, apple_password)
    result = run(list(command), timeout=timeout, echo=False, secrets=secrets)
    if result.returncode != 0:
        raise MacSignError(
            f"Échec de la préparation notaire.\n{_failure_text(command, result, secrets)}"
        )
    return result


def _prepare_notary(
    auth: NotaryAuth,
    run: Runner,
    env: Mapping[str, str],
) -> tuple[NotaryAuth, Callable[[], None]]:
    """Prépare l'authentification de submit.

    Une clé d'API est passée par chemin (``--key``), sans ``store-credentials``.
    Un identifiant Apple appelle ``store-credentials`` sans ``--password`` :
    notarytool demande le mot de passe une fois dans le Terminal. On ne
    crée pas de trousseau temporaire et on ne passe pas ``-p`` à
    ``security`` : ces invites en double ne servaient qu'au CI, et la
    signature se fait sur le Mac.
    """
    if auth.kind == "profile":
        return auth, lambda: None
    if auth.kind == "api_key":
        key_path = Path(auth.api_key)
        if not key_path.is_file():
            raise MacSignError(
                f"Fichier de clé d'API introuvable : {key_path}. "
                "APPLE_API_KEY doit être le chemin d'un .p8 lisible par vous seul."
            )
        return auth, lambda: None
    if auth.kind != "apple_id" or not (auth.apple_id and auth.team_id):
        raise MacSignError("Identifiants Apple incomplets.", code=2)
    # Sans Terminal, on n'appelle pas notarytool : le mot de passe ne peut
    # pas être demandé, et il ne doit pas être un argument.
    if run is run_command and not _terminal_can_prompt():
        raise MacSignError(_hand_store_message(DEFAULT_NOTARY_PROFILE), code=1)

    keychain = env.get(NOTARY_KEYCHAIN_ENV, "").strip()
    command = store_credentials_argv(
        DEFAULT_NOTARY_PROFILE,
        auth.apple_id,
        auth.team_id,
        keychain,
    )
    redact_secrets = auth.secrets()
    print(
        "Enregistrement du profil notaire dans le trousseau "
        "(sans --password : notarytool le demande une fois, il n'est pas affiché)…",
        flush=True,
    )
    _refuse_if_secret_in_argv(command, auth.password)
    if run is run_command:
        _run_prompt(command, timeout=NOTARY_HISTORY_TIMEOUT, secrets=redact_secrets)
    else:
        _checked(
            run,
            command,
            timeout=NOTARY_HISTORY_TIMEOUT,
            secrets=redact_secrets,
            apple_password=auth.password,
        )

    prepared = NotaryAuth(
        kind="profile",
        profile=DEFAULT_NOTARY_PROFILE,
        keychain=keychain,
        password=auth.password,
    )
    return prepared, lambda: None


def submit_and_wait(
    archive: Path,
    auth: NotaryAuth,
    run: Runner,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """Envoie ``archive`` et attend. Seul le statut Accepted est un succès."""
    prepared, cleanup = _prepare_notary(auth, run, env or {})
    try:
        return _submit_prepared(archive, prepared, run)
    finally:
        cleanup()


def _submit_prepared(archive: Path, auth: NotaryAuth, run: Runner) -> str:
    secrets = auth.secrets()
    command = notary_submit_command(archive, auth)
    _refuse_if_secret_in_argv(command, auth.password)
    print("Envoi à Apple (notarytool --wait)…", flush=True)
    result = run(command, timeout=NOTARY_TIMEOUT, echo=False, secrets=secrets)
    combined = f"{result.stdout}\n{result.stderr}"
    submission_id = parse_submission_id(combined)
    status = final_notary_status(combined)
    accepted = result.returncode == 0 and status is not None and status.lower() == "accepted"
    if accepted:
        print(
            f"Notarisation acceptée{f' ({submission_id})' if submission_id else ''}.",
            flush=True,
        )
        return submission_id or ""

    log_text = ""
    if submission_id:
        print(f"Notarisation non acceptée, journal {submission_id}…", flush=True)
        log_command = notary_log_command(submission_id, auth)
        _refuse_if_secret_in_argv(log_command, auth.password)
        log_result = run(log_command, timeout=STAPLE_TIMEOUT, echo=False, secrets=secrets)
        log_text = redact(f"{log_result.stdout}\n{log_result.stderr}".strip(), secrets)
    detail = redact(combined.strip(), secrets)
    shown = status or "absent"
    parts = [
        f"La notarisation n'est pas acceptée (statut : {shown}).",
        f"Identifiant : {submission_id or 'inconnu'}",
        f"Sortie de notarytool :\n{detail or '(vide)'}",
    ]
    if log_text:
        parts.append(f"Journal Apple :\n{log_text}")
    else:
        parts.append("Pas d'identifiant de soumission : le journal n'a pas été récupéré.")
    parts.append("Corrigez les erreurs du journal, puis relancez la même commande.")
    raise MacSignError("\n".join(parts))


def staple(path: Path, run: Runner, *, required: bool, secrets: Sequence[str] = ()) -> bool:
    print(f"Agrafe (stapler) : {path}", flush=True)
    command = stapler_command(path)
    result = run(command, timeout=STAPLE_TIMEOUT, echo=False, secrets=secrets)
    if result.returncode == 0:
        print(f"Agrafe posée : {path}", flush=True)
        return True
    detail = _failure_text(command, result, secrets)
    message = f"Échec de l'agrafe sur {path}.\n{detail}"
    if required:
        raise MacSignError(message)
    print(message, flush=True)
    print("L'agrafe du .dmg reste celle qui compte pour la distribution.", flush=True)
    return False


def gatekeeper(path: Path, run: Runner, *, disk_image: bool, secrets: Sequence[str] = ()) -> None:
    command = spctl_open_command(path) if disk_image else spctl_app_command(path)
    print(f"Contrôle Gatekeeper : {' '.join(command[:3])}", flush=True)
    result = run(command, timeout=SPCTL_TIMEOUT, echo=False, secrets=secrets)
    output = redact(f"{result.stdout}\n{result.stderr}".strip(), secrets)
    if output:
        print(output, flush=True)
    if result.returncode != 0:
        hint = ""
        if "Unnotarized" in output:
            hint = (
                "\nGatekeeper voit une signature Developer ID sans notarisation "
                "(« Unnotarized Developer ID »). L'agrafe n'est pas prise en compte, "
                "ou la notarisation n'a pas couvert ce fichier."
            )
        raise MacSignError(
            f"Gatekeeper refuse {path} (spctl -a -vv).\n{output or '(pas de détail)'}{hint}"
        )


def create_disk_image(
    app: Path, dmg_path: Path, run: Runner, *, secrets: Sequence[str] = ()
) -> None:
    dmg_path.parent.mkdir(parents=True, exist_ok=True)
    if dmg_path.exists():
        dmg_path.unlink()
    print(f"Création de l'image disque : {dmg_path}", flush=True)
    command = hdiutil_command(app, dmg_path)
    result = run(command, timeout=ARCHIVE_TIMEOUT, echo=False, secrets=secrets)
    if result.returncode != 0 or not dmg_path.is_file():
        raise MacSignError(
            f"Échec de hdiutil pour {dmg_path}.\n{_failure_text(command, result, secrets)}"
        )


def sign_disk_image(
    dmg_path: Path, identity: str, run: Runner, *, secrets: Sequence[str] = ()
) -> None:
    print(f"Signature de l'image disque : {dmg_path}", flush=True)
    command = codesign_disk_image_command(identity, dmg_path)
    result = run(command, timeout=CODESIGN_TIMEOUT, echo=False, secrets=secrets)
    if result.returncode != 0:
        detail = _failure_text(command, result, secrets)
        raise MacSignError(
            f"Échec de la signature de {dmg_path}.\n{detail}{_keychain_hint(detail)}"
        )
    verify = ["codesign", "--verify", "--verbose=2", str(dmg_path)]
    checked = run(verify, timeout=CODESIGN_TIMEOUT, echo=False, secrets=secrets)
    if checked.returncode != 0:
        raise MacSignError(
            f"La signature de {dmg_path} ne passe pas codesign --verify.\n"
            f"{_failure_text(verify, checked, secrets)}"
        )


def zip_app(app: Path, zip_path: Path, run: Runner, *, secrets: Sequence[str] = ()) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()
    print(f"Archive (ditto) : {zip_path}", flush=True)
    command = ditto_zip_command(app, zip_path)
    result = run(command, timeout=ARCHIVE_TIMEOUT, echo=False, secrets=secrets)
    if result.returncode != 0 or not zip_path.is_file():
        raise MacSignError(
            f"Échec de ditto pour {zip_path}.\n{_failure_text(command, result, secrets)}"
        )


def distribute(
    *,
    app: Path,
    dist_dir: Path,
    identity: str | None,
    notarize: bool,
    dmg: bool,
    notary: NotaryAuth | None,
    entitlements: Path,
    run: Runner,
    env: Mapping[str, str] | None = None,
) -> None:
    """Signe, notarise, et éventuellement produit ``Sentinel.dmg``."""
    if notarize and not identity:
        raise MacSignError(
            "La notarisation exige une signature Developer ID. Relancez avec --sign.",
            code=2,
        )
    if notarize and identity and "Developer ID Application:" not in identity:
        raise MacSignError(
            "La notarisation exige un certificat « Developer ID Application ».\n"
            f"Identité fournie : {identity}\n"
            "Un certificat « Apple Development » signe en local mais Apple refuse "
            "de notarier une app distribuée hors App Store.\n" + XCODE_CERT_STEPS,
            code=2,
        )
    if notarize and notary is None:
        raise MacSignError("Authentification notaire manquante.", code=2)

    secrets = notary.secrets() if notary is not None else ()
    if identity:
        sign_bundle(app, identity, entitlements, run, secrets=secrets)

    dmg_path = dist_dir / f"{APP_DISPLAY_NAME}.dmg"
    zip_path = dist_dir / f"{APP_DISPLAY_NAME}.zip"

    if dmg:
        create_disk_image(app, dmg_path, run, secrets=secrets)
        if identity:
            sign_disk_image(dmg_path, identity, run, secrets=secrets)

    if notarize:
        assert notary is not None
        if dmg:
            submit_and_wait(dmg_path, notary, run, env=env)
            staple(dmg_path, run, required=True, secrets=secrets)
            app_stapled = staple(app, run, required=False, secrets=secrets)
            gatekeeper(dmg_path, run, disk_image=True, secrets=secrets)
            if app_stapled:
                gatekeeper(app, run, disk_image=False, secrets=secrets)
        else:
            with tempfile.TemporaryDirectory(prefix="sentinel-notary-") as tmp:
                upload = Path(tmp) / f"{APP_DISPLAY_NAME}.zip"
                zip_app(app, upload, run, secrets=secrets)
                submit_and_wait(upload, notary, run, env=env)
            staple(app, run, required=True, secrets=secrets)
            gatekeeper(app, run, disk_image=False, secrets=secrets)
            zip_app(app, zip_path, run, secrets=secrets)
            print(f"Archive à distribuer (liens conservés) : {zip_path}", flush=True)

    print("Terminé.", flush=True)
    print(f"  Application : {app}", flush=True)
    if dmg:
        print(f"  Image disque : {dmg_path}", flush=True)
    if notarize and not dmg:
        print(f"  Archive : {zip_path}", flush=True)


def store_credentials_command(profile: str) -> str:
    return f"xcrun notarytool store-credentials {profile}"


def _non_macos_report() -> DoctorReport:
    return DoctorReport(
        checks=[
            DoctorCheck(
                title="Machine",
                ok=False,
                summary=(
                    "La signature exige macOS. codesign, notarytool et stapler "
                    "n'existent que sur un Mac. Cette machine n'est pas un Mac."
                ),
            )
        ],
        commands=[],
        offer_commands=False,
    )


def _tools_check(
    xcode: CommandResult,
    tool_paths: Mapping[str, str | None],
) -> DoctorCheck:
    missing: list[str] = []
    if xcode.returncode != 0:
        detail = (xcode.stderr or xcode.stdout).strip()
        extra = f" ({detail})" if detail else ""
        missing.append(f"Xcode Command Line Tools{extra}")
    if not tool_paths.get("codesign"):
        missing.append("codesign")
    if not tool_paths.get("notarytool"):
        missing.append("notarytool")
    if not tool_paths.get("stapler"):
        missing.append("stapler")
    if missing:
        return DoctorCheck(
            title="Outils Apple",
            ok=False,
            summary="Il manque : " + ", ".join(missing) + ".",
            fix="Installez les outils (une fenêtre va s'ouvrir) :\n"
            "  xcode-select --install\n"
            "Si Xcode est déjà là mais pas sélectionné :\n"
            "  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer\n"
            "Puis vérifiez :\n"
            "  xcode-select -p\n"
            "  xcrun --find notarytool\n"
            "  xcrun --find stapler",
        )
    selected = xcode.stdout.strip() or "(chemin non affiché)"
    return DoctorCheck(
        title="Outils Apple",
        ok=True,
        summary=(
            f"Xcode Command Line Tools : {selected}\n"
            "codesign, notarytool et stapler sont disponibles."
        ),
    )


def _identity_check(found: Sequence[str], requested: str | None) -> tuple[DoctorCheck, list[str]]:
    developer_ids = developer_id_applications(found)
    others = [name for name in found if name not in developer_ids]
    if requested:
        exact = [name for name in found if name == requested]
        partial = [name for name in found if requested in name]
        chosen = exact or (partial if len(partial) == 1 else [])
        if len(exact) > 1 or (not exact and len(partial) > 1):
            listed = "\n".join(f"  - {name}" for name in (exact or partial))
            return (
                DoctorCheck(
                    title="Certificat demandé",
                    ok=False,
                    summary=f"Plusieurs certificats correspondent à {requested!r} :\n{listed}",
                    fix="Passez le nom complet, entre guillemets, tel que "
                    "« security find-identity -v -p codesigning » l'affiche.",
                ),
                [],
            )
        if chosen:
            match = chosen[0]
            if not match.startswith("Developer ID Application:"):
                return (
                    DoctorCheck(
                        title="Certificat demandé",
                        ok=False,
                        summary=(
                            f"{match} est installé, mais ce n'est pas un "
                            "« Developer ID Application ». La notarisation pour "
                            "une distribution hors App Store sera refusée."
                        ),
                        fix=XCODE_CERT_STEPS,
                    ),
                    [],
                )
            return (
                DoctorCheck(
                    title="Certificat Developer ID Application",
                    ok=True,
                    summary=f"Identité prête : {match}",
                ),
                [match],
            )
        installed = "\n".join(f"  - {name}" for name in found) or "  (aucun)"
        return (
            DoctorCheck(
                title="Certificat demandé",
                ok=False,
                summary=f"{requested!r} n'est pas dans le trousseau.\nCertificats vus :\n{installed}",
                fix=XCODE_CERT_STEPS,
            ),
            [],
        )

    if developer_ids:
        lines = "\n".join(f"  - {name}" for name in developer_ids)
        summary = f"Certificat trouvé :\n{lines}"
        if others:
            summary += "\nAutres identités (elles ne notarisent pas une app publique) :\n"
            summary += "\n".join(f"  - {name}" for name in others)
        return (
            DoctorCheck(title="Certificat Developer ID Application", ok=True, summary=summary),
            list(developer_ids),
        )
    if found:
        lines = "\n".join(f"  - {name}" for name in found)
        return (
            DoctorCheck(
                title="Certificat Developer ID Application",
                ok=False,
                summary=(
                    "Aucun certificat « Developer ID Application ». "
                    "Ceux qui sont installés ne servent qu'au développement local :\n" + lines
                ),
                fix=XCODE_CERT_STEPS,
            ),
            [],
        )
    return (
        DoctorCheck(
            title="Certificat Developer ID Application",
            ok=False,
            summary="Aucun certificat de signature dans le trousseau (0 identité utilisable).",
            fix=XCODE_CERT_STEPS,
        ),
        [],
    )


def _profile_missing(result: CommandResult) -> bool:
    text = f"{result.stdout}\n{result.stderr}".lower()
    return result.returncode != 0 and (
        result.returncode == 69
        or "no keychain password item found" in text
        or ("could not find" in text and "profile" in text)
        or "could not be found in the keychain" in text
    )


def _notary_fix(profile: str) -> str:
    return (
        "Créez d'abord un mot de passe pour l'app sur https://appleid.apple.com\n"
        "(Connexion et sécurité → Mots de passe pour les apps), puis enregistrez-le\n"
        "une seule fois. La commande n'a pas --password : notarytool le demande\n"
        "dans le Terminal. Il ne reste ni dans l'historique, ni dans ps.\n"
        f"  {store_credentials_command(profile)}\n"
        "N'écrivez pas --password, ni @env: (syntaxe d'altool, pas de notarytool) :\n"
        "cette chaîne serait enregistrée comme mot de passe.\n"
        "Tout se fait sur votre Mac. GitHub Actions ne signe pas.\n"
        "Une clé d'API, si vous en avez une, reste aussi sur ce Mac :\n"
        "docs/signature-macos.md, section « Clé d'API App Store Connect »."
    )


def _notary_check(
    *,
    profile_arg: str | None,
    env: Mapping[str, str],
    keychain_item: CommandResult | None,
    history: CommandResult | None,
) -> tuple[DoctorCheck, str]:
    try:
        auth = resolve_notary(profile_arg, env)
    except MacSignError as exc:
        return (
            DoctorCheck(title="Notarisation", ok=False, summary=str(exc), fix=""),
            DEFAULT_NOTARY_PROFILE,
        )
    if auth.kind == "api_key":
        key_path = Path(auth.api_key)
        if not key_path.is_file():
            return (
                DoctorCheck(
                    title="Clé d'API",
                    ok=False,
                    summary=f"Fichier de clé d'API introuvable : {key_path}.",
                    fix=(
                        "APPLE_API_KEY est le chemin du fichier .p8 "
                        "(AuthKey_….p8), pas son contenu."
                    ),
                ),
                DEFAULT_NOTARY_PROFILE,
            )
        return (
            DoctorCheck(
                title="Clé d'API",
                ok=True,
                summary=(
                    f"Clé d'API App Store Connect prête ({auth.api_key_id}). "
                    "notarytool recevra le chemin du .p8, pas son contenu. "
                    "Le fichier n'est pas affiché."
                ),
            ),
            DEFAULT_NOTARY_PROFILE,
        )
    if auth.kind == "apple_id":
        return (
            DoctorCheck(
                title="Notarisation",
                ok=True,
                summary=(
                    "APPLE_ID et APPLE_TEAM_ID sont définis. "
                    "Le mot de passe d'application n'est pas lu dans l'environnement. "
                    "store-credentials sera lancé sans --password : notarytool le demande "
                    "une fois dans le Terminal. Il n'est pas un argument et n'est pas "
                    "affiché. La signature se fait sur ce Mac."
                ),
            ),
            auth.profile or DEFAULT_NOTARY_PROFILE,
        )
    profile = auth.profile
    if keychain_item is not None and keychain_item.returncode == 0:
        return (
            DoctorCheck(
                title="Profil notaire",
                ok=True,
                summary=f"Le profil « {profile} » est dans un trousseau fichier.",
            ),
            profile,
        )
    if history is not None and history.returncode == 0:
        return (
            DoctorCheck(
                title="Profil notaire",
                ok=True,
                summary=(
                    f"Le profil « {profile} » répond (notarytool history). "
                    "Il est utilisable, y compris s'il est dans le trousseau iCloud."
                ),
            ),
            profile,
        )
    if history is not None and _profile_missing(history):
        return (
            DoctorCheck(
                title="Profil notaire",
                ok=False,
                summary=f"Aucun profil notaire nommé « {profile} » dans le trousseau.",
                fix=_notary_fix(profile),
            ),
            profile,
        )
    if keychain_item is not None and _profile_missing(keychain_item) and history is None:
        return (
            DoctorCheck(
                title="Profil notaire",
                ok=False,
                summary=(
                    f"Le profil « {profile} » n'est pas dans un trousseau fichier. "
                    "S'il a été créé sans --keychain, il est peut-être dans le "
                    "trousseau iCloud : relancez --check avec le réseau pour que "
                    "notarytool history le confirme."
                ),
                fix=_notary_fix(profile),
            ),
            profile,
        )
    if history is not None:
        detail = redact(f"{history.stdout}\n{history.stderr}".strip(), ())
        return (
            DoctorCheck(
                title="Profil notaire",
                ok=False,
                summary=(
                    f"Impossible de confirmer le profil « {profile} ».\n{detail or '(pas de détail)'}"
                ),
                fix=_notary_fix(profile),
            ),
            profile,
        )
    return (
        DoctorCheck(
            title="Profil notaire",
            ok=False,
            summary=f"Le profil « {profile} » n'a pas pu être vérifié.",
            fix=_notary_fix(profile),
        ),
        profile,
    )


def build_doctor_report(
    *,
    xcode: CommandResult,
    tool_paths: Mapping[str, str | None],
    identity_output: str,
    identity_returncode: int,
    requested_identity: str | None,
    profile_arg: str | None,
    env: Mapping[str, str],
    keychain_item: CommandResult | None,
    history: CommandResult | None,
) -> DoctorReport:
    checks = [_tools_check(xcode, tool_paths)]
    if identity_returncode != 0 and not parse_code_signing_identities(identity_output):
        detail = identity_output.strip() or "security find-identity a échoué."
        checks.append(
            DoctorCheck(
                title="Certificat Developer ID Application",
                ok=False,
                summary=detail,
                fix="Relancez :\n  security find-identity -v -p codesigning\n" + XCODE_CERT_STEPS,
            )
        )
        identities: list[str] = []
    else:
        check, identities = _identity_check(
            parse_code_signing_identities(identity_output),
            requested_identity,
        )
        checks.append(check)
    notary_check, _profile = _notary_check(
        profile_arg=profile_arg,
        env=env,
        keychain_item=keychain_item,
        history=history,
    )
    checks.append(notary_check)
    if len(identities) == 1:
        commands = [
            f'python packaging/build.py --sign "{identities[0]}" --notarize',
        ]
    elif len(identities) > 1:
        commands = [f'python packaging/build.py --sign "{name}" --notarize' for name in identities]
    else:
        commands = [
            'python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize'
        ]
    return DoctorReport(checks=checks, commands=commands)


def render_doctor(report: DoctorReport) -> str:
    lines = [
        "Contrôle de la signature macOS",
        "==============================",
        "",
    ]
    for check in report.checks:
        mark = "OK" if check.ok else "MANQUE"
        lines.append(f"[{mark}] {check.title}")
        for paragraph in check.summary.splitlines() or [""]:
            lines.append(f"    {paragraph}")
        if check.fix:
            lines.append("    Pour corriger :")
            for paragraph in check.fix.splitlines():
                lines.append(f"    {paragraph}")
        lines.append("")
    if not report.offer_commands:
        return "\n".join(lines).rstrip() + "\n"
    if report.ok:
        lines.append("Tout est prêt. Une fois le gel lancé, la commande unique est :")
    else:
        lines.append("Il manque au moins un prérequis. Corrigez les lignes [MANQUE], puis relancez")
        lines.append("python packaging/build.py --check.")
        lines.append("Quand tout est [OK], la commande de signature sera :")
    for command in report.commands:
        lines.append(f"  {command}")
    lines.append("Ajoutez --dmg pour produire en plus une image disque signée.")
    return "\n".join(lines).rstrip() + "\n"


def _probe(run: Runner, args: Sequence[str], *, timeout: float) -> CommandResult:
    try:
        return run(args, timeout=timeout, echo=False, secrets=())
    except MacSignError as exc:
        return CommandResult(127, "", str(exc))


def _uses_apple_env(profile_arg: str | None, env: Mapping[str, str]) -> bool:
    try:
        return resolve_notary(profile_arg, env).kind in {"apple_id", "api_key"}
    except MacSignError:
        return False


def discover_tool_paths(run: Runner) -> dict[str, str | None]:
    paths: dict[str, str | None] = {"codesign": shutil.which("codesign")}
    for tool in ("notarytool", "stapler"):
        result = _probe(run, ["xcrun", "--find", tool], timeout=DOCTOR_TIMEOUT)
        found = result.stdout.strip() if result.returncode == 0 else ""
        paths[tool] = found or None
    return paths


def run_doctor(
    *,
    platform: str,
    env: Mapping[str, str],
    sign_arg: str | None,
    profile_arg: str | None,
    run: Runner | None = None,
    tool_paths: Mapping[str, str | None] | None = None,
) -> int:
    if platform != "darwin":
        print(render_doctor(_non_macos_report()), end="")
        return 1
    runner = run or run_command
    paths = dict(tool_paths) if tool_paths is not None else discover_tool_paths(runner)
    xcode = _probe(runner, ["xcode-select", "-p"], timeout=DOCTOR_TIMEOUT)
    identity = _probe(runner, find_identity_command(), timeout=DOCTOR_TIMEOUT)
    requested = None
    if sign_arg is not None:
        requested = sign_arg.strip() or env.get("SENTINEL_CODESIGN_IDENTITY", "").strip() or None
    keychain_item: CommandResult | None = None
    history: CommandResult | None = None
    # Le mot de passe d'application n'est pas une variable : on ne le passe
    # à aucune commande du diagnostic. Pas de sonde non plus quand APPLE_ID
    # ou APPLE_TEAM_ID manque : le rapport explique déjà laquelle.
    if not _uses_apple_env(profile_arg, env):
        try:
            profile = resolve_notary(profile_arg, env).profile
        except MacSignError:
            profile = ""
        if profile:
            keychain_item = _probe(
                runner,
                notary_profile_keychain_command(profile),
                timeout=DOCTOR_TIMEOUT,
            )
            if keychain_item.returncode != 0:
                history = _probe(
                    runner,
                    notary_history_command(profile),
                    timeout=NOTARY_HISTORY_TIMEOUT,
                )
    report = build_doctor_report(
        xcode=xcode,
        tool_paths=paths,
        identity_output=f"{identity.stdout}\n{identity.stderr}",
        identity_returncode=identity.returncode,
        requested_identity=requested,
        profile_arg=profile_arg,
        env=env,
        keychain_item=keychain_item,
        history=history,
    )
    print(render_doctor(report), end="")
    return 0 if report.ok else 1
