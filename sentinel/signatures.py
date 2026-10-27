"""Règles de signature SIG-0001…SIG-0016.

V1 : SIG-0001…0010 (10 règles).
V2 : + SIG-0011 (JSP/ASP), + SIG-0013 (htaccess), + SIG-0014 (.bashrc/.profile/.zshrc),
       + SIG-0015 (passwd/sudoers), + SIG-0016 (LD_PRELOAD/LD_LIBRARY_PATH vers /tmp),
       + support EC + PKCS#8 dans SIG-0008.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from .models import Finding, RuleContext, Severity

# --- Base -----------------------------------------------------------------


class Rule:
    rule_id: str = ""
    severity: Severity = "medium"
    message: str = ""

    def quick_keywords(self) -> set[str] | None:
        """Sous-chaînes qui, si présentes dans une ligne, indiquent que
        la règle a une chance de matcher. P2-3 : utilisé par le scanner
        pour skipper les regex coûteuses sur les lignes qui ne
        contiennent aucun keyword. Retourne `None` si la règle est
        full-regex sans mot-clé discriminant (les regex sont alors
        appliquées systématiquement)."""
        return None

    def scan(
        self,
        rel_path: str,
        text: str,
        context: RuleContext | None = None,
    ) -> Iterable[Finding]:
        raise NotImplementedError


# --- Helpers --------------------------------------------------------------


def _iter_lines(text: str) -> Iterable[tuple[int, str]]:
    if not text:
        return
    yield from enumerate(text.splitlines(), start=1)


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith("#")


def _is_code_fence(line: str) -> bool:
    """Markdown code fence ``` or ~~~ (opening or closing)."""
    s = line.lstrip()
    return s.startswith("```") or s.startswith("~~~")


# `` `sh` ``, `` `bash` ``, `` `curl` ``… : balise inline Markdown, pas une
# substitution de commande. `` `curl` `` dans un README déclenchait SIG-0009.
_SHORT_LANGTAG = re.compile(r"`\s*(?:sh|bash|shell|curl|wget|nc|ncat)\s*`")


def _match_inside_short_langtag(line: str, match: re.Match[str]) -> bool:
    for tag in _SHORT_LANGTAG.finditer(line):
        if tag.start() <= match.start() and match.end() <= tag.end():
            return True
    return False


# --- SIG-0001 : Web shell PHP (eval, base64_decode ou cmd shell sur HTTP) -


class Sig0001(Rule):
    rule_id = "SIG-0001"
    severity: Severity = "critical"
    message = "Web shell PHP : eval, base64_decode ou commande shell sur une entrée HTTP"

    PATTERNS = [
        re.compile(r"\beval\s*\(\s*base64_decode\s*\("),
        re.compile(r"\beval\s*\(\s*\$\s*_(GET|POST|REQUEST|COOKIE|SERVER)\b"),
        re.compile(r"\bsystem\s*\(\s*\$\s*_(GET|POST|REQUEST|COOKIE)\b"),
        re.compile(r"\bpassthru\s*\(\s*\$\s*_(GET|POST|REQUEST|COOKIE)\b"),
        re.compile(r"\bshell_exec\s*\(\s*\$\s*_(GET|POST|REQUEST|COOKIE)\b"),
        re.compile(r"\bexec\s*\(\s*\$\s*_(GET|POST|REQUEST|COOKIE)\b"),
        re.compile(r"\bproc_open\s*\(\s*\$\s*_(GET|POST|REQUEST|COOKIE)\b"),
    ]

    def quick_keywords(self) -> set[str]:
        return {
            "eval",
            "base64_decode",
            "system",
            "passthru",
            "shell_exec",
            "proc_open",
            "_GET",
            "_POST",
            "_REQUEST",
            "_COOKIE",
            "_SERVER",
        }

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        if not rel_path.lower().endswith((".php", ".phtml", ".php5", ".php7")):
            return
        for ln, line in _iter_lines(text):
            for pat in self.PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )
                    break


# --- SIG-0002 : Reverse shell ----------------------------------------------

# `ncat` seul dans une phrase (« Also ncat is a tool. ») n'est pas un
# reverse shell. On exige un contexte de commande : drapeau (-e, -c, -l,
# --exec), adresse IP, couple hôte/port, pipe, ou invocation par un shell.
# Un commentaire qui contient vraiment `ncat -e …` reste détecté : on ne
# saute pas les commentaires en bloc.
_NCAT_COMMAND = re.compile(
    r"(?:"
    r"\bncat\b[^\n]*?(?:(?<=\s)-[A-Za-z]*[ecl][A-Za-z]*\b"
    r"|--exec\b|--sh-exec\b|--lua-exec\b)"
    r"|\bncat\b[^\n]*?\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\bncat\b(?:\s+-\S+)*\s+"
    r"(?:localhost|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\s+\d{2,5}\b"
    r"|\bncat\b[^\n]*\|"
    r"|\|\s*\bncat\b"
    r"|`\s*ncat\b"
    r"|\$\(\s*ncat\b"
    r"|\b(?:bash|sh|zsh|dash|ksh)\s+-c\b[^\n]*\bncat\b"
    r")"
)


class Sig0002(Rule):
    rule_id = "SIG-0002"
    severity: Severity = "critical"
    message = "Reverse shell (bash interactif, /dev/tcp, nc -e, ncat ou socat exec)"

    PATTERNS = [
        re.compile(r"\bbash\s+-i\b"),
        re.compile(r"/dev/tcp/"),
        re.compile(r"\bnc\s+-[a-zA-Z]*e\b"),
        re.compile(r"\bnc\.exe\b"),
        _NCAT_COMMAND,
        re.compile(r"\bsocat\b.*\bexec\b", re.IGNORECASE),
    ]

    def quick_keywords(self) -> set[str]:
        # P2-3 : les keywords doivent être des sous-chaînes *requises* par
        # au moins un pattern. « nc » (sans espace) couvre `nc -e`, `nc.exe`
        # et `nc\t-e` ; l'ancien `"nc "` laissait passer les deux derniers
        # (faux négatifs constatés). Idem `socat` sans espace : le motif
        # est `\bsocat\b…exec` et n'exige pas d'espace après le mot.
        # « bash » et non « bash -i » : le motif est `bash\s+-i`, donc
        # une tabulation ou plusieurs espaces (`bash\t-i`, `bash  -i`)
        # sont de vrais reverse shells. L'ancien mot-clé exact les
        # faisait sauter avant même d'atteindre la regex.
        return {"bash", "/dev/tcp/", "nc", "ncat", "socat"}

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            for pat in self.PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )
                    break


# --- SIG-0003 : Téléchargement puis exécution -----------------------------


class Sig0003(Rule):
    rule_id = "SIG-0003"
    severity: Severity = "high"
    message = "Téléchargement puis exécution (curl|sh, wget|bash, python -c avec urllib et exec)"

    # Motifs « primaires » : curl/wget suivi d'un pipe vers sh/bash.
    PATTERNS_PRIMARY = [
        re.compile(r"\bcurl\b[^\n]*\|\s*(sh|bash)\b"),
        re.compile(r"\bwget\b[^\n]*\|\s*(sh|bash)\b"),
    ]
    # python -c 'import urllib … exec(…)' — toujours standalone, pas de chaîne.
    PATTERN_PYTHON = re.compile(r"\bpython\d*(?:\.\d+)?\s+-c\s+['\"][^'\"]*urllib[^'\"]*exec\(")
    # Marqueurs « commande chaînée » : `&&`, `||`, `;`. `&` seul (sans `&`) n'est pas
    # traité comme un chaînage ici (rare et bruyant).
    CHAIN = re.compile(r"&&|\|\||;")

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            # Une ligne entièrement commentée n'exécute pas le téléchargement.
            # `curl … | sh  # note` reste détecté : le commentaire ne couvre
            # pas la commande. On ne fait pas ça pour SIG-0002 (un `ncat -e`
            # commenté est encore un contexte de commande).
            if _is_comment(line) or line.lstrip().startswith("//"):
                continue
            # python -c 'import urllib; exec(…)' est toujours un standalone.
            m = self.PATTERN_PYTHON.search(line)
            if m:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=m.group(0).strip(),
                )
                continue

            # Sinon : curl/wget|sh/bash — mais seulement si c'est la commande
            # PRINCIPALE de la ligne (pas après &&/||/; ni dans une sous-shell).
            for pat in self.PATTERNS_PRIMARY:
                m = pat.search(line)
                if not m:
                    continue
                pre = line[: m.start()]
                # Sous-shell ouvrante au début → pas la commande principale.
                if pre.lstrip().startswith("("):
                    break
                # Chaînage explicite → pas la commande principale.
                if self.CHAIN.search(pre):
                    break
                evidence = m.group(0).strip()
                if "|" in evidence:
                    idx = evidence.find("|")
                    s = max(0, idx - 24)
                    e = min(len(evidence), idx + 24)
                    evidence = evidence[s:e].strip()
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=evidence,
                )
                break

    def quick_keywords(self) -> set[str]:
        # P2-3 : préfiltre par sous-chaîne. Les keywords sont des briques
        # indivuelles (pas le pattern complet) parce que les fixtures
        # ont souvent `curl X | sh` (X non vide), donc `curl|sh` ne
        # match pas en substring.
        return {"curl ", "wget ", "python ", "urllib", "exec(", "|sh", "|bash", "| sh", "| bash"}


# --- SIG-0004 : Charge encodée --------------------------------------------


class Sig0004(Rule):
    rule_id = "SIG-0004"
    severity: Severity = "high"
    message = "Exécution de charge encodée (base64 -d|sh, eval(atob), powershell -enc)"

    PATTERNS = [
        re.compile(r"\bbase64\s+-d\b[^\n]*\|\s*(sh|bash)\b"),
        re.compile(r"\beval\s*\(\s*atob\s*\("),
        re.compile(r"\bpowershell(?:\.exe)?\s+-enc\b"),
    ]

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            for pat in self.PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )
                    break


# --- SIG-0005 : Indicateur de minage --------------------------------------


class Sig0005(Rule):
    rule_id = "SIG-0005"
    severity: Severity = "high"
    message = "Indicateur de minage (stratum+tcp, xmrig, minerd, --donate-level)"

    PATTERNS = [
        re.compile(r"\bstratum\+tcp\b"),
        re.compile(r"\bxmrig\b"),
        re.compile(r"\bminerd\b"),
        re.compile(r"\b--donate-level\b"),
        re.compile(r"\bcryptonight\b"),
    ]

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            for pat in self.PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )
                    break


# --- SIG-0006 : Persistance cron ------------------------------------------


class Sig0006(Rule):
    rule_id = "SIG-0006"
    severity: Severity = "high"
    message = "Persistance cron (@reboot, ou cinq champs * ou */N, avec curl, wget ou nc)"

    # Forme d'une entrée crontab : la ligne COMMENCE par @reboot, puis une
    # commande. « # @reboot … » dans un .py, ou « Also @reboot is a keyword »,
    # ne matchent pas. Cette forme EST le contexte crontab : on ne l'exige
    # pas seulement dans un fichier nommé crontab, sinon un fragment déposé
    # (`persist.txt`) disparaîtrait.
    REBOOT_ENTRY = re.compile(r"^\s*@reboot\s+\S")
    STAR_FIELDS = re.compile(r"^\s*(?:\*|\*/\d+)(?:\s+(?:\*|\*/\d+)){4}\s+(.+)$")
    DANGEROUS = re.compile(r"\b(curl|wget|nc|ncat)\b")

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            if self.REBOOT_ENTRY.search(line):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence="@reboot",
                )
                continue
            m = self.STAR_FIELDS.match(line)
            if m:
                tail = m.group(1)
                dm = self.DANGEROUS.search(tail)
                if dm:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=dm.group(0),
                    )


# --- SIG-0007 : Clé SSH dans authorized_keys ------------------------------


class Sig0007(Rule):
    rule_id = "SIG-0007"
    severity: Severity = "high"
    message = "Clé SSH publique ajoutée dans authorized_keys"

    SSH_KEY_PREFIXES = ("ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-")

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        if PurePosixPath(rel_path).name != "authorized_keys":
            return
        for ln, line in _iter_lines(text):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _ALL_SSH_KEY_RE.search(line)
            if m and m.group("type").startswith(self.SSH_KEY_PREFIXES):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=m.group("type"),
                )


# --- SIG-0008 : Clé privée en clair (RSA, OpenSSH, EC, PKCS#8) -----------


class Sig0008(Rule):
    rule_id = "SIG-0008"
    severity: Severity = "critical"
    message = "Clé privée en clair (RSA, OpenSSH, EC ou PKCS#8)"

    MARKERS = (
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",  # PKCS#8
    )

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            for marker in self.MARKERS:
                if marker in line:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=marker,
                    )
                    break


# --- SIG-0009 : Injection shell -------------------------------------------


class Sig0009(Rule):
    rule_id = "SIG-0009"
    severity: Severity = "medium"
    message = "Injection shell (substitution de commande, rm -rf chaîné ou curl chaîné)"

    PATTERNS = [
        re.compile(r"\$\(\s*(curl|wget|nc|ncat|bash|sh)\b"),
        re.compile(r"`\s*(curl|wget|nc|ncat|bash|sh)\b"),
        re.compile(r";\s*rm\s+-rf\b"),
        re.compile(r"&&[^\n]*\bcurl\b"),
        re.compile(r";[^\n]*\bcurl\b"),
    ]

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            if _is_comment(line) or _is_code_fence(line):
                continue
            for pat in self.PATTERNS:
                m = pat.search(line)
                if not m or _match_inside_short_langtag(line, m):
                    continue
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=m.group(0).strip(),
                )
                break


# --- SIG-0010 : User-Agent d'outil d'attaque ------------------------------


class Sig0010(Rule):
    rule_id = "SIG-0010"
    severity: Severity = "medium"
    message = "User-Agent d'outil d'attaque ou de client scripté"

    UA_RE = re.compile(r"User-Agent\s*:\s*([^\r\n]+)", re.IGNORECASE)
    KNOWN = (
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "zgrab",
        "wpscan",
        "dirbuster",
        "gobuster",
        "whatweb",
        "acunetix",
        "burpsuite",
    )

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            m = self.UA_RE.search(line)
            if not m:
                continue
            ua = m.group(1).strip()
            for kw in self.KNOWN:
                if kw in ua.lower():
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=f"User-Agent: {ua}",
                    )
                    break


# --- SIG-0011 : Web shell JSP/ASP ----------------------------------------


class Sig0011(Rule):
    rule_id = "SIG-0011"
    severity: Severity = "critical"
    message = "Web shell JSP/ASP (Runtime.exec, Execute ou eval request dans un bloc <% )"

    PATTERNS = [
        re.compile(r"<%[^%]*Runtime\.getRuntime\(\)\.exec\s*\("),
        re.compile(r"<%[^%]*\.execute\s*\(\s*Request\b", re.IGNORECASE),
        re.compile(r"<%[^%]*eval\s*\(\s*request", re.IGNORECASE),
    ]

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        if not rel_path.lower().endswith((".jsp", ".asp", ".aspx")):
            return
        for ln, line in _iter_lines(text):
            for pat in self.PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )
                    break


# --- SIG-0012 : Log4Shell (jndi:) ----------------------------------------


class Sig0012(Rule):
    rule_id = "SIG-0012"
    severity: Severity = "critical"
    message = "Log4Shell : lookup ${jndi:"

    RE = re.compile(r"\$\{jndi\s*:")

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            m = self.RE.search(line)
            if m:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=m.group(0),
                )


# --- SIG-0013 : .htaccess dangereux --------------------------------------


class Sig0013(Rule):
    rule_id = "SIG-0013"
    severity: Severity = "high"
    message = "Directive .htaccess dangereuse (auto_prepend ou AddType PHP)"

    PATTERNS = [
        re.compile(r"\bphp_value\s+auto_prepend_file\b", re.IGNORECASE),
        re.compile(r"\bphp_value\s+auto_append_file\b", re.IGNORECASE),
        re.compile(r"\bAddType\s+application/x-httpd-php\b", re.IGNORECASE),
        re.compile(r"\bAddHandler\s+application/x-httpd-php\b", re.IGNORECASE),
        re.compile(r"\bSetHandler\s+application/x-httpd-php\b", re.IGNORECASE),
    ]

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        if PurePosixPath(rel_path).name.lower() != ".htaccess":
            return
        for ln, line in _iter_lines(text):
            for pat in self.PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )
                    break


# --- SIG-0014 : Persistance shell utilisateur (.bashrc/.profile/.zshrc) -


class Sig0014(Rule):
    rule_id = "SIG-0014"
    severity: Severity = "high"
    message = "Persistance shell dans .bashrc, .profile, .zshrc ou .bash_profile"

    INTERESTING = re.compile(r"\b(curl|wget|nc|ncat|eval|base64|python|perl)\b")
    SHELL_FILES = {".bashrc", ".profile", ".zshrc", ".bash_profile"}

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        name = PurePosixPath(rel_path).name
        if name not in self.SHELL_FILES:
            return
        for ln, line in _iter_lines(text):
            if _is_comment(line):
                continue
            m = self.INTERESTING.search(line)
            if m:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=m.group(0),
                )


# --- SIG-0015 : passwd / sudoers ------------------------------------------


class Sig0015(Rule):
    rule_id = "SIG-0015"
    severity: Severity = "high"
    message = "Modification d'identités (passwd :0:0: ou sudoers NOPASSWD / ALL=(ALL))"

    SUDO_NOPASSWD = re.compile(r"\bNOPASSWD\b\s*:\s*\bALL\b", re.IGNORECASE)
    SUDO_ALL_ALL = re.compile(r"\bALL=\(ALL\)", re.IGNORECASE)

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        path = PurePosixPath(rel_path)
        name = path.name
        if name == "passwd":
            for ln, line in _iter_lines(text):
                if _is_comment(line):
                    continue
                # username:passwd:uid:gid — le compte root légitime n'est pas un ajout.
                fields = line.strip().split(":")
                if len(fields) < 3:
                    continue
                user, uid = fields[0], fields[2]
                if user != "root" and uid == "0":
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=f"{user} uid={uid}",
                    )
            return
        if name == "sudoers" or "sudoers.d" in path.parts[:-1]:
            for ln, line in _iter_lines(text):
                if _is_comment(line):
                    continue
                m = self.SUDO_NOPASSWD.search(line) or self.SUDO_ALL_ALL.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0),
                    )


# --- SIG-0016 : LD_PRELOAD / LD_LIBRARY_PATH vers /tmp -------------------


class Sig0016(Rule):
    rule_id = "SIG-0016"
    severity: Severity = "medium"
    message = "LD_PRELOAD ou LD_LIBRARY_PATH pointant vers /tmp"

    ASSIGN = re.compile(r"\b(LD_PRELOAD|LD_LIBRARY_PATH)\s*=\s*([^\n#]*)")
    # /tmp en début de valeur ou après un séparateur de PATH, pas /var/tmp ni /tmpfoo.
    TMP = re.compile(r"(?:^|[:\s\"'])/tmp(?![\w])")

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        for ln, line in _iter_lines(text):
            if _is_comment(line):
                continue
            m = self.ASSIGN.search(line)
            if not m or not self.TMP.search(m.group(2)):
                continue
            value = m.group(2).strip()
            yield Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                path=rel_path,
                line=ln,
                message=self.message,
                evidence=f"{m.group(1)}={value[:80]}",
            )


# --- SIG-0017 : Unité systemd malveillante ------------------------------


class Sig0017(Rule):
    """Détecte les unités systemd (`*.service`, `*.timer`, `*.socket`)
    qui exécutent du code suspect.

    Les indicateurs sont :
      - ExecStart avec reverse-shell (bash -i, /dev/tcp/, nc -e, ncat, socat exec)
      - ExecStart avec téléchargement+exécution (curl|sh, wget|bash, python -c urllib exec)
      - ExecStart avec décode+exec (base64 -d|sh, eval(atob(, powershell -enc)
      - ExecStart avec minage (stratum+tcp, xmrig, minerd, --donate-level)

    Le fichier doit être une unité systemd (suffixe `.service/.timer/.socket`
    ou un chemin typique comme `/etc/systemd/system/…`).
    """

    rule_id = "SIG-0017"
    severity: Severity = "critical"
    message = "Unité systemd avec ExecStart suspect (reverse-shell, dropper, ou mineur)"

    SYSTEMD_SUFFIXES = (".service", ".timer", ".socket")
    SYSTEMD_DIRS = ("/etc/systemd/", "/usr/lib/systemd/", "/lib/systemd/")

    # On reprend une partie des patterns de SIG-0002, SIG-0003, SIG-0004, SIG-0005,
    # limités à la valeur de ExecStart.
    EXEC_PATTERNS = [
        # reverse shell
        re.compile(r"\bbash\s+-i\b"),
        re.compile(r"/dev/tcp/"),
        re.compile(r"\bnc\s+-[a-zA-Z]*e\b"),
        re.compile(r"\bnc\.exe\b"),
        _NCAT_COMMAND,
        re.compile(r"\bsocat\b.*\bexec\b", re.IGNORECASE),
        # dropper (curl|sh, wget|bash, python urllib+exec)
        re.compile(r"\bcurl\b[^\n]*\|\s*(sh|bash)\b"),
        re.compile(r"\bwget\b[^\n]*\|\s*(sh|bash)\b"),
        re.compile(r"\bpython\d*(?:\.\d+)?\s+-c\s+['\"][^'\"]*urllib[^'\"]*exec\("),
        # encoded payload
        re.compile(r"\bbase64\s+-d\b[^\n]*\|\s*(sh|bash)\b"),
        re.compile(r"\beval\s*\(\s*atob\s*\("),
        re.compile(r"\bpowershell(?:\.exe)?\s+-enc\b"),
        # miner
        re.compile(r"\bstratum\+tcp\b"),
        re.compile(r"\bxmrig\b"),
        re.compile(r"\bminerd\b"),
        re.compile(r"\b--donate-level\b"),
        re.compile(r"\bcryptonight\b"),
    ]

    def quick_keywords(self) -> set[str]:
        # P2-3 : mêmes pièges que SIG-0002. Les anciens `"curl|sh"` et
        # `"wget|bash"` ne matchaient que si le pipe était *collé* au nom
        # de commande : une unité `ExecStart=/bin/bash -c "curl -s URL | sh"`
        # (forme réelle) passait le préfiltre sans être vue. On liste donc
        # les briques réellement requises : `curl `, `wget `, `| sh`, `|sh`…
        return {
            "bash",
            "/dev/tcp/",
            "nc",
            "ncat",
            "socat",
            "curl ",
            "wget ",
            "|sh",
            "|bash",
            "| sh",
            "| bash",
            "python ",
            "urllib",
            "base64",
            "atob",
            "powershell",
            "stratum+tcp",
            "xmrig",
            "minerd",
            "donate-level",
            "cryptonight",
        }

    EXEC_KEYS = re.compile(
        r"^\s*(?:ExecStart(?:Pre|Post)?|ExecCondition|ExecReload)\s*=",
        re.MULTILINE,
    )

    @classmethod
    def _is_systemd_unit(cls, rel_path: str) -> bool:
        p = PurePosixPath(rel_path)
        if p.suffix.lower() in cls.SYSTEMD_SUFFIXES:
            return True
        for d in cls.SYSTEMD_DIRS:
            if rel_path.startswith(d):
                return True
        return False

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        if not self._is_systemd_unit(rel_path):
            return
        for ln, line in _iter_lines(text):
            if not self.EXEC_KEYS.match(line):
                continue
            for pat in self.EXEC_PATTERNS:
                m = pat.search(line)
                if m:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        path=rel_path,
                        line=ln,
                        message=self.message,
                        evidence=m.group(0).strip(),
                    )
                    break


# --- SIG-0018 : SUID / SGID modifié --------------------------------------


class Sig0018(Rule):
    """Détecte les fichiers qui ont acquis (ou qui possèdent déjà) un bit
    SUID (0o4000) ou SGID (0o2000).

    Sans baseline : déclenche sur tout fichier avec SUID ou SGID posé
    (utile pour un premier inventaire). Avec baseline : ne déclenche
    QUE si le bit a été ajouté post-baseline (escalade de privilèges).
    """

    rule_id = "SIG-0018"
    severity: Severity = "high"
    message = "Fichier SUID/SGID (escalade de privilèges possible)"

    SUID = 0o4000
    SGID = 0o2000

    @staticmethod
    def _bits(mode: int) -> int:
        return mode & 0o7000  # SUID + SGID + sticky

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        ctx = context or RuleContext()
        cur_mode = ctx.file_mode
        if cur_mode is None:
            return
        cur_bits = self._bits(cur_mode)
        base_bits = self._bits(ctx.baseline_mode) if ctx.baseline_mode is not None else 0

        # Nouveau bit SUID/SGID ?
        added = cur_bits & ~base_bits
        if not added:
            return

        labels: list[str] = []
        if added & self.SUID:
            labels.append("SUID")
        if added & self.SGID:
            labels.append("SGID")
        if not labels:
            return

        mode_str = oct(cur_mode & 0o7777)
        yield Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            path=rel_path,
            line=1,
            message=f"Bit {'+'.join(labels)} acquis (mode={mode_str})",
            evidence=f"{'+'.join(labels)}={oct(added)}",
        )


# --- SIG-0019 : Clé ed25519 ajoutée à authorized_keys post-baseline ------


# Une ligne authorized_keys peut préfixer la clé d'options
# (`command="…",no-pty ssh-ed25519 AAAA…`). Le type n'est alors pas en
# début de ligne : l'ancien `match` ancré les ignorait, et SIG-0007
# comme SIG-0019 rataient une persistance SSH classique.
_ALL_SSH_KEY_RE = re.compile(
    r"(?:^|\s)(?P<type>ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-[a-z0-9-]+)"
    r"\s+(?P<key>[A-Za-z0-9+/]+)"
)


def _extract_all_ssh_keys(text: str) -> set[tuple[str, str]]:
    """Retourne le set des clés SSH (type, body) d'un fichier
    `authorized_keys`. Lignes vides et commentaires (`#…`) sont ignorées.
    Les options OpenSSH en préfixe (`command="…",no-pty`) ne masquent pas
    la clé.

    Le type est inclus dans la clé composite : une clé ed25519 et une
    clé rsa avec le même body (très improbable mais possible) sont
    distinguées. Un retrait de clé (clé qui disparaît) n'est PAS un
    finding — seul l'ajout compte.
    """
    keys: set[tuple[str, str]] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ALL_SSH_KEY_RE.search(line)
        if m:
            keys.add((m.group("type"), m.group("key")))
    return keys


def _ssh_fingerprint(key: tuple[str, str]) -> str:
    return hashlib.sha256((key[0] + " " + key[1]).encode("ascii")).hexdigest()


class Sig0019(Rule):
    """Détecte l'ajout de clés SSH à un fichier `authorized_keys`
    *post-baseline*. Couvre tous les types courants (ed25519, rsa, dss,
    ecdsa). Sans baseline, on ne peut pas dire « augmentée » : la
    règle reste silencieuse (l'audit « n'importe quelle clé SSH dans
    authorized_keys » est déjà couvert par SIG-0007).
    """

    rule_id = "SIG-0019"
    severity: Severity = "high"
    message = "Clé SSH ajoutée à authorized_keys (intégrité × signature)"

    def scan(
        self, rel_path: str, text: str, context: RuleContext | None = None
    ) -> Iterable[Finding]:
        if PurePosixPath(rel_path).name != "authorized_keys":
            return
        ctx = context or RuleContext()
        if ctx.baseline_ssh_fingerprints is not None:
            current_keys = _extract_all_ssh_keys(text)
            added = {
                key
                for key in current_keys
                if _ssh_fingerprint(key) not in ctx.baseline_ssh_fingerprints
            }
        elif ctx.baseline_text is not None:
            added = _extract_all_ssh_keys(text) - _extract_all_ssh_keys(ctx.baseline_text)
        else:
            return
        if not added:
            return

        # Trouve la ligne de la PREMIÈRE clé ajoutée pour l'evidence.
        for ln, line in _iter_lines(text):
            m = _ALL_SSH_KEY_RE.search(line)
            if m and (m.group("type"), m.group("key")) in added:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    path=rel_path,
                    line=ln,
                    message=self.message,
                    evidence=f"{m.group('type')} <nouvelle clé>",
                )
                return


# --- Registre -------------------------------------------------------------


ALL_RULES: list[Rule] = [
    Sig0001(),
    Sig0002(),
    Sig0003(),
    Sig0004(),
    Sig0005(),
    Sig0006(),
    Sig0007(),
    Sig0008(),
    Sig0009(),
    Sig0010(),
    Sig0011(),
    Sig0012(),
    Sig0013(),
    Sig0014(),
    Sig0015(),
    Sig0016(),
    Sig0017(),
    Sig0018(),
    Sig0019(),
]


def _flatten_signature_source(value: object):
    if isinstance(value, re.Pattern):
        yield ("re", value.pattern)
    elif isinstance(value, str):
        yield ("lit", value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _flatten_signature_source(item)


def _iter_signature_sources():
    for value in globals().values():
        if isinstance(value, re.Pattern):
            yield ("re", value.pattern)
    skip = {"rule_id", "severity", "message"}
    for rule in ALL_RULES:
        for key, value in vars(type(rule)).items():
            if key.startswith("_") or key in skip:
                continue
            yield from _flatten_signature_source(value)


def _tree_span(tree, maxrepeat: int) -> int | None:
    total = 0
    for op, av in tree:
        width = _node_span(op, av, maxrepeat)
        if width is None:
            return None
        total += width
    return total


_OP_NAMES: dict[int, str] = {}


def _op_name(op) -> str:
    """Nom d'opcode SRE. Entier sur 3.10 (``sre_parse``), enum ensuite."""
    found = getattr(op, "name", None)
    if isinstance(found, str):
        return found
    if isinstance(op, int):
        return _OP_NAMES.get(op, "")
    return ""


def _node_span(op, av, maxrepeat: int) -> int | None:
    name = _op_name(op)
    if name in {"LITERAL", "NOT_LITERAL", "ANY", "IN", "CATEGORY"}:
        return 1
    if name in {"AT", "ASSERT", "ASSERT_NOT"}:
        return 0
    if name == "SUBPATTERN":
        return _tree_span(av[-1], maxrepeat)
    if name == "BRANCH":
        widths: list[int] = []
        for alt in av[1]:
            width = _tree_span(alt, maxrepeat)
            if width is None:
                return None
            widths.append(width)
        return max(widths) if widths else 0
    if name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
        _lo, hi, sub = av
        if hi >= maxrepeat:
            return None
        sub_w = _tree_span(sub, maxrepeat)
        if sub_w is None:
            return None
        return hi * sub_w
    return None


def _longest_literal(tree) -> int:
    best = 0
    run = 0
    for op, av in tree:
        if _op_name(op) == "LITERAL":
            run += 1
            best = max(best, run)
            continue
        run = 0
        best = max(best, _child_literals(op, av))
    return best


def _child_literals(op, av) -> int:
    name = _op_name(op)
    if name == "SUBPATTERN":
        return _longest_literal(av[-1])
    if name == "BRANCH":
        return max((_longest_literal(alt) for alt in av[1]), default=0)
    if name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
        return _longest_literal(av[2])
    if name in {"ASSERT", "ASSERT_NOT"}:
        return _longest_literal(av[1])
    return 0


def measured_signature_overlap() -> int:
    """Plus long match borné, ou plus long littéral, plancher 512.

    Un motif non borné (`.*`, `\\s+`, `[^\n]*`) ne contribue pas de
    largeur maximale : le scan coupe sur les sauts de ligne, donc la
    ligne entière est dans une seule fenêtre tant qu'elle tient dans
    le chunk. Le plancher couvre une commande qui chevauche une coupe
    au milieu d'une ligne plus longue que le chunk.
    """
    # `re._parser` date de 3.11. 3.10 expose encore `sre_parse`.
    # importlib : mypy ne voit pas un import de module privé.
    import importlib

    try:
        parser: Any = importlib.import_module("re._parser")
        constants: Any = importlib.import_module("re._constants")
    except ModuleNotFoundError:
        parser = importlib.import_module("sre_parse")
        constants = importlib.import_module("sre_constants")
    opcodes = getattr(constants, "OPCODES", None)
    _OP_NAMES.clear()
    if isinstance(opcodes, dict):
        # 3.10 : nom -> entier. 3.11+ les opcodes ont déjà ``.name``.
        _OP_NAMES.update({int(value): str(name) for name, value in opcodes.items()})
    maxrepeat = int(constants.MAXREPEAT)

    best_span = 0
    best_literal = 0
    for kind, text in _iter_signature_sources():
        if kind == "lit":
            best_literal = max(best_literal, len(text))
            continue
        try:
            tree = parser.parse(text)
        except re.error:
            best_literal = max(best_literal, len(text))
            continue
        span = _tree_span(tree, maxrepeat)
        if span is not None:
            best_span = max(best_span, span)
        best_literal = max(best_literal, _longest_literal(tree))
    return max(best_span, best_literal, 512)
