# SENTINEL — analyse de sécurité locale orientée fichiers (V4)

Version du paquet : **3.0.0**. Les mentions V1 à V5 ci-dessous désignent des étapes historiques du moteur et de ses corrections, pas des versions distinctes du paquet.

Analyse un dossier : détecte des **indicateurs d'intrusion connus** (signatures),
les **modifications** par rapport à une référence (baseline), et un **score
d'anomalie par fichier** (V2 heuristique ou **V3 neuronal — autoencodeur**).

Versions :

- **V1** — signatures de base + intégrité (SHA-256, mode bits).
- **V2** — signatures étendues + heuristique d'anomalie (4 features).
- **V3** — autoencodeur neuronal 8 → 6 → 4 → 6 → 8 (Python pur) + trainset.
- **V4** — règles augmentées (intégrité × signature), quarantaine read-only,
  surveillance temps réel (`watch`), trainset étendu (250 fichiers).
- **P0 (audit P0-1..P0-6)** — corrections d'angles morts silencieux :
  P0-1 textes non-ASCII, P0-2 baseline V1 muette, P0-3 symlinks,
  P0-4 uid/gid + capabilities, P0-5 normalisation des payloads obfusqués,
  P0-6 SIG-0019 généralisé à tous types de clés SSH.

Bibliothèque standard uniquement. **Zéro dépendance de production** ; `watchdog`
est *optionnel* (fallback polling si absent).

## Usage

```bash
# 1) Créer une baseline d'intégrité d'un dossier
#    Sans clé : baseline non signée (avertissement). Le clair des fichiers
#    sensibles (clé privée, authorized_keys, .env, …) n'est pas embarqué.
python3 -m sentinel baseline <dossier> --out baseline.json
#    Avec clé, hors de l'historique du shell : contenu en HMAC + signature.
export SENTINEL_KEY="$(cat ~/.config/sentinel/key)"   # ou : --key-file chemin (chmod 600)
python3 -m sentinel baseline <dossier> --out baseline.json

# 2) Scanner (signatures [+intégrité] [+anomalie])
python3 -m sentinel scan <dossier> --format text
python3 -m sentinel scan <dossier> --baseline baseline.json --anomaly --top 10
#    Politique opt-in : refuser une baseline non signée (défaut = avertissement).
#    Équivalent : SENTINEL_REQUIRE_SIGNED=1 (aussi true / yes).
python3 -m sentinel scan <dossier> --baseline baseline.json --require-signed
python3 -m sentinel scan <dossier> --neural --model model.json --anomaly

# 3) Entraîner un autoencodeur (V3)
python3 -m sentinel train <dossier_normal> --out model.json --epochs 200

# 4) V4 — règles augmentées (SIG-0017/0018/0019) et trainset étendu
tools/expand_trainset.py --limit 250 --out tests/fixtures/benign_large
python3 -m sentinel train tests/fixtures/benign_large --out model_large.json --epochs 200

# 5) V4 — quarantaine (mv + read-only + manifest)
python3 -m sentinel quarantine path/to/suspect.py path/to/other.sh

# 6) V4 — surveillance temps réel (FSEvents via watchdog si dispo, sinon polling)
python3 -m sentinel watch <dossier> --interval 2.0 --baseline baseline.json
pip install watchdog     # optionnel, pour la version événementielle

# 7) Signer une baseline déjà écrite (sans régénérer les entrées)
#    Déjà signée et vérifiée par la clé : --yes suffit hors terminal.
python3 -m sentinel baseline --resign baseline.json --key-file ~/.config/sentinel/key --yes
#    Non signée : confiance initiale, --trust-unsigned est obligatoire
#    (--yes seul est refusé). En cas de doute, régénérez avec `baseline`.
python3 -m sentinel baseline --resign baseline.json --key-file ~/.config/sentinel/key --yes --trust-unsigned
#    --backup copie l'original en baseline.json.bak
```

Codes de sortie : `0` rien · `1` findings et/ou modifications d'intégrité · `2` erreur · `3` scan incomplet (fichier ou dossier illisible).
**Le score d'anomalie seul (sans signature ni modification) ne change pas l'exit code.**
**`3` est prioritaire sur `1`** : les findings déjà obtenus restent dans le rapport, mais un exit 1 ferait croire que tout l'arbre a été lu. Un binaire ignoré volontairement n'est pas un chemin illisible. Le parcours est `os.walk(onerror=…)` : un dossier illisible est listé dans `report.unreadable` (texte, JSON, stderr), il n'est plus avalé par `rglob`.

Les signatures couvrent **tout** le fichier, par fenêtres d'au plus 8 Mio plus un overlap (le plus long match borné, plancher 512). La coupe se fait sur un saut de ligne quand la ligne tient dans la fenêtre ; une ligne plus longue est coupée et l'overlap déduplique les findings déjà vus. Les numéros de ligne restent ceux du fichier. L'anomalie continue d'échantillonner le début.

`ncat` (SIG-0002) ne part plus sur le mot seul : il faut un drapeau (`-e`, `-c`, `-l`, `--exec`), une IP, un couple hôte/port, un pipe ou un shell (`bash -c`). `@reboot` (SIG-0006) ne part que si la ligne **commence** par `@reboot` suivi d'une commande. Une ligne entièrement commentée ne déclenche plus SIG-0003 ; un `ncat -e` dans un commentaire reste un SIG-0002.

## Règles de signature

| ID        | Sévérité | Déclencheur résumé |
|-----------|----------|--------------------|
| SIG-0001  | critical | Web shell PHP (`eval`, `base64_decode`, `system($_GET…)`) |
| SIG-0002  | critical | Reverse shell (`bash -i`, `/dev/tcp/`, `nc -e`, `ncat` en contexte de commande, `socat exec`) |
| SIG-0003  | high     | Téléchargement+exécution (`curl|sh`, `wget|bash`, `python urllib+exec`) |
| SIG-0004  | high     | Charge encodée (`base64 -d|sh`, `eval(atob)`, `powershell -enc`) |
| SIG-0005  | high     | Minage (`stratum+tcp`, `xmrig`, `minerd`, `--donate-level`) |
| SIG-0006  | high     | Persistance cron (ligne `@reboot <commande>`, champs `*` + `curl/wget/nc`) |
| SIG-0007  | high     | Clé SSH dans `authorized_keys` |
| SIG-0008  | critical | Clé privée en clair (RSA / OpenSSH / EC / PKCS#8) |
| SIG-0009  | medium   | Injection shell (`$()`, `` `` ``, `;rm -rf`, `&& curl`) |
| SIG-0010  | medium   | User-Agent d'outil d'attaque |
| SIG-0011  | critical | Web shell JSP/ASP |
| SIG-0012  | critical | Log4Shell (`${jndi:`) |
| SIG-0013  | high     | `.htaccess` dangereux |
| SIG-0014  | high     | Persistance shell utilisateur |
| SIG-0015  | high     | Modification `passwd`/`sudoers` |
| SIG-0016  | medium   | `LD_PRELOAD`/`LD_LIBRARY_PATH` → `/tmp` |
| SIG-0017  | critical | Unité systemd `ExecStart` suspect (V4) |
| SIG-0018  | high     | SUID/SGID acquis (escalade de privilèges) (V4) |
| SIG-0019  | high     | Clé SSH ajoutée à `authorized_keys` post-baseline — P0-6 : tous types (ed25519, rsa, dss, ecdsa) |

SIG-0018 et SIG-0019 sont les premières règles « augmentées » : elles
utilisent le `RuleContext` (mode du fichier, contenu baseline) pour
détecter des changements. SIG-0017 inspecte le contenu d'unités systemd
spécifiques.

## Angles morts — corrections P0

Six corrections d'audit suite à l'analyse de WorkBuddy :

- **P0-1** — `looks_binary()` accepte maintenant les textes non-ASCII.
  Le ratio de « non-imprimables » est calculé sur la chaîne UTF-8 décodée
  (et non plus sur les octets bruts), donc les fichiers en CJK, arabe,
  emoji ou latin étendu ne sont plus pris pour du binaire. Un vrai
  binaire (NULs en série, > 5 % de NUL) reste détecté. Conséquence :
  un `.php` chinois contenant `eval($_POST["x"])` est maintenant scanné.
- **P0-2** — `load_baseline_text()` retourne `None` (et un warning
  global est émis) si la baseline n'embarque pas le contenu historique
  (V1 ou fichier > 64 KB). Plus de comparaison fallacieuse
  « fichier vs lui-même » : SIG-0019 reste silencieuse sur ces
  fichiers tant que la baseline n'est pas régénérée.
- **P0-3** — Politique explicite sur les symlinks (et, sur Windows, les
  jonctions et autres points de reparse). Par défaut, ils sont
  ignorés (le scanner ne sort plus de la racine). Avec `--follow-links`,
  les symlinks sont suivis SAUF si leur cible résolue est hors-confinement
  (containment) ; les cibles ignorées sont listées dans
  `report.skipped_external` pour audit.
- **P0-4** — uid/gid + capabilities Linux dans la baseline.
  `IntegrityDiff` expose `owner_changed` (chown) et `cap_changed`
  (`getcap` ; best-effort, None sur macOS). Les deux sont plus pertinents
  que SUID aujourd'hui (escalade via `cap_net_bind_service`,
  `cap_dac_read_search`, etc.).
- **P0-5** — Couche de normalisation des payloads. Un module
  `sentinel/normalize.py` est appliqué avant les règles : décodage des
  `\xHH` / `\uHHHH` / `\OOO`, résolution des concaténations Python
  (`"abc" "def"` → fusion), décodage des littéraux base64 ≥ 32 chars.
  Les numéros de ligne sont préservés (1 ligne → 1 ligne).
- **P0-6** — SIG-0019 généralisée à **tous** les types de clés SSH
  (ed25519, rsa, dss, ecdsa). Avant P0-6, une clé ssh-rsa ajoutée
  n'était vue que par SIG-0007 (« une clé existe »), pas comme
  ajout post-baseline.

## Détection d'anomalie

### V2 — heuristique (4 features)

50 % entropie + 30 % longueur de ligne + 10 % non-imprimables + 10 % métacaractères.
Score 0..100. Le rapport texte n'affiche que les scores ≥ 60.

### V3 — autoencodeur neuronal

Vecteur 8 features → encodeur ReLU → goulot tanh (4) → décodeur ReLU → linéaire.
Optimiseur Adam. **Python pur**, pas de numpy/torch.
Score = `100 × MSE / max_score` où `max_score = 5× pire perte trainset`.

### Trainset large (V4)

```bash
tools/expand_trainset.py --limit 250 --out tests/fixtures/benign_large
```

Échantillonne 250 fichiers Python depuis la stdlib + site-packages locaux,
déduplique par SHA-256. Re-entraîne → `model_large.json` (mêmes dimensions,
meilleure généralisation).

## Quarantaine (V4) et restauration (P1)

`python3 -m sentinel quarantine <paths...>` déplace les fichiers vers
`./.sentinel-quarantine/` (configurable : `--dest`). Ce défaut relatif
reste le bon choix — y compris lancé depuis `$HOME`, où il se résout en
`$HOME/.sentinel-quarantine` sans `--force`. On ne bascule pas vers
`~/.local/state/sentinel/quarantine` : le CLI, `restore` et ce fichier
documentent déjà le dossier à côté du CWD, et ce nom n'est pas un
répertoire de secrets.

Sur NFS ou SMB, `flock` ne protège pas le journal entre deux clients.
Sentinel le voit (`/proc/mounts` sous Linux, `mount` sous macOS, chemin
UNC ou lecteur réseau sous Windows) et pose en plus un fichier exclusif
(`O_EXCL`). Ce fichier porte le pid, l'instant de démarrage du
processus et, lorsqu'ils existent, le boot id et le machine-id. Deux
machines ou deux conteneurs peuvent partager un hostname. Avec un
machine-id, le verrou est repris si cette identité est celle d'un
processus mort (un pid recyclé a un autre instant de démarrage). Sans
machine-id, le boot id seul ne suffit pas : il faut aussi le hostname
et l'instant de démarrage du pid, sinon le verrou est traité comme
étranger et seul l'âge le reprend.
Tant qu'il est tenu, sa date est rafraîchie. Un verrou d'un autre hôte
expire s'il n'est plus rafraîchi depuis `SENTINEL_HOSTLOCK_STALE_SECONDS`
secondes (86400 par défaut, 24 h). Le message d'attente donne l'hôte,
le pid, l'âge et le chemin exact du fichier `.hostlock`. Pour forcer
la reprise une fois le processus terminé, supprimer ce fichier. Un
disque local garde seulement le verrou du noyau.

Refus **même avec `--force`** (liste dure) :

| Système | Chemins |
|---------|---------|
| Tous | racine de volume (`/`, `C:\`, `D:\`, racine UNC `\\serveur\partage`), le dossier du compte lui-même, `~/.ssh`, `~/.gnupg` |
| macOS | `~/Library/Keychains` |
| Windows | `%USERPROFILE%` (le dossier, pas son contenu), `%USERPROFILE%\.ssh`, `%USERPROFILE%\.gnupg` |

Refus **sans `--force`**, levable avec `--force` (liste souple) :

| Système | Chemins |
|---------|---------|
| Tous | `~/.config` |
| Linux | `/bin`, `/sbin`, `/lib`, `/usr`, `/etc`, `/var`, `/boot`, `/opt`, … |
| macOS | les mêmes, plus `~/Library` (sauf Keychains, déjà dure), `/Library`, `/Applications`, `/System`, `/Volumes`, `/private/etc`, `/private/var` |
| Windows | `%APPDATA%`, `%LOCALAPPDATA%`, `%SystemRoot%` (`C:\Windows`), `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%` |

La comparaison est **insensible à la casse** sur Windows et macOS
(`C:\WINDOWS` = `c:\windows`, `~/.SSH` = `~/.ssh`). Linux reste
sensible : `~/.SSH` n'est pas `~/.ssh`. Sur Windows, chaque chemin
passé aux listes (source, destination, fichier de clé, dossier
temporaire, profil, `%APPDATA%`, …) est d'abord débarrassé d'un
préfixe étendu (`\\?\C:\…` devient `C:\…`, `\\?\UNC\srv\share`
devient `\\srv\share`, y compris `//?/` et la casse mélangée), puis
un realpath et le nom long ``GetLongPathNameW``. Un nom court 8.3
(`C:\Users\RUNNER~1\.ssh`) est donc le même chemin que le profil
long : cette expansion passe par le nom long Windows, pas par une
table lexicale. Avant la comparaison, chaque composant perd ses
points et espaces finaux (`.ssh.` et `.ssh ` sont `.ssh`), et les
flux `::$DATA` et `:$INDEX_ALLOCATION` sont retirés. Tout autre
flux (`fichier:secret`), le préfixe NT `\??\`, et un chemin relatif
à un lecteur (`C:Users\…`, sans `\` après les deux-points) sont
refusés. `\\.\`, `\\?\GLOBALROOT`, `\\?\Volume{GUID}` et les autres
chemins d'objet NT ne se canonisent pas : ils sont refusés. Si le
nom long ne peut pas être obtenu, ou si un parent existe mais n'est
pas lisible, le chemin est refusé. Un chemin UNC dont l'hôte est
cette machine est refusé, ainsi que tout partage dont le nom se
termine par `$` (`\\serveur\C$\…`), même distant : on ne le ramène
pas silencieusement à `C:\`. L'hôte est d'abord normalisé sans DNS :
crochets et point final retirés, casse ignorée, suffixe `.local` et
suffixe DNS de la machine retirés, `*.ipv6-literal.net` décodé
(`0--1.ipv6-literal.net` → `::1`), IPv4 lue comme `inet_aton`
(`127.1`, `0177.0.0.1`, `0x7f000001`, `2130706433`). Sont locaux :
`localhost`, la boucle (`127.0.0.0/8`, `::1`, IPv4 mappée
`::ffff:a.b.c.d` ou traduite `::ffff:0:a.b.c.d`, compatible
`::a.b.c.d`, NAT64 `64:ff9b::/96` et `64:ff9b:1::/48`, 6to4 `2002::/16`
quand l'IPv4 embarquée est locale), `0.0.0.0/8`, `::`, le lien local
(`fe80::/10`, `169.254.0.0/16`), le nom, le FQDN, `COMPUTERNAME`, `.`,
`?`, et toute adresse de cette machine (nom d'hôte, `/proc` sous Linux,
`GetAdaptersAddresses` sous Windows). Si cette liste échoue, le refus
dit pourquoi (`adresses locales indisponibles, nouvel essai dans N s`)
et expire au bout de 60 s : un incident ne bloque pas les hôtes
distants pour toujours. Une saturation du résolveur n'est pas mémorisée
et le message dit `résolveur saturé`, pas « dest critique ». Sinon le
nom est résolu (`socket.getaddrinfo`, au plus 4 fils daemon, un seul
vol par hôte, et un seul calcul des adresses de la machine à la fois).
Le FQDN, ces adresses et la résolution de l'hôte partagent un seul
délai `UNC_DNS_TIMEOUT` de 2 s par appelant : un pas lent ne relance
pas un budget neuf. L'attente d'un créneau et la résolution partagent
ce même délai. Un succès est gardé 5 minutes, un échec 60 secondes.
Un FQDN en échec expire aussi au bout de 60 s ; une saturation du
résolveur n'est pas mémorisée. `GetAdaptersAddresses` parcourt toute
la liste : si elle dépasse la borne de sécurité, le refus est fermé,
sans jeter d'adresses en silence. Si une adresse résolue est locale,
si aucun travailleur n'est libre avant le délai, ou si la résolution
échoue ou expire, le chemin est refusé. Un dossier
qui *contient* le temporaire du processus est souple, pas seulement
le temporaire lui-même — y compris sous une racine connue
(`/tmp/x` quand `TMPDIR=/tmp/x/sub`), jusqu'à cette racine comprise.
Si `$HOME` est *dans* un
préfixe système (`/var/home/…`), seul le préfixe lui-même est souple ;
le reste du compte ne l'est pas. Le dossier temporaire du processus
n'est autorisé que s'il est, **après realpath**, à l'intérieur d'un
emplacement temporaire du système : `/tmp` et `/var/tmp` ; sur macOS
aussi `/private/tmp`, `/private/var/tmp` et `/private/var/folders` ;
sur Windows `%LOCALAPPDATA%\Temp` et `%SystemRoot%\Temp`. `TMPDIR`,
`TEMP` ou `TMP` qui pointent ailleurs (`~/.config`, `~/.ssh`,
`~/.gnupg`, `/etc`, `$HOME`, `/`, `%APPDATA%`, `C:\Windows`, …) ne
donnent **aucune** exemption. La comparaison se fait composant par
composant (`/tmpfoo` n'est pas sous `/tmp`), après résolution des
liens, jonctions et `..`. La racine temporaire elle-même reste
souple, qu'il s'agisse d'une racine connue (`/tmp`,
`%LOCALAPPDATA%\Temp`) ou du dossier exact auquel `TMPDIR`/`TEMP`
aboutit, même s'il est ordinaire : on ne le quarantine pas en entier
sans `--force`. Seul son contenu l'est. Un préfixe sensible niché
dans un vrai temporaire (`~/.ssh`, `~/.config`) garde sa classe. Le
défaut `.sentinel-quarantine` sous le compte reste autorisé.
Un sous-dossier arbitraire du dossier source reste une boucle de scan
et demande `--force`.

Les **sources** suivent les mêmes listes. `quarantine ~/.ssh` est un
refus définitif, même avec `--force`. Un dossier qui *contient* une
zone dure (`/home` contient `~/.ssh`) aussi. `~/.config` ou `/etc`
comme source demandent `--force`. Une destination sticky ou
world-writable (`/tmp` en 1777) est refusée : on ne retire pas le bit
sticky du répertoire partagé. Un dossier déjà existant n'est pas
`chmod` ; seul un dossier créé par cette commande est resserré.

Le bit setuid (SIG-0018) n'existe pas sur Windows : le scan ne le
signale pas, parce que le bit n'est pas posé. Sur Windows, `NUL` est
parfois annoncé comme un terminal ; `--resign` vérifie
`GetConsoleMode` et refuse sans `--yes` si ce n'est pas une console.

Chaque fichier est rendu **non modifiable**. Sur POSIX : chmod 0444
(un dossier passe en 0555 pour rester traversable) et le dossier de
stockage perd l'écriture groupe/autres. Sur Windows, `chmod` ne
protège pas : une ACL est posée. Le compte courant peut lire et
exécuter, et garde `WRITE_DAC`, `DELETE` et `FILE_WRITE_ATTRIBUTES`
pour que `restore` puisse rouvrir le fichier, mais pas
`FILE_WRITE_DATA`. Un ACE deny sur Everyone bloque aussi
`FILE_APPEND_DATA` pour Administrateurs et SYSTEM : un compte admin
ne réécrit pas le fichier via le groupe Administrateurs. Users lit
(comme 0444). Le propriétaire garde `WRITE_DAC` pour `restore`.
L'attribut lecture seule est aussi posé : `DeleteFile` le refuse tant
qu'il est là. Le retirer puis supprimer est l'équivalent POSIX de
l'`unlink` d'un 0444 par le propriétaire du dossier, sans rendre le
contenu modifiable. Un échec d'ACL annule le déplacement. Le mode d'origine
est remis au restore : chmod complet sur POSIX ; sur Windows, seul le
bit d'écriture du propriétaire existe vraiment (attribut lecture seule
+ ACL). Le **manifest JSONL** (`<dest>/manifest.jsonl`, surchargeable
avec `--manifest`) enregistre l'original, le SHA-256, la taille, le mode
d'origine et l'horodatage. Chaque entrée est écrite **immédiatement après
son déplacement** (`append` + `fsync`) : un crash au milieu d'un lot laisse
donc l'audit complet de ce qui a déjà été déplacé, et `restore` peut le
rejouer.

```jsonl
{"original": "/srv/app/x.php", "quarantined": "/srv/q/x.php",
 "sha256": "…", "size": 42, "mode_before": 33188,
 "moved_at": "2026-10-18T12:00:00Z", "_status": "done"}
```

`python3 -m sentinel restore` rejoue l'opération inverse : le SHA-256 du
fichier en quarantaine est **revérifié avant** restauration (un fichier
remplacé ou corrompu est refusé), le `mode_before` est remis, et l'entrée
reste dans le journal marquée `_status: "restored"` + `restored_at`. Le
manifest est donc un journal d'audit complet : on peut répondre à « ce
fichier a-t-il été mis en quarantaine, quand, et quand a-t-il été remis ? ».

**SENTINEL ne supprime jamais**. Un `restore --force` écrase un *fichier*
au chemin d'origine, mais refuse si c'est un dossier.

## Clé HMAC, fichiers sensibles, signature (baseline)

Trois façons de fournir la clé. Une seule à la fois (exit 2 sinon) :

| Source | Rôle |
|--------|------|
| `SENTINEL_KEY` | variable d'environnement, absente de `ps` et de l'historique |
| `--key-file PATH` | fichier lu au démarrage. **Refusé** s'il est lisible par d'autres comptes. POSIX : `chmod 600` (bits groupe/autres). Windows : l'ACL ne doit autoriser que l'utilisateur courant, SYSTEM et Administrateurs. DACL NULL, ACE incomprise ou SID étranger : refus, jamais un succès silencieux |
| `--encrypt-key` | **déprécié** : la valeur reste dans l'historique du shell et la liste des processus. Un avertissement le rappelle. Le drapeau fonctionne encore. |

Avec une clé, le contenu des fichiers devient un HMAC-SHA256 et la baseline
est **signée** (HMAC-SHA256 du JSON canonique, champs `signature` /
`signature_alg`). `encrypted`, `key_check` et `key_hint` sont **dans** le
payload signé : les remplacer casse la signature. `scan` et `watch`
revérifient ce HMAC : s'il ne correspond pas (fichier modifié, hash
recopié, mauvaise clé), **exit 2**.

Une baseline déjà produite, sans signature **et** sans marqueur de clé
(`encrypted`, `key_check`), reste lisible : avertissement « non signée »,
pas d'échec. C'est voulu : retirer `signature`, `encrypted`, `key_check`
et `key_hint` rend le fichier indiscernable d'une ancienne baseline, et
le défaut ne doit pas casser ces fichiers. Retirer `signature` alors
qu'une clé est fournie, ou que ces marqueurs sont encore là, est un
**exit 2** (la vérification ne se contourne pas en effaçant les champs).
Sans clé au moment du `scan` ou du `watch`, une baseline **signée**
échoue aussi (exit 2) : on ne peut pas distinguer un document intact
d'un document retouché. `--allow-unverified-baseline` est l'opt-out
explicite : le chargement continue avec l'avertissement « signature
non vérifiée ».

`--require-signed` (`scan` et `watch`) inverse le défaut pour les
baselines non signées : **exit 2**, message explicite. La variable
`SENTINEL_REQUIRE_SIGNED` fait la même chose si elle vaut `1`, `true`
ou `yes` (casse ignorée, espaces extrêmes ignorés). Toute autre valeur,
ou l'absence de la variable, laisse l'avertissement. Sans `--baseline`,
le drapeau n'a rien à vérifier. Une baseline illisible sous cette
politique est aussi un exit 2 (on ne peut pas prouver qu'elle était
signée), même sans `--strict`.

**Précédence.** `--require-signed` et `--allow-unverified-baseline`
passés ensemble sur la ligne de commande sont une **erreur (exit 2)** :
les deux drapeaux se contredisent, le scan ne démarre pas.
`SENTINEL_REQUIRE_SIGNED` n'est pas un second drapeau que l'on
négocierait : si elle est active, `--allow-unverified-baseline` est
**ignoré** (avertissement), y compris pour une baseline signée sans clé.
L'environnement ne désactive pas un `--require-signed` explicite. Une
baseline signée dont la clé est fournie et la signature valide reste
acceptée.

### Resignature (`baseline --resign`)

`python3 -m sentinel baseline --resign baseline.json` ajoute (ou
rafraîchit) `signature` / `signature_alg` **sur le document déjà écrit**.
Les entrées ne sont pas régénérées, le contenu n'est pas chiffré : une
baseline en clair le reste. La clé vient de `SENTINEL_KEY` ou
`--key-file` ; `--encrypt-key` fonctionne encore et affiche le même
avertissement de dépréciation. Sans clé : **exit 2**, fichier intact.

Avant d'écrire, l'outil compare le JSON aux fichiers actuels du champ
`root` et affiche ajouts, suppressions, contenus modifiés, modes,
propriétaires et capabilities. Une liste vide veut dire « le JSON
colle à l'arbre », pas « le JSON n'a jamais été édité », et encore
moins « l'arbre est sain ». Il demande alors une confirmation
(`y`, `yes`, `oui`). Si stdin n'est pas un TTY, il **refuse** sauf
`--yes`. `--backup` copie l'original vers `<fichier>.bak` puis
remplace le JSON via un fichier temporaire et `os.replace` (pas de
baseline à moitié écrite).

Si le fichier est **déjà signé**, la signature est vérifiée avec la clé
**avant** ce diff et avant toute écriture. Un décalage (document
retouché, mauvaise clé) est un exit 2 : `--yes` ne relave pas une
signature invalide. `--trust-unsigned` n'est pas demandé. Le dossier
positionnel et `--out` ne se combinent pas avec `--resign` (la racine
est celle du JSON, la sortie est le même fichier).

**Baseline non signée.** Ce cas est une confiance initiale. Une
baseline dont on a retiré `signature`, `encrypted`, `key_check` et
`key_hint`, puis recopié le hash d'un fichier déjà modifié, est
indiscernable d'une baseline saine qui décrit le même arbre : le diff
est vide, et régénérer avec `baseline` certifierait le même état
compromis. `--resign` ne prétend pas le détecter. `--yes` seul est
refusé (exit 2). Il faut `--trust-unsigned`. L'avertissement, y
compris dans l'invite interactive, dit de ne le faire que pour une
baseline générée soi-même sur un système connu sain. En cas de doute,
**régénérez** avec `baseline <dossier> --out …` depuis cet état, plutôt
que de resigner.

La resignature pose alors `resigned_from_unsigned: true` et
`resigned_at` (horodatage UTC) **dans** le payload signé. Les modifier
casse la signature. `scan` et `watch`, une fois la signature vérifiée,
affichent un avis : cette baseline vient d'une confiance initiale.

`key_check` permet toujours de répondre « mauvaise clé » (exit 2) avant
même de parler de signature. Les nouvelles baselines conservent les empreintes SHA-256 des clés publiques de `authorized_keys` (jusqu'à 64 Kio), y compris avec une clé HMAC. SIG-0019 peut ainsi comparer les clés sans conserver les lignes ou commentaires. Ces empreintes révèlent toutefois si une clé publique connue est présente : protégez la baseline. Les anciennes baselines et les fichiers plus grands restent sans cet historique.

Sans clé, les petits fichiers ordinaires gardent leur contenu (SIG-0019
peut comparer). Les fichiers évidemment sensibles ne l'embarquent plus,
seulement leur SHA-256 : clé privée (marqueurs SIG-0008, quel que soit le
nom), `authorized_keys`, `id_rsa` et équivalents, `.pem` / `.key`, `.env`.
Pour `authorized_keys` jusqu’à 64 Kio, les empreintes des clés permettent à SIG-0019 de fonctionner sans conserver le contenu. Pour les anciennes baselines sans empreintes, la limite est annoncée. SIG-0007 continue de voir les clés présentes dans le fichier
actuel. Un `.env.example` / `.env.sample` / `.env.template` n'est pas traité
comme un secret par son nom.

## Surveillance temps réel (V4)

`python3 -m sentinel watch <dossier>` tourne en boucle :

- Si `watchdog` est installé : surveillance événementielle (FSEvents sur
  macOS, inotify sur Linux). Quasi-instantanée.
- Sinon : polling sur le même parcours que le scanner,
  `os.walk(onerror=…)`. Un dossier illisible (mode 000, par exemple)
  n'est plus avalé en silence : il est listé, avec la mention
  « illisible » / exit 3, et la commande `watch` **sort 3** si au moins
  un chemin l'a été. Les symlinks sont ignorés, comme au scan. Sur
  Windows, les jonctions et les autres points de reparse le sont aussi.

Contrôle de contenu du polling (mtime restauré + même taille) :

- fichier ≤ 8 Mio : SHA-256 en flux **à chaque tour**. Un fichier de
  2 Mio modifié puis remis à la même taille et au même mtime est vu au
  tour suivant ;
- fichier plus gros : empreinte échantillonnée (64 Kio en tête, au milieu
  et en queue) à chaque tour. Le SHA-256 complet est planifié **par
  fichier** (au plus 10 instantanés depuis le dernier hash de ce
  fichier), et ce hash est recopié sur les tours qui ne le recalculent
  pas. Une modification entre les trois fenêtres est donc vue au
  prochain hash complet de ce fichier, même si un autre fichier a
  changé entre-temps (ce changement ne remet pas le compteur à zéro et
  ne jette pas le dernier hash). On ne relit pas un disque entier à
  chaque tick.

À chaque changement, un scan complet est lancé, son rapport imprimé
sur stdout. Ctrl-C / SIGTERM pour arrêter. `--baseline` est vérifiée
comme pour `scan` (signature HMAC, exit 2 si elle ne correspond pas,
`--require-signed` et `SENTINEL_REQUIRE_SIGNED` compris).

## Comportement par système

Les contrôles de sécurité ne passent pas en silence hors Linux. S'ils
ne peuvent pas s'exécuter, ils échouent fermés (message, exit non nul).

| Contrôle | Linux | macOS | Windows |
|----------|-------|-------|---------|
| Fichier de clé | mode `0600` (refus si groupe ou autres peuvent lire) | identique à Linux | ACL via `ctypes` (pas d'`icacls` externe). Utilisateur courant + SYSTEM + Administrateurs seulement |
| Liens | symlink, non suivi par défaut (`scan`, `train`, quarantaine, restore, baseline) | identique | symlink **et** jonction / point de reparse (`FILE_ATTRIBUTE_REPARSE_POINT`). Un placeholder cloud n'est pas lu |
| Quarantaine, chemins | listes ci-dessus, casse respectée | mêmes listes + Keychains / `/System` / `/Library` / `/Applications`, casse ignorée | `%USERPROFILE%`, `%APPDATA%`, `C:\Windows`, Program Files, racines de lecteur, casse ignorée |
| Quarantaine, verrou | `0444` / `0555`, dossier sans écriture groupe/autres | identique | ACL sans `FILE_WRITE_DATA` pour le compte courant ; `WRITE_DAC` conservé pour le restore |
| Propriétaire | uid/gid | uid/gid | uid/gid stockés `None` (ils valent toujours 0). Le SID (`owner`) est comparé |
| Capabilities | `getcap` si présent | `None` : contrôle non fait, pas « aucune capability » | identique à macOS |
| setuid (SIG-0018) | bit Unix | bit Unix | le bit n'existe pas ; rien à signaler |

`os.path.normcase` ne plie pas la casse sur macOS. La comparaison des
listes de quarantaine passe par `str.casefold` sur Windows et macOS
seulement.

## Interface bureau

Le moteur reste la bibliothèque standard. L'interface est un extra :

```bash
pip install -e ".[gui]"          # PySide6
pip install -e ".[gui,keyring]"  # + trousseau système, optionnel
sentinel-gui                     # ou : python -m sentinel.gui
```

Pages : tableau de bord (dernier scan, baseline présente / signée /
vérifiée / resignée depuis une baseline non signée, surveillance),
analyse (dossiers, progression, tableau filtrable et triable, export
JSON et SARIF, ouvrir le dossier), intégrité (créer, voir les écarts,
resigner — la case de confiance reprend `--trust-unsigned`, elle est
recochée à chaque changement d'état, et un dialogue montre les écarts
avant d'écrire), quarantaine
(journal, restauration après confirmation), surveillance (démarrage /
arrêt, icône de barre quand la session en a une). Les travaux longs
tournent dans un `QThread` ; Annuler interrompt le scan et la création
de baseline. La classification d'un dossier ou d'une quarantaine
(hôte UNC compris) passe aussi par un `QThread` : le thread Qt ne
résout pas de nom. Fermer la fenêtre pendant une quarantaine est
refusé : le déplacement n'est pas coupé. La ranger dans la barre ne
fige pas l'interface et n'abandonne pas un dossier en cours de
classement. Quitter (menu, Ctrl+C, ou SIGTERM) pendant une quarantaine
laisse la boucle d'événements vivante et montre « Fermeture après la
fin de la mise en quarantaine… ». « Forcer la fermeture » demande
confirmation : un fichier peut rester à moitié déplacé. Un second
Quitter pendant cette attente ouvre la même confirmation. La sortie
réelle attend au plus 2,5 s les classements de dossiers encore en
cours, puis quitte le processus (`os._exit`) s'il en reste, après
avoir vidé le journal de quarantaine (flush et fsync), les réglages,
les journaux et les sorties standard. Qt ne détruit pas un fil encore
vivant. Un classement de dossier périmé est ignoré. Quitter (menu,
Ctrl+C ou SIGTERM) pendant l'attente du verrou — restauration ou reprise
au démarrage — n'attend pas ce délai : l'attente est annulée, le fil est
joint, le journal n'est pas modifié, et l'interface dit que l'opération
a été interrompue.

La clé HMAC n'est pas écrite dans les réglages Qt. Elle reste en
mémoire pour la session. Si `keyring` est installé, un dialogue propose
le trousseau (service `sentinel`, entrée `hmac`). Sans `keyring`, ou
s'il échoue, on redemande la clé à la prochaine session.

Dossier d'état (dernier scan seulement) : `$XDG_DATA_HOME/sentinel` ou
`~/.local/share/sentinel` sur Linux, `~/Library/Application Support/Sentinel`
sur macOS, `%LOCALAPPDATA%\Sentinel` sur Windows.

Les chemins proposés au scan sont le dossier du compte et, s'ils
existent, Bureau, Documents, Téléchargements. On ne propose pas `/` ni
`C:\`. Un chemin de la liste dure ou souple affiche un avertissement ;
le scan reste permis (inspecter `/etc` est un usage normal), la
quarantaine vers cet endroit non.

### Empaquetage

```bash
pip install -e ".[gui,bundle]"
python packaging/build.py
```

Le spec est `packaging/sentinel.spec`. Résultat : `dist/Sentinel.app`
sur macOS, `dist/sentinel/sentinel` sur Linux, `dist/sentinel/sentinel.exe`
sur Windows. Le workflow `.github/workflows/package.yml` fait la même
chose à la demande (`workflow_dispatch`) et dépose des artefacts non signés.
Il ne lit aucun secret Apple.

Sur macOS, la signature Developer ID et la notarisation se font sur le
Mac du mainteneur, pas dans GitHub Actions. Le pas à pas (certificat dans
Xcode, mot de passe d'application, profil notaire `sentinel-notary`, à
quoi ressemble une réussite) est
[docs/signature-macos.md](docs/signature-macos.md) :

```bash
python packaging/build.py --check
python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize
```

Sans `--sign`, le binaire reste non signé.

Tests de l'interface (ignorés sans PySide6 ; la suite `unittest` n'en
dépend pas) :

```bash
QT_QPA_PLATFORM=offscreen python -m pytest tests/test_gui.py -q
```

## Tests

```bash
python3 -m unittest discover -s tests
ruff check sentinel/ tests/ && ruff format --check sentinel/ tests/
mypy
```

La CI (`.github/workflows/ci.yml`) lance cette suite à **chaque push**
et sur chaque pull request : Ubuntu (Python 3.10 à 3.13), macOS et
Windows (3.12), plus un job GUI sur les trois OS
(`QT_QPA_PLATFORM=offscreen`). Un test n'est sauté que si l'OS ne peut
pas produire l'objet (jonction, DACL, privilège). Les décisions de
chemins et d'ACL sont testées partout, y compris la casse Windows et
macOS depuis Linux.

La suite couvre : scan vide, 19 règles × fixtures, heuristique V2,
autoencodeur V3, **règles augmentées V4** (RuleContext, SIG-0017/0018/0019
unitaires + end-to-end), quarantaine, watch (snapshot/diff/polling),
intégrité (added/removed/modified/mode_changed), trainset large (non-régression),
les non-régressions de la V4 (CLI `quarantine`, dossiers 0555, manifest
cumulatif, exclusion `__pycache__`, horodatage UTC), les angles morts P0,
les garde-fous P1-P3, les non-régressions V5 (`tests/test_v5_fixes.py`),
`--require-signed` / `SENTINEL_REQUIRE_SIGNED`, `baseline --resign`,
la parité Windows/macOS (`tests/test_platform_parity.py`) et les
services de l'interface (`tests/test_gui_services.py`).

## V5 — corrections de bugs (2026-10-18)

Trouvés en exécutant l'outil, pas seulement la suite de tests :

- **Numéros de ligne faux après normalisation.** `\n` échappé et base64
  décodé pouvaient ajouter des lignes au texte analysé : un fichier de
  3 lignes en produisait 5, et tous les findings suivants pointaient à
  côté (décalage choisi par l'attaquant). L'invariant 1 ligne → 1 ligne
  est désormais respecté (les sauts de ligne décodés deviennent des espaces).
- **Préfiltres désynchronisés des regex.** SIG-0002 ratait `nc.exe` et
  `nc\t-e` ; SIG-0017 ratait la forme réelle `ExecStart=… "curl -s URL | sh"`
  (les keywords étaient `curl|sh`, pipe collé). Une unité systemd dropper
  n'était donc pas vue par la règle systemd.
- **Baseline V1 → `owner_changed` sur tous les fichiers.** uid/gid absents
  étaient comparés à 0. La comparaison est ignorée quand un côté ne les
  connaît pas.
- **`chown` / `setcap` sortaient en exit 0.** `owner_changed` et
  `cap_changed` entrent dans `exit_code` : une CI ne peut plus valider
  silencieusement une escalade.
- **`scan --encrypt-key` était un drapeau mort** et SIG-0019 disparaissait
  sans un mot sur une baseline chiffrée. La clé est maintenant vérifiée
  (`key_check`, exit 2 si fausse) et la désactivation de SIG-0019 est
  annoncée.
- **Manifest de quarantaine écrit après tout le lot** : un crash perdait
  l'audit des fichiers déjà déplacés. Écriture entrée par entrée.
- **`restore` effaçait le journal** et restaurait un fichier de
  quarantaine corrompu sans vérifier son SHA-256. Le journal est conservé
  (`_status: restored`) et le hash est vérifié avant restauration.
- **Findings filtrés invisibles** : `ignored_findings` apparaît maintenant
  dans le JSON, en résultats *supprimés* dans le SARIF, et en résumé dans
  le texte.
- **Fichiers volumineux lus en RAM** pour le SHA-256 (`read_bytes()` sur
  chaque fichier) : hachage en flux de 1 MB.
- **Symlink re-ciblé invisible** : la cible (`link_target`) entre dans la
  baseline, un re-ciblage ressort en `modified`.

## Démonstrations

| Fichier                       | Mode   | Sortie                                                              |
|-------------------------------|--------|---------------------------------------------------------------------|
| `demo_report.{txt,json}`      | V1     | 28 findings                                                         |
| `demo_v2_report.{txt,json}`   | V2     | 38 findings + heuristique                                           |
| `demo_v3_report.{txt,json}`   | V3     | 38 findings + autoencodeur (modèle 6 fichiers)                      |
| `demo_v3_large_report.*`      | V3     | idem, modèle `model_large.json` (250 fichiers)                      |
| `demo_v4_report.{txt,json}`   | V4     | SIG-0017 + SIG-0018 + SIG-0019 (généré par `tools/make_demo_v4.py`) |

## Limites connues

- Binaire détecté par octet NUL ou > 30 % d'octets inhabituels.
- SIG-0007/0014/0015 dépendent du nom de fichier (`authorized_keys`, `.bashrc`, `sudoers`).
- SIG-0016 ignore `/var/tmp` ; SIG-0009 ignore les lignes `#` et les fences Markdown.
- Score d'anomalie (V2 ou V3) n'influe **jamais** sur l'exit code.
- `watch` surveille les fichiers (événements ou polling) ; il ne surveille ni le réseau ni les processus. La quarantaine est une action manuelle, pas une protection automatique.
- Trainset V3 dépendant d'un corpus d'entraînement : sans `--model` ou
  avec un modèle absent, fallback heuristique (annoté `autoencoder:untrained`).
- V4 : `watchdog` est *optionnel* ; sans, fallback polling (intervalle ≥ 1 s
  recommandé ; le défaut CLI est 2 s).
- La baseline JSON embarque le contenu des fichiers **non sensibles** ≤ 64 KB
  pour SIG-0019. Au-delà, ou si le fichier est sensible (clé, `authorized_keys`,
  `.env`, …), ou si la baseline est chiffrée : pas de clair. Les nouvelles baselines conservent les empreintes de clés publiques pour `authorized_keys` jusqu’à 64 Kio ; les anciennes baselines sans empreintes ne permettent pas cette comparaison. Pas de relecture du fichier actuel comme historique.
- `train` ignore les symlinks par défaut (même politique que `scan`),
  ainsi que les jonctions et points de reparse Windows.
  `--follow-links` ne suit une cible que si elle reste dans le corpus,
  et ne descend pas dans un répertoire qui est lui-même un lien.
- Les modes Unix exacts (`0644`, `0755`) n'existent pas sur Windows :
  l'attribut lecture seule et l'ACL portent l'écriture. `restore` remet
  le bit d'écriture du propriétaire, pas les autres bits. Supprimer un
  fichier de quarantaine demande de retirer l'attribut lecture seule ;
  l'ACL continue de refuser `FILE_WRITE_DATA`.
- `getcap` n'est pas un « aucune capability » hors Linux : le champ
  reste absent.
- L'interface ne démarre pas sans l'extra `[gui]`. `sentinel` (CLI) n'en
  a pas besoin. Les binaires PyInstaller ne sont pas signés tant que
  `python packaging/build.py --sign … --notarize` n'est pas lancé sur un
  Mac (voir [docs/signature-macos.md](docs/signature-macos.md)). Ils
  n'embarquent pas `keyring` sauf si l'environnement de build l'a
  installé.
- Le polling de `watch` ne garantit pas le tour suivant pour une modification
  hors des fenêtres d'échantillon d'un fichier > 8 Mio (rattrapage ≤ 10
  instantanés de ce fichier, dernier hash complet conservé).
- `mypy` est un outil de dev (pas une dépendance de production). Il type le
  paquet `sentinel/` en Python 3.10+. `requires-python` est `>=3.10`.

Spécification détaillée : `SPEC.md`.

## Couverture et triage des alertes

Les rapports texte, JSON et SARIF présentent la couverture des signatures :
`scanned_files` compte les fichiers texte lus jusqu'au bout ; `binary_files`
liste ceux reconnus comme binaires ; `unreadable_paths` contient les chemins
illisibles ; `disappeared_files` les fichiers disparus pendant le scan.
`excluded_entries` liste les éléments volontairement écartés (par exemple
`__pycache__` et les liens non suivis). Un dossier exclu compte pour **une
entrée** : le nombre de fichiers qu'il contient n'est pas connu. Les dossiers
illisibles représentent aussi des sous-arbres de taille inconnue. Ces comptes
ne mesurent pas la couverture des menaces. L'interface affiche ce résumé et
les conseils de triage au survol d'une alerte.

Chaque alerte inclut un extrait déclencheur, une limite d'interprétation et
une vérification conseillée. Ces indications aident au triage et ne prouvent
pas qu'un fichier est malveillant.

Pour écarter un seul constat lors d'un scan CLI, copiez sa valeur
`suppression_fingerprint` depuis le rapport et ajoutez une ligne dans le
fichier passé à `--ignore-file` (par défaut `.sentinelignore` dans le dossier
courant) :

```text
FINGERPRINT <empreinte-hexadécimale-de-64-caractères> Exemple de test vérifié 2026-10-27
```

La justification est obligatoire. L'empreinte dépend de la règle, du chemin,
de la ligne, du message, de l'extrait et d'un hash de la ligne complète : si
ces éléments changent, l'alerte doit être réexaminée. Les alertes filtrées et
leur motif restent dans les rapports texte, JSON et SARIF. Les anciennes
règles d'exclusion par motif restent utilisables. Ce filtre est appliqué par
la commande `scan` ; l'interface ne lit pas encore `.sentinelignore`.

## Interpréter les résultats

Les signatures ne couvrent pas tous les logiciels malveillants et les binaires
sont ignorés par l'analyse de contenu. Des exemples ou commentaires peuvent
aussi déclencher des alertes : vérifiez le contexte avant une quarantaine.
Les scores heuristiques et neuronaux ne sont pas des probabilités de menace ;
aucune mesure indépendante de leur précision n'est fournie. Évaluez-les sur
un corpus séparé de l'entraînement, étiqueté et représentatif, avec faux
positifs et faux négatifs, avant de fixer un seuil opérationnel.

Créez la baseline depuis un état vérifié et protégez-la ainsi que sa clé ;
une signature prouve l'intégrité de la baseline, pas la propreté initiale du
système. Pour refuser une baseline non signée, utilisez `--require-signed`.
