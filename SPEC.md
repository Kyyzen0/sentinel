# SPEC — SENTINEL

Spécification du scanner de sécurité local orienté fichiers.

## Vue d'ensemble

SENTINEL prend en entrée un répertoire et produit un rapport contenant :

1. **Findings** : détections déterministes issues de règles (signatures).
2. **Anomalies** : score 0..100 par fichier (V2 heuristique ou V3 neuronal).
3. **Integrity diff** : différence d'intégrité vs une baseline optionnelle.

V1 et V2 sont strictement en lecture seule, sans réseau, en bibliothèque
standard. V3 ajoute un autoencodeur neuronal implémenté **en Python pur**
(toujours sans dépendance externe) pour vraiment tenir la promesse « Neuronal ».

## CLI

```
python3 -m sentinel <commande> [args]

baseline <folder> --out baseline.json         V1 : crée une référence d'intégrité
            [--key-file PATH]                clé HMAC (fichier chmod 600)
            [--encrypt-key …]                DÉPRÉCIÉ (historique / ps) ; SENTINEL_KEY aussi
baseline --resign <baseline.json>            signe le JSON en place (clé obligatoire)
            [--yes] [--backup]               --yes si stdin n'est pas un TTY ;
                                             --backup → <fichier>.bak
            [--trust-unsigned]               obligatoire si le JSON n'est pas signé
            [--key-file PATH]
scan <folder> [--baseline f.json]            V1 : scan signatures [+ intégrité]
            [--anomaly]                      V2 : ajoute le score d'anomalie
            [--top N]                        (top N dans le rapport texte, défaut 10)
            [--neural --model model.json]    V3 : remplace l'heuristique par l'autoencodeur
            [--format text|json]             (défaut text)
            [--require-signed]               refuse une baseline non signée (exit 2)
            [--allow-unverified-baseline]    baseline signée sans clé : avertissement
train <folder> --out model.json              V3 : entraîne l'autoencodeur et sauvegarde les poids
            [--epochs N] [--lr X] [--seed N]
            [--follow-links]                 symlinks : ignorés par défaut ;
                                             avec le drapeau, cible hors corpus refusée
quarantine <paths...>                        V4 : déplace les fichiers dans une
            [--dest <dir>]                  zone de quarantaine read-only et
            [--manifest <f.jsonl>]          écrit un manifest JSONL (append par entrée)
            [--force]
restore                                      P1 : rejoue l'inverse (hash vérifié,
            [--manifest <f.jsonl>]          mode_before restauré, journal conservé)
            [--dest <dir>] [--force] [--only ...]
watch <folder>                               V4 : surveillance temps réel
            [--interval S] [--baseline f.json]
            [--anomaly] [--neural --model model.json]
            [--max-iterations N]
            [--require-signed]
            [--allow-unverified-baseline]    même politique que scan
```

Codes de sortie :
- `0` — rien à signaler (pas de findings, pas de modifications)
- `1` — au moins un finding OU une modification d'intégrité
- `2` — erreur (commande inconnue, dossier introuvable, etc.)
- `3` — couverture incomplète : au moins un fichier ou dossier illisible. Prioritaire sur `1` (les findings restent dans le rapport). `watch` utilise le même code si le polling (ou watchdog) a vu un chemin illisible. `scan` et `watch` sortent **2** si la signature HMAC de la baseline ne correspond pas, si une baseline signée est chargée sans clé (sauf `--allow-unverified-baseline`), ou si `--require-signed` / `SENTINEL_REQUIRE_SIGNED` refuse une baseline non signée ou illisible. `baseline --resign` sort **2** sans clé, sans confirmation, si une signature existante ne correspond pas, ou si une baseline non signée est resignée sans `--trust-unsigned` (`--yes` ne suffit pas).

Le score d'anomalie ne change **jamais** l'exit code à lui seul.

## Modèle de données

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str  # "SIG-0001" … "SIG-0016"
    severity: str  # "critical" | "high" | "medium" | "low"
    path: str  # chemin relatif POSIX par rapport à la racine scannée
    line: int  # numéro de ligne 1-indexé
    message: str  # description en français
    evidence: str  # extrait déclencheur (tronqué, ≤ ~50 chars)


@dataclass(frozen=True)
class AnomalyScore:
    path: str
    score: float  # 0..100
    entropy: float  # Shannon, 0..8
    max_line_len: int
    nonprintable_ratio: float  # 0..1
    shell_metachar_ratio: float  # 0..1
    avg_line_len: float
    method: str  # "heuristic" | "autoencoder" | "autoencoder:untrained"


@dataclass
class IntegrityDiff:
    added: list[str]  # fichiers présents maintenant mais pas dans la baseline
    removed: list[str]  # fichiers présents dans la baseline mais plus maintenant
    modified: list[str]  # hash ou taille changés
    mode_changed: list[str]  # bits de permission changés (mode 0o7777)
```

## Règles de signature

16 règles au total. Chaque règle expose `scan(rel_path, text) -> Iterable[Finding]`.

| ID        | Sévérité | Déclencheur résumé                                                 |
|-----------|----------|--------------------------------------------------------------------|
| SIG-0001  | critical | Web shell PHP : `eval(base64_decode(`, `eval($_GET…)`, `system($_GET…)` etc. (fichiers `.php`/`.phtml`/`.php5`/`.php7`) |
| SIG-0002  | critical | Reverse shell : `bash -i`, `/dev/tcp/`, `nc -e`, `ncat` en contexte de commande, `socat … exec:` |
| SIG-0003  | high     | Téléchargement puis exécution : `curl URL \| sh`, `wget URL \| bash`, `python -c 'import urllib; exec(…)'`. **Première commande de la ligne uniquement** — pas après `&&`, `||`, `;`, ni dans une sous-shell `(…)`. |
| SIG-0004  | high     | Charge encodée : `base64 -d … \| sh`, `eval(atob(`, `powershell -enc` |
| SIG-0005  | high     | Minage : `stratum+tcp`, `xmrig`, `minerd`, `--donate-level`, `cryptonight` |
| SIG-0006  | high     | Cron persistant : ligne `@reboot <commande>`, ou cinq champs `*\|*/N` suivis de `curl`/`wget`/`nc` |
| SIG-0007  | high     | Clé SSH dans un fichier nommé `authorized_keys` (préfixes `ssh-ed25519`, `ssh-rsa`, `ssh-dss`, `ecdsa-sha2-`) |
| SIG-0008  | critical | Clé privée en clair : RSA, OpenSSH, **EC** (V2), **PKCS#8** (V2) |
| SIG-0009  | medium   | Injection shell : `$(curl\|wget\|…)`, `` `curl\|wget` ``, `;rm -rf`, `&& curl`, `; curl`. Ignore les lignes `#`, les fences Markdown (` ``` ` / ` ```sh `) et les balises inline courtes (`` `sh` ``, `` `bash` ``). |
| SIG-0010  | medium   | User-Agent d'outil d'attaque (`sqlmap`, `nikto`, `nmap`, `wpscan`, …) |
| SIG-0011  | critical | Web shell JSP/ASP (V2) : `<% … Runtime.exec(`, `<% … .execute(Request…)`, `<% … eval(request…)` dans des fichiers `.jsp`/`.asp`/`.aspx` |
| SIG-0012  | critical | Log4Shell : `${jndi:` n'importe où |
| SIG-0013  | high     | `.htaccess` : `php_value auto_prepend_file`, `php_value auto_append_file`, `AddType\|AddHandler\|SetHandler application/x-httpd-php` |
| SIG-0014  | high     | Persistance shell utilisateur : fichier nommé `.bashrc`/`.profile`/`.zshrc`/`.bash_profile` contenant `curl`/`wget`/`nc`/`eval`/`base64`/`python`/`perl` |
| SIG-0015  | high     | `passwd` : `:[01]:0[01]?:` (UID 0 ajouté) ; `sudoers`/`sudoers.d/` : `NOPASSWD: ALL` ou `ALL=(ALL)` |
| SIG-0016  | medium   | `LD_PRELOAD`/`LD_LIBRARY_PATH` pointant vers `/tmp` (mais pas `/var/tmp`) |

## Détection de binaire

Un fichier est considéré binaire (et donc ignoré par les signatures) si :

- il contient un octet NUL, **ou**
- plus de 30 % des octets sont en dehors de `[\t\n\r]` ET hors
  `[0x20..0x7E]` ET hors `0x80+` (UTF-8 accepté mais compté comme
  « inhabituel »).

Limite V2 : un texte très accentué peut être pris pour binaire.

## Intégrité (V1)

Chaque fichier d'un dossier produit un `Entry{path, sha256, size, mode}`.
Le diff compare :

- `added` : présent maintenant, absent de la baseline
- `removed` : absent maintenant, présent dans la baseline
- `modified` : `sha256` ou `size` différents
- `mode_changed` : bits de permission (mode & 0o7777) différents

## Anomalie V2 (heuristique)

Quatre features par fichier :

```
entropy         = Shannon(text sample, base 2)            ∈ [0, 8]
max_line_len    = max(len(line))                          ∈ N
nonprintable_ratio = nb(c < 0x20 hors \t\n\r) / n        ∈ [0, 1]
shell_metachar_ratio = nb(c ∈ "|&;`\\$<>(){}") / n        ∈ [0, 1]
avg_line_len    = mean(len(line))                         ∈ R+
```

(sortie texte échantillonnée à 200 000 caractères max pour le coût)

Score :

```
score = 100 × clamp01(
    0.50 × min(1, entropy/8)
  + 0.30 × min(1, max_line_len/800)
  + 0.10 × nonprintable_ratio
  + 0.10 × shell_metachar_ratio
)
```

## Anomalie V3 (autoencodeur neuronal)

Vecteur de 8 features par fichier (toutes clampées dans `[0, 1]` sauf
cas limites) :

```
0. log10(taille) / 6
1. entropy / 8
2. max_line_len / 500
3. avg_line_len / 100
4. nonprintable_ratio
5. shell_metachar_ratio
6. digits_ratio      (nb(c.isdigit()) / n)
7. uppercase_ratio   (nb("A" <= c <= "Z") / n)
```

Architecture :

```
        8 → 6 (ReLU) → 4 (tanh) → 6 (ReLU) → 8 (linear)
```

Forward : `_tensor.py` (mat_vec + activations). Backprop : implémenté à la main
dans `neural.py`. Adam (β₁=0.9, β₂=0.999, eps=1e-8), lr par défaut `5e-3`.

Loss : MSE entre l'entrée et la reconstruction.

Score : `100 × MSE / max_score`, où `max_score = 5 × pire perte finale sur
le trainset`. Cela place les fichiers du trainset entre 0 et ~20 (saturant
à 100 dès qu'on s'en écarte significativement).

Persistance du modèle (JSON) : poids `W1, b1, W2, b2, W3, b3, W4, b4` (matrices
et vecteurs imbriqués) + `max_score` + `version`. Le `load()` reconstitue
un état strictement équivalent (test roundtrip `places=4`).

Sans modèle (ou `model_path` invalide), `score_autoencoder` retombe sur
l'heuristique V2 et marque `method = "autoencoder:untrained"` dans le JSON.

## Décisions de TDD

Tous les comportements publics sont couverts par 74 tests unitaires
(`python3 -m unittest discover -s tests`). L'ajout d'une 20e règle
demande :

1. un test qui échoue (RED),
2. l'implémentation du détecteur (GREEN),
3. un refactor éventuel.

## V4 — extensions

### Règles augmentées (RuleContext)

Les signatures de V1-V3 ne prenaient que `(rel_path, text)`. À partir
de V4, l'interface `Rule.scan` accepte un troisième paramètre `context:
RuleContext | None` qui porte :

- `file_mode: int | None` — `st_mode` du fichier scanné
- `baseline_text: str | None` — contenu du même fichier dans la
  baseline (None si absent ou si la baseline n'est pas fournie)
- `baseline_mode: int | None` — mode du même fichier dans la baseline

Les règles qui n'utilisent pas le contexte l'ignorent simplement.

### Baseline V2 (contenu embarqué)

`make_baseline` produit un JSON `version: 2` qui inclut, pour chaque
fichier de taille ≤ 64 KB, le **contenu UTF-8** au moment de la
baseline. Cela permet à `load_baseline_text` de comparer le contenu
actuel au contenu historique SANS dépendre du dossier source (qui
peut être détruit ou injoignable). **Pas de fallback disque** : au-delà
de 64 KB (ou si le contenu est absent, ou si la baseline est chiffrée),
`load_baseline_text` retourne `None` et le scanner annonce la dégradation —
lire le fichier actuel donnerait une comparaison « fichier vs lui-même »
faussement rassurante.

Avec une clé (`SENTINEL_KEY`, `--key-file`, ou `--encrypt-key` déprécié),
la baseline ne contient plus que `hmac_sha256 = HMAC-SHA256(clé, contenu)`
et un `key_check = HMAC-SHA256(clé, "sentinel-key-check-v1")` qui permet
de valider la clé fournie à `scan` / `watch` (exit 2 si elle ne correspond
pas). Un HMAC n'étant pas réversible, les règles dépendant du contenu
historique (SIG-0019) sont désactivées sur une baseline chiffrée, et le
scan le dit explicitement.

La même clé **signe le document** : `signature` est le HMAC-SHA256 de la
clé sur le JSON canonique (`sort_keys`, séparateurs compacts) **sans** les
champs `signature` et `signature_alg`. `encrypted`, `key_check` et
`key_hint` restent dans ce payload : les échanger sans recalculer le HMAC
est un exit 2. Recopier le nouveau sha256 d'un fichier modifié dans le
JSON sans la clé casse cette signature : `scan` et `watch` sortent 2.
Retirer `signature` / `signature_alg` aussi, dès qu'une clé est fournie
ou que `encrypted` / `key_check` est encore présent. Une baseline
ancienne, sans signature et sans ces marqueurs, est chargée avec un
avertissement (pas d'exit 2). Ce défaut reste : un document dont on a
retiré `signature`, `encrypted`, `key_check` et `key_hint` est
indiscernable de cette ancienne baseline. Sans clé face à une baseline
signée : **exit 2** (message explicite). `--allow-unverified-baseline`
sur `scan` et `watch` rétablit l'avertissement « signature non
vérifiée » et laisse le chargement continuer.

`--require-signed` (`scan`, `watch`) et `SENTINEL_REQUIRE_SIGNED`
(`1` / `true` / `yes`, casse ignorée) refusent cette baseline non
signée (exit 2). Une baseline signée sans clé reste un exit 2, et
`--allow-unverified-baseline` ne contourne pas la politique :

- les deux drapeaux passés ensemble → exit 2 immédiat (ils se
  contredisent ; le scan ne démarre pas) ;
- variable d'environnement active + `--allow-unverified-baseline` →
  la variable l'emporte, le drapeau est ignoré (avertissement), exit 2
  si la baseline n'est pas signée ou si la signature n'est pas
  vérifiable ;
- l'environnement n'éteint pas `--require-signed`.

Sans `--baseline`, `--require-signed` ne change pas le scan. Avec
`--baseline` illisible, la politique force l'exit 2 même sans
`--strict`.

`baseline --resign <fichier>` exige une clé (`SENTINEL_KEY`,
`--key-file`, ou `--encrypt-key` déprécié avec son avertissement).
Sans clé : exit 2, aucune écriture. Le document déjà signé est
vérifié d'abord ; signature invalide ou mauvaise clé → exit 2, fichier
intact (`--yes` ne passe pas outre). `--trust-unsigned` n'est alors
pas requis. Sinon l'outil affiche le diff entre les entrées et les
fichiers actuels de `root` (ajouts, suppressions, contenu, mode,
propriétaire, capabilities), puis attend `y` / `yes` / `oui`. Stdin
non TTY → exit 2 sauf `--yes`. L'écriture est atomique (temporaire
dans le même dossier + `os.replace`). `--backup` conserve
`<fichier>.bak`. Resignature ne régénère pas les entrées et ne pose
pas `encrypted`. `--resign` refuse un dossier positionnel ou `--out`.

Une baseline **non signée** ne peut pas être distinguée d'un document
sain qui décrit le même arbre. Retirer `signature`, `encrypted`,
`key_check` et `key_hint`, puis recopier le hash d'un fichier déjà
compromis, donne un diff vide. Régénérer la baseline depuis ces
fichiers certifierait le même état. `--resign` ne le détecte pas.
`--yes` seul est un exit 2 : il faut `--trust-unsigned`. L'avertissement
(affiché aussi dans l'invite) rappelle que c'est une confiance initiale
et qu'il ne faut le faire que pour une baseline produite soi-même sur
un système connu sain. En cas de doute, régénérer avec `baseline`
depuis cet état, plutôt que resigner.

La resignature ajoute alors `resigned_from_unsigned: true` et
`resigned_at` (UTC, `YYYY-MM-DDTHH:MM:SSZ`) au document, **dans** le
JSON canonique signé. Les altérer casse le HMAC. Quand `scan` ou
`watch` vérifie la signature et trouve ce booléen, il affiche un avis
(la marque n'est pas annoncée si la signature n'a pas été vérifiée).

Sans clé, le contenu ≤ 64 KB est embarqué **sauf** pour un fichier
évidemment sensible : nom (`authorized_keys`, `id_rsa` et variantes, `.env`
hors `.env.example` / `.sample` / `.template`, `.pem`, `.key`, …) ou
contenu portant un marqueur SIG-0008. Dans ce cas `content` est null,
`content_redacted` vaut `"sensitive"`, le SHA-256 reste. SIG-0019 est
désactivée pour ces entrées et le scan l'annonce (même contrat que la
baseline chiffrée). Le clair n'est pas récupérable ; on ne relit pas le
fichier actuel comme historique.

### Quarantaine

`quarantine_file(src, dest_dir)` :
1. `shutil.move(src, dest_dir/<unique_name>)` (cross-filesystem OK)
2. Lecture seule : `0444` pour un fichier, `0555` pour un dossier — les bits
   `x` sont conservés sinon le dossier n'est plus traversable ; le contenu
   d'un dossier passe en lecture seule récursivement
3. Retourne un `QuarantineRecord(original, quarantined, sha256, size, mode_before, moved_at)`

`quarantine_paths(paths, dest, manifest)` :
- Itère sur les paths, continue en cas d'échec, et **ajoute l'entrée au
  manifest immédiatement après chaque déplacement** (`append` + `fsync`,
  JSONL). Un crash au milieu du lot laisse donc l'audit de tout ce qui a
  déjà été déplacé — sinon ces fichiers seraient irrécupérables par
  `restore` et absents du journal.
- `exit 0` si tout déplacé, `exit 1` si au moins un échec (mais aucun
  fichier supprimé), `exit 2` si le garde-fou de chemin a refusé le lot

`restore_paths(manifest, dest, force, only)` :
- Rejoue l'inverse : `quarantined` → `original`, `mode_before` restauré.
- **Vérifie le SHA-256 avant restauration** : un fichier de quarantaine
  corrompu ou remplacé est refusé (0444 n'arrête ni root ni un remontage).
- Conserve les entrées restaurées dans le journal (`_status: "restored"`,
  `restored_at`) : le manifest reste un audit complet, et une entrée
  `restored` n'est jamais rejouée.
- Refuse d'écraser un dossier au chemin d'origine, même avec `--force`
  (« ne supprime jamais »).

### Surveillance (watch)

Deux backends :
- `watch_polling(folder, interval, on_change, max_iterations=...)` :
  même `os.walk(onerror=…)` que le scanner (les symlinks ne sont pas
  suivis). Un chemin illisible est rapporté (stderr « illisible », clé
  `unreadable` du diff) et la commande `watch` sort 3. Stdlib only.
  Argument nommé optionnel `unreadable_out` (la signature positionnelle
  ne change pas).
- Contenu : SHA-256 en flux à chaque tour jusqu'à 8 Mio (un fichier de
  2 Mio à taille et mtime identiques est donc vu). Au-delà, échantillon
  de 3 × 64 Kio à chaque tour, et hash complet **par fichier** au plus
  tous les 10 instantanés de ce fichier. Le dernier hash complet est
  recopié sur les tours échantillon et comparé au hash suivant : le
  changement d'un autre fichier ne jette pas ce digest et ne remet pas
  l'échéance à zéro. Une modification entre les fenêtres attend au plus
  ce rattrapage.
- `watch_event(folder, on_change)` : via `watchdog` (FSEvents/inotify).
  Optionnel ; repli automatique sur polling si non installé. Les chemins
  illisibles y sont rapportés de la même façon.

À chaque changement détecté (added/removed/modified), un scan complet
est lancé et son rapport imprimé. Ctrl-C / SIGTERM pour arrêter.

## Hors-scope (à dessein)

- Apprentissage sur disque (le modèle V3 est figé après `train`)
- Réseau (pas de mise à jour des signatures, pas d'API)
- GUI
- `rm` / suppression (V4 déplace en quarantaine, ne supprime jamais)

Le polling reste *interne* à la commande `watch` ; il n'est pas activé
par défaut pour les autres sous-commandes.

## P0 — corrections d'angles morts silencieux

Suite à l'audit de WorkBuddy sur les faux-négatifs silencieux (PR #2 mergée),
six corrections P0 sont livrées en une passe.

### P0-1 — `looks_binary()` accepte le non-ASCII

Ancien comportement : tout octet > 0x7E comptait comme « inhabituel » dans
le ratio binaire, donc les fichiers CJK / arabe / emoji / latin étendu
étaient rejetés comme binaires. Un `.php` en chinois contenant
`eval($_POST["x"])` ne produisait aucun finding.

Nouveau comportement : le ratio de non-imprimables est calculé sur la
chaîne UTF-8 décodée (et non sur les octets bruts) — on compte :
- `\ufffd` (caractère de remplacement UTF-8 → indique un octet mal décodé),
- les caractères de catégorie Unicode `Cc` (control) hors blanc.

Seuils :
- NUL (`\x00`) > 5 % du contenu → binaire (vrais binaires, exécutables).
- Plus de 30 % de non-imprimables après décodage → binaire.

### P0-2 — `load_baseline_text()` retourne None sans fallback disque

Ancien comportement : si la baseline n'embarquait pas le contenu (V1
ou fichier > 64 KB), la fonction lisait le contenu actuel sur disque —
ce qui revient à comparer le fichier à lui-même, et produit un faux
négatif silencieux.

Nouveau comportement : `load_baseline_text()` retourne `None` si le
champ `content` est absent ou null. Le scanner collecte ces fichiers
dans une liste `no_baseline_text` et émet un warning global :

```
⚠ N fichier(s) sans contenu exploitable dans la baseline (V1, baseline
  chiffrée, ou fichier > 64 KB). Les règles augmentées (SIG-0019, etc.)
  sont désactivées pour eux. Régénère la baseline avec
  `python3 -m sentinel baseline ...` (sans --encrypt-key) quand le fichier
  n'est pas sensible.

⚠ M fichier(s) sensible(s) : contenu non embarqué (seul le SHA-256 est
  conservé). SIG-0019 (« clé ajoutée ») est désactivée pour eux, comme
  pour une baseline chiffrée.
```

Régénérer sans `--encrypt-key` ne ré-embarque **pas** le clair d'un
fichier sensible : c'est volontaire. SIG-0007 continue de voir le fichier
actuel.

### P0-3 — symlinks : politique explicite + containment

- `follow_links=False` (défaut) : les symlinks sont **ignorés** (sécurité
  par défaut : un symlink déposé par un attaquant ne peut pas faire
  remonter un fichier hors-périmètre dans la baseline).
- `follow_links=True` : les symlinks sont suivis SAUF si leur cible
  résolue est hors du dossier scanné (containment). Les cibles
  hors-périmètre sont ajoutées à `report.skipped_external` pour audit.

CLI : `python3 -m sentinel scan <folder> --follow-links`.

### P0-4 — uid/gid + capabilities dans la baseline

`Entry` ajoute trois champs :
- `uid` : propriétaire (via `lstat` — ne pas suivre les symlinks)
- `gid` : groupe
- `capabilities` : sortie de `getcap` (None si l'utilitaire n'est pas
  disponible, chaîne vide si le fichier n'a pas de capabilities)

`IntegrityDiff` expose `owner_changed` (chown) et `cap_changed`
(changement de capabilities). Les deux sont plus pertinents que SUID
aujourd'hui : une `cap_net_bind_service` ou `cap_dac_read_search`
donnée à un binaire est un vecteur d'escalade de privilèges que SUID
ne couvre pas.

### P0-5 — `sentinel/normalize.py` — couche de normalisation

Module dédié appliqué par le scanner **avant** les règles, ligne par
ligne, en préservant les numéros de ligne.

Trois passes :
1. Résolution des concaténations Python : `"abc" "def"` → `"abcdef"`.
2. Décodage des échappements C : `\xHH` → 1 octet, `\uHHHH` → 1 char,
   `\OOO` → 1 octet, `\\`, `\'`, `\"`, `\n`, `\t`, `\r`, `\0` → leurs
   valeurs littérales.
3. Décodage des littéraux base64 « évidents » (≥ 32 chars, alphabet
   strict) : la version décodée est suffixée en commentaire inline
   `# SENTINEL_DECODED_B64: ...` sur la même ligne.

Conséquence : un `.php` qui cache `eval(` derrière `\x65\x76\x61\x6c\x28`
est désormais détecté par SIG-0001, sans qu'on ait à écrire une variante
de la règle.

### P0-6 — SIG-0019 généralisée

`_extract_all_ssh_keys()` remplace `_extract_ed25519_keys()` : on
extrait **toutes** les clés SSH du fichier (ed25519, rsa, dss, ecdsa),
identifiées par le couple `(type, body)`. SIG-0019 fire donc maintenant
sur l'ajout de n'importe quel type — une clé ssh-rsa ajoutée
post-baseline n'est plus seulement vue par SIG-0007.
