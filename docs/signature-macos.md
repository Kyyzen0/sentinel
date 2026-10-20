# Signer et notarier Sentinel sur macOS

Ce guide est pour la personne qui a le compte Apple Developer et qui
veut produire `dist/Sentinel.app` accepté par Gatekeeper, sans connaître
`codesign`. Une seule commande fait le gel PyInstaller, la signature et
la notarisation :

```bash
python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize
```

Avant la première fois, trois réglages (une fois chacun) : le certificat,
un mot de passe d'application, et l'enregistrement de ce mot de passe
dans le trousseau. Le diagnostic dit ce qui manque :

```bash
python packaging/build.py --check
```

Tout se fait sur votre Mac. Linux et Windows produisent un binaire non
signé ; `--sign` y est refusé. GitHub Actions construit aussi des
artefacts non signés : le dépôt public ne signe pas et ne notarie pas.
Le profil `sentinel-notary` et la clé d'API, si vous en utilisez une,
restent sur ce Mac.

## Ce que la commande fait

1. PyInstaller construit `dist/Sentinel.app` (bundle onedir, pas un
   exécutable unique).
2. Chaque binaire Mach-O, dylib et framework **à l'intérieur** du bundle
   est signé, du plus profond vers l'extérieur, avec l'identité
   Developer ID, un horodatage Apple (`--timestamp`) et le Hardened
   Runtime (`--options runtime`). `--deep` n'est pas utilisé : il signe
   dans le mauvais ordre.
3. L'exécutable principal, le `.app`, et tout `.app` imbriqué avec son
   exécutable reçoivent `packaging/entitlements.plist`. Un seul droit :
   `com.apple.security.cs.allow-unsigned-executable-memory`. CPython
   (via libffi, donc PySide6) et le bootloader PyInstaller réservent de
   la mémoire à la fois inscriptible et exécutable. Sans ce droit,
   macOS tue l'app au lancement. `allow-jit` ne suffit pas.
   `disable-library-validation` n'est pas posé : tout est re-signé avec
   le même Team ID, et le gel n'extrait rien dans un dossier temporaire.
4. `codesign --verify --strict` doit réussir, sinon la commande s'arrête.
5. `--notarize` archive le bundle avec `ditto` (les liens symboliques
   de PyInstaller restent des liens), envoie l'archive à Apple
   (`xcrun notarytool submit --wait --keychain-profile`), agrafe le ticket
   (`xcrun stapler staple`) et vérifie Gatekeeper
   (`spctl -a -vv -t exec`).
6. `--dmg` ajoute `dist/Sentinel.dmg`. Avec `--notarize`, c'est l'image
   disque qui est envoyée à Apple.

Sur votre Mac, le plus simple est un profil du trousseau : le mot de
passe est demandé une fois, dans Terminal, et n'est plus retapé. La
commande `store-credentials` est lancée **sans** `--password`.
`notarytool` ne comprend pas `@env:` (c'était une option d'`altool`).

## 0. Vérifier l'état

```bash
python packaging/build.py --check
```

Exemple quand il manque encore tout :

```text
Contrôle de la signature macOS
==============================

[MANQUE] Outils Apple
    Il manque : Xcode Command Line Tools, codesign, notarytool, stapler.
    Pour corriger :
    Installez les outils (une fenêtre va s'ouvrir) :
      xcode-select --install

[MANQUE] Certificat Developer ID Application
    Aucun certificat de signature dans le trousseau (0 identité utilisable).
    Pour corriger :
    1. Ouvrez Xcode → Réglages… → Comptes
    ...

[MANQUE] Profil notaire
    Aucun profil notaire nommé « sentinel-notary » dans le trousseau.
    Pour corriger :
      xcrun notarytool store-credentials sentinel-notary
```

Quand les trois blocs sont `[OK]`, le diagnostic affiche la commande
exacte à copier, avec le nom du certificat trouvé dans le trousseau.

## 1. Outils Apple

Sans Xcode (ou au moins ses Command Line Tools), `codesign` et
`notarytool` n'existent pas.

```bash
xcode-select --install
```

Une fenêtre propose l'installation. Ensuite :

```bash
xcode-select -p
xcrun --find notarytool
xcrun --find stapler
```

Succès typique :

```text
/Applications/Xcode.app/Contents/Developer
/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool
/Applications/Xcode.app/Contents/Developer/usr/bin/stapler
```

Si Xcode est installé mais `xcode-select -p` échoue :

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
```

## 2. Certificat « Developer ID Application »

Il faut un compte [Apple Developer](https://developer.apple.com/programs/)
(le programme payant). Le certificat **Apple Development**, créé tout
seul par Xcode pour lancer une app sur sa machine, ne peut pas notarier
une app distribuée en dehors de l'App Store.

1. Ouvrez **Xcode**.
2. **Xcode → Settings… → Accounts** (Réglages → Comptes). Sur une vieille
   version : **Xcode → Preferences → Accounts**.
3. En bas à gauche, **+** si votre compte Apple Developer n'est pas là.
   Connectez-vous.
4. Sélectionnez le compte. À droite, **Manage Certificates…**
   (Gérer les certificats).
5. **+** → **Developer ID Application**.
6. Fermez la fenêtre. Le certificat et sa clé privée sont dans le
   trousseau de session.

Vérification :

```bash
security find-identity -v -p codesigning
```

Succès :

```text
  1) A1B2C3D4E5F67890 "Developer ID Application: Votre Nom (AB12CD34EF)"
     1 valid identities found
```

Ce qui est entre guillemets est l'identité à passer à `--sign`. Le
`AB12CD34EF` (10 caractères) est le **Team ID**.

`find-identity` ne liste une identité que si la **clé privée** est dans
le trousseau. Un certificat sans clé n'apparaît pas : revenez à
Manage Certificates et recréez **Developer ID Application** depuis ce Mac.

## 3. Mot de passe d'application

À faire si vous notarisez depuis votre Mac avec votre identifiant Apple.
Le mot de passe n'est jamais écrit dans une commande.

Apple n'accepte pas le mot de passe habituel du compte pour `notarytool`.

1. Allez sur [https://appleid.apple.com](https://appleid.apple.com) et
   connectez-vous.
2. **Connexion et sécurité** → **Mots de passe pour les applications**
   (App-Specific Passwords).
3. Créez-en un, par exemple nommé `sentinel-notary`.
4. Notez la valeur `xxxx-xxxx-xxxx-xxxx`. Elle ne sera plus affichée.

## 4. Enregistrer le profil notaire (une fois)

Dans Terminal.app (pas besoin de le refaire à chaque build) :

```bash
xcrun notarytool store-credentials sentinel-notary
```

Apple demande, dans l'ordre :

- **Apple ID** : l'adresse du compte Developer ;
- **Team ID** : les 10 caractères entre parenthèses dans le nom du
  certificat ;
- **mot de passe d'application** : celui de l'étape 3, pas le mot de
  passe du compte.

Cette forme interactive ne laisse pas le mot de passe dans l'historique
du shell. Succès :

```text
Validating your credentials...
Success. Credentials validated.
Credentials saved to Keychain.
To use them, specify `--keychain-profile "sentinel-notary"`
```

N'ajoutez pas `--password`. Le manuel `notarytool` (`man notarytool`,
page `NOTARYTOOL(1)`) dit que `--password` est le mot de passe
d'application lui-même : il resterait dans l'historique de zsh et serait
visible dans `ps`. `@env:` est une syntaxe d'`altool`, pas de
`notarytool`. Si on écrit `--password @env:APPLE_APP_PASSWORD`,
`notarytool` enregistre la chaîne `@env:APPLE_APP_PASSWORD` comme mot
de passe, et la notarisation échoue à l'authentification. Sans
`--password`, `notarytool` ouvre une invite sécurisée. C'est la commande
du début de cette section, et elle a besoin d'un Terminal.

Sur votre Mac, si `APPLE_ID` et `APPLE_TEAM_ID` sont définies,
`python packaging/build.py` appelle `store-credentials` **sans**
`--password` et sans créer de trousseau temporaire. `notarytool`
demande le mot de passe une seule fois dans le Terminal. S'il n'y a
pas de Terminal, la commande s'arrête et affiche la ligne à lancer
une fois à la main, puis `--keychain-profile`. Le mot de passe n'est
jamais un argument. `APPLE_APP_PASSWORD` n'est pas lu : le mettre
dans l'environnement ne le transmet pas.

Le profil est enregistré dans le trousseau de la session, ou dans
`SENTINEL_NOTARY_KEYCHAIN` s'il est défini. On ne passe pas `-p` à
`security create-keychain` ni à `unlock-keychain`. Ces deux mots de
passe provoquaient deux invites, et ils ne servaient qu'à un
environnement sans Terminal. La signature ne se fait pas dans
GitHub Actions.

Relancez `python packaging/build.py --check`. Les trois lignes doivent
être `[OK]`.

Profil d'un autre nom : `--keychain-profile NOM` ou
`export SENTINEL_NOTARY_PROFILE=NOM`. Sans rien, le nom est
`sentinel-notary`.

## 5. La commande unique

Depuis la racine du dépôt, avec l'extra d'empaquetage :

```bash
pip install -e ".[gui,bundle]"
python packaging/build.py --sign "Developer ID Application: Votre Nom (AB12CD34EF)" --notarize
```

Si l'identité est déjà dans l'environnement, `--sign` sans valeur suffit :

```bash
export SENTINEL_CODESIGN_IDENTITY="Developer ID Application: Votre Nom (AB12CD34EF)"
python packaging/build.py --sign --notarize
```

La première fois, macOS peut demander le mot de passe du trousseau de
session pour autoriser `codesign` à utiliser la clé privée. Choisissez
**Toujours autoriser**. Lancez la commande dans Terminal.app : une
session SSH n'affiche pas cette fenêtre et la signature échoue avec
`errSecInternalComponent`.

La suite dure le temps du gel Qt, puis quelques minutes chez Apple
(parfois plus). Succès, en raccourci :

```text
Signature (1/N) : .../Sentinel.app/Contents/Frameworks/...
Signature (N/N) : .../Sentinel.app
Vérification : codesign --verify --strict
Signature enregistrée :
  Authority=Developer ID Application: Votre Nom (AB12CD34EF)
  Authority=Developer ID Certification Authority
  Authority=Apple Root CA
  Timestamp=...
  TeamIdentifier=AB12CD34EF
Signature terminée : .../dist/Sentinel.app
Archive (ditto) : ...
Envoi à Apple (notarytool --wait)…
Notarisation acceptée (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
Agrafe (stapler) : .../dist/Sentinel.app
Agrafe posée : .../dist/Sentinel.app
Contrôle Gatekeeper : spctl -a -vv
.../dist/Sentinel.app: accepted
source=Notarized Developer ID
Archive à distribuer (liens conservés) : .../dist/Sentinel.zip
Terminé.
```

`source=Notarized Developer ID` est le critère. L'app à lancer est
`dist/Sentinel.app`. Le zip `dist/Sentinel.zip` se ré-extrait avec
`ditto -x -k Sentinel.zip` (un `unzip` classique peut casser les liens
et la signature).

## Image disque

```bash
python packaging/build.py --sign "Developer ID Application: Votre Nom (AB12CD34EF)" --notarize --dmg
```

Produit `dist/Sentinel.dmg`. L'image est signée, envoyée à Apple à la
place du zip, puis agrafée. Gatekeeper est contrôlé avec
`spctl -a -vv -t open --context context:primary-signature`.
Sans ce `--context`, Gatekeeper refuse une image pourtant notariée.
L'application, elle, est contrôlée avec `spctl -a -vv -t exec`
(`-t install` est réservé aux paquets `.pkg`).

## Variables d'environnement

| Variable | Rôle |
|----------|------|
| `SENTINEL_CODESIGN_IDENTITY` | Identité utilisée quand `--sign` est passé sans valeur |
| `SENTINEL_NOTARY_PROFILE` | Nom du profil trousseau (défaut `sentinel-notary`) |
| `APPLE_API_KEY` | Chemin du fichier `.p8` (pas son contenu) |
| `APPLE_API_KEY_ID` | Identifiant de la clé, en général 10 caractères |
| `APPLE_API_ISSUER` | UUID émetteur. Obligatoire pour une clé d'équipe |
| `APPLE_ID` | Identifiant Apple, sur ce Mac |
| `APPLE_TEAM_ID` | Team ID, 10 caractères |
| `SENTINEL_NOTARY_KEYCHAIN` | Trousseau déjà déverrouillé, s'il n'est pas celui de la session. Il n'est pas créé avec `-p` |

`--keychain-profile` explicite gagne sur tout le reste. Sinon, une clé
d'API complète gagne sur l'identifiant Apple. Un groupe à moitié rempli
est une erreur : on ne bascule pas en silence vers l'autre méthode.

Avec la clé d'API, `notarytool submit` reçoit `--key`, `--key-id` et
`--issuer`. `--key` est un chemin de fichier. Le contenu du `.p8` n'est
pas un argument.

Avec l'identifiant Apple, `store-credentials` est appelé sans
`--password` (une invite du Terminal, voir la section 4). `submit`
reçoit `--keychain-profile`, et `--keychain` seulement si
`SENTINEL_NOTARY_KEYCHAIN` est défini. Le mot de passe d'application
n'est jamais un argument, et il n'est pas lu dans l'environnement.

## Clé d'API App Store Connect

Autre méthode, toujours sur votre Mac. `notarytool` lit un fichier
`.p8` qui reste chez vous. Il ne reçoit pas le texte de la clé dans
ses arguments. GitHub Actions n'utilise pas cette clé.

1. Ouvrez [App Store Connect](https://appstoreconnect.apple.com) →
   **Users and Access** → **Integrations** → **App Store Connect API**
   (ou **Users and Access** → **Keys**, selon l'affichage du site).
2. Il faut un rôle d'administrateur de l'équipe pour créer une clé
   d'équipe. Le rôle de la clé peut être **Developer**.
3. Cliquez sur **Generate API Key** (ou **+**). Donnez-lui un nom, par
   exemple `sentinel-notary`.
4. Notez deux valeurs affichées dans le tableau :
   - **Key ID**, 10 caractères, par exemple `AB12CD34EF`. C'est
     `APPLE_API_KEY_ID`.
   - **Issuer ID**, un UUID en haut de la page. C'est
     `APPLE_API_ISSUER`. Il est obligatoire pour une clé d'équipe. Une
     clé individuelle (sans Issuer) n'est pas le chemin prévu ici : ne
     la mélangez pas, `notarytool` répond 401 si l'émetteur est fourni
     pour une clé individuelle.
5. **Download API Key**. Apple ne propose le téléchargement qu'une fois.
   Le fichier s'appelle `AuthKey_AB12CD34EF.p8`. Ne le committez pas.

Sur votre Mac :

```bash
chmod 600 ~/Desktop/AuthKey_AB12CD34EF.p8
export APPLE_API_KEY="$HOME/Desktop/AuthKey_AB12CD34EF.p8"
export APPLE_API_KEY_ID="AB12CD34EF"
export APPLE_API_ISSUER="00000000-0000-0000-0000-000000000000"
python packaging/build.py --sign "Developer ID Application: NOM (TEAMID)" --notarize
```

Déplacez ensuite le `.p8` hors du Bureau, dans un dossier réservé, et
mettez à jour `APPLE_API_KEY`. Ne le committez pas : le dépôt ignore
`*.p8`, ainsi que `*.p12` et `*.cer`.

## Artefacts GitHub

Le workflow
[`.github/workflows/package.yml`](../.github/workflows/package.yml)
se lance à la main (`workflow_dispatch`). Il construit les binaires des
trois systèmes et les dépose **non signés**. Il ne lit aucun secret
Apple, n'importe pas de certificat et n'appelle pas `notarytool`.

La signature et la notarisation se font seulement sur votre Mac, en
suivant les étapes ci-dessus. Le profil `sentinel-notary` et la clé
`.p8` restent sur cette machine.

## Erreurs fréquentes

**`errSecInternalComponent` pendant `codesign`.**
Le trousseau n'a pas laissé utiliser la clé. Ouvrez Trousseau d'accès,
déverrouillez la session (cadenas), relancez dans Terminal.app, et
choisissez **Toujours autoriser**.

**`0 valid identities found`.**
Pas de certificat, ou certificat sans clé privée. Reprenez l'étape 2
sur ce Mac. Un certificat exporté depuis un autre Mac n'est utilisable
ici que si le `.p12` (certificat + clé) a été importé.

**Seulement `Apple Development: …`.**
Normal après avoir ouvert Xcode une fois. Il faut en plus
**Developer ID Application** (étape 2). `--notarize` refuse cette
identité avant d'envoyer quoi que ce soit à Apple.

**`No Keychain password item found` / code 69.**
Le profil `sentinel-notary` n'existe pas. Relancez
`xcrun notarytool store-credentials sentinel-notary`.

**`The signature does not include a secure timestamp`.**
Le Mac n'a pas joint l'horodatage Apple. Il faut le réseau vers
`timestamp.apple.com` pendant la signature. La commande passe déjà
`--timestamp` ; un proxy ou un pare-feu qui bloque ce serveur suffit
à provoquer l'erreur.

**Notarisation `Invalid`.**
La commande affiche le journal (`notarytool log`). Les causes typiques :
binaire intérieur non signé (le journal cite le chemin), lien symbolique
remplacé par une copie (`zip` sans conserver les liens — on utilise
`ditto`), ou certificat qui n'est pas Developer ID.

**`spctl` : `source=Unnotarized Developer ID`.**
La signature est bonne, le ticket notaire n'est pas agrafé ou Apple n'a
pas accepté le fichier. Lisez le journal au-dessus. Ne distribuez pas
cette copie.

**L'app signée quitte tout de suite.**
Le Hardened Runtime bloque la mémoire exécutable si l'entitlement a été
retiré. `packaging/entitlements.plist` doit rester celui du dépôt.

**La commande demande `--sign` alors que vous avez passé `--notarize`.**
La notarisation sans signature Developer ID est refusée par Apple. Les
deux drapeaux vont ensemble.
