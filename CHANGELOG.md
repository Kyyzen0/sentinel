# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Non publié]

### Modifié

- La signature et la notarisation Apple se font uniquement sur le Mac,
  avec `python packaging/build.py --sign`. Le mot de passe d'application
  n'est plus lu dans l'environnement : `notarytool` le demande une fois
  dans le Terminal, ou un profil du trousseau est utilisé. Le trousseau
  temporaire créé avec `security -p` (deux invites) n'est plus utilisé.
- Le fichier `.hostlock` d'un journal sur NFS ou SMB enregistre le pid,
  l'instant de démarrage du processus et, lorsqu'ils sont disponibles,
  le boot id et le machine-id. Un verrou n'est repris comme processus
  terminé que si cette identité correspond. Sans machine-id, le boot id
  seul ne suffit pas : il faut le hostname et l'instant de démarrage du
  pid, sinon le verrou est étranger et seul l'âge le reprend. Un verrou
  d'un autre hôte expire s'il n'est plus rafraîchi
  (`SENTINEL_HOSTLOCK_STALE_SECONDS`, 86400 par défaut). Le message
  d'attente donne l'hôte, le pid, l'âge et le chemin exact du fichier
  à supprimer.

### Supprimé

- Le refus spécifique à GitHub Actions dans le module de signature :
  la CI ne signe pas, ce garde-fou ne servait plus.

## [3.0.0]

### Ajouté

- Paquet `sentinel` : signatures, intégrité, quarantaine, interface.
