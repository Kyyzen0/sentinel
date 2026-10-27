"""Contexte de triage des alertes, sans conclure à une compromission."""

_CHECKS = {
    "SIG-0001": "Vérifiez si ce code PHP traite une entrée utilisateur et s'il est attendu.",
    "SIG-0002": "Vérifiez si la commande peut ouvrir un shell distant et qui l'a introduite.",
    "SIG-0003": "Vérifiez l'origine du téléchargement et les conditions d'exécution.",
    "SIG-0004": "Examinez le contenu décodé dans un environnement adapté, sans l'exécuter.",
    "SIG-0005": "Vérifiez si la configuration ou l'outil de minage est autorisé.",
    "SIG-0006": "Vérifiez le propriétaire et la légitimité de la tâche planifiée.",
    "SIG-0007": "Vérifiez à qui appartient la clé publique et si son accès est autorisé.",
    "SIG-0008": "Vérifiez si la clé privée doit être présente et si son exposition impose une rotation.",
    "SIG-0009": "Vérifiez si les métacaractères sont exécutés ou présents comme simples données.",
    "SIG-0010": "Vérifiez la source et le contexte de l'entrée de journal.",
    "SIG-0011": "Vérifiez si ce code serveur permet l'exécution de commandes non autorisées.",
    "SIG-0012": "Vérifiez le contexte de la chaîne et l'exposition éventuelle du service concerné.",
    "SIG-0013": "Vérifiez si cette directive modifie l'accès ou l'exécution sur le serveur.",
    "SIG-0014": "Vérifiez l'origine et la légitimité de cette modification de profil shell.",
    "SIG-0015": "Vérifiez les comptes ou privilèges concernés et leur autorisation.",
    "SIG-0016": "Vérifiez si les bibliothèques chargées depuis ce chemin sont attendues.",
    "SIG-0017": "Vérifiez l'unité systemd, son propriétaire et sa commande de démarrage.",
    "SIG-0018": "Vérifiez si les nouveaux bits de privilège sont justifiés et leur origine.",
    "SIG-0019": "Vérifiez le propriétaire de la nouvelle clé et si son accès est autorisé.",
}


def guidance(rule_id: str) -> dict[str, str]:
    return {
        "limitation": "Un motif détecté ne prouve pas une compromission ; le contexte peut être légitime.",
        "check": _CHECKS.get(
            rule_id, "Vérifiez le contexte et l'origine du fichier avant toute action."
        ),
    }
