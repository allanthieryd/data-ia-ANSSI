"""Etape 6 : Envoi d'une alerte email pour les vulnerabilites critiques.

La logique d'envoi (auparavant dans le notebook) est isolee ici pour etre
reutilisable et testable. Les identifiants SMTP sont lus depuis le fichier
.env (voir .env.example) afin de ne jamais figurer dans le code.

Execution directe : ``python -m scripts.alerte`` (envoie un email de test).
"""

from __future__ import annotations

import os
import smtplib
from email.mime.text import MIMEText

from dotenv import load_dotenv

load_dotenv()


def _config_smtp() -> tuple[str, str]:
    """Recupere (expediteur, mot de passe) depuis l'environnement.

    Leve une RuntimeError explicite si la configuration .env est absente.
    """
    expediteur = os.environ.get("EMAIL_SENDER")
    mot_de_passe = os.environ.get("EMAIL_PASSWORD")
    if not expediteur or not mot_de_passe:
        raise RuntimeError(
            "Configuration email manquante : definissez EMAIL_SENDER et "
            "EMAIL_PASSWORD dans un fichier .env (voir .env.example)."
        )
    return expediteur, mot_de_passe


def envoyer_email(destinataire: str, sujet: str, corps: str) -> None:
    """Envoie un email texte via le SMTP Gmail (port 587, STARTTLS)."""
    expediteur, mot_de_passe = _config_smtp()

    msg = MIMEText(corps)
    msg["From"] = expediteur
    msg["To"] = destinataire
    msg["Subject"] = sujet

    with smtplib.SMTP("smtp.gmail.com", 587) as serveur:
        serveur.starttls()
        serveur.login(expediteur, mot_de_passe)
        serveur.send_message(msg)
    print(f"[OK] Email envoye a {destinataire}")


def alerter_vulnerabilite(cve: str, produit: str, cvss: float | None,
                          destinataire: str | None = None) -> None:
    """Envoie une alerte formatee pour un CVE critique donne.

    destinataire : par defaut EMAIL_RECIPIENT (.env).
    """
    destinataire = destinataire or os.environ.get("EMAIL_RECIPIENT")
    if not destinataire:
        raise RuntimeError("Aucun destinataire (EMAIL_RECIPIENT absent du .env).")

    sujet = f"[ALERTE] Vulnérabilité critique {cve}"
    corps = (
        f"Une vulnérabilité critique a été détectée.\n\n"
        f"CVE     : {cve}\n"
        f"Produit : {produit}\n"
        f"CVSS    : {cvss if cvss is not None else 'N/A'}\n\n"
        f"Action recommandée : appliquer le correctif dès que possible."
    )
    envoyer_email(destinataire, sujet, corps)


if __name__ == "__main__":
    # Test manuel : envoie une alerte d'exemple au destinataire du .env.
    alerter_vulnerabilite(
        cve="CVE-2023-46805",
        produit="Ivanti Connect Secure",
        cvss=9.8,
    )
