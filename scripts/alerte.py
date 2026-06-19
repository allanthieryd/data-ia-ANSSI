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

import config

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


def alerter_critiques(critiques: list[dict], destinataire: str | None = None) -> bool:
    """Envoie UN mail recapitulatif listant les CVE critiques fournies.

    critiques : liste de dicts {cve, produit, cvss, epss}. Si la liste est vide,
    aucun mail n'est envoye. Retourne True si un mail a ete envoye.
    """
    if not critiques:
        print("[INFO] Aucune CVE critique : pas d'alerte envoyee.")
        return False

    destinataire = destinataire or os.environ.get("EMAIL_RECIPIENT")
    if not destinataire:
        raise RuntimeError("Aucun destinataire (EMAIL_RECIPIENT absent du .env).")

    lignes = [
        f"- {c['cve']} | {c.get('produit') or 'N/A'} | "
        f"CVSS {c['cvss'] if c.get('cvss') is not None else 'N/A'} | "
        f"EPSS {c['epss'] if c.get('epss') is not None else 'N/A'}"
        for c in critiques
    ]
    sujet = f"[ALERTE] {len(critiques)} vulnérabilité(s) critique(s) détectée(s)"
    corps = (
        f"Vulnérabilités dépassant les seuils critiques "
        f"(CVSS ≥ {config.SEUIL_CVSS_ALERTE} ou EPSS ≥ {config.SEUIL_EPSS_ALERTE}) :\n\n"
        + "\n".join(lignes)
        + "\n\nAction recommandée : appliquer les correctifs dès que possible."
    )
    envoyer_email(destinataire, sujet, corps)
    return True


if __name__ == "__main__":
    # Test manuel : envoie une alerte d'exemple au destinataire du .env.
    alerter_vulnerabilite(
        cve="CVE-2023-46805",
        produit="Ivanti Connect Secure",
        cvss=9.8,
    )
