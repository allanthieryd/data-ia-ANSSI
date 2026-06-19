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


def _smtp_config() -> tuple[str, str]:
    """Recupere (expediteur, mot de passe) depuis l'environnement.

    Leve une RuntimeError explicite si la configuration .env est absente.
    """
    sender = os.environ.get("EMAIL_SENDER")
    password = os.environ.get("EMAIL_PASSWORD")
    if not sender or not password:
        raise RuntimeError(
            "Configuration email manquante : definissez EMAIL_SENDER et "
            "EMAIL_PASSWORD dans un fichier .env (voir .env.example)."
        )
    return sender, password


def send_email(recipient: str, subject: str, body: str) -> None:
    """Envoie un email texte via le SMTP Gmail (port 587, STARTTLS)."""
    sender, password = _smtp_config()

    msg = MIMEText(body)
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
    print(f"[OK] Email envoye a {recipient}")


def alert_vulnerability(cve: str, product: str, cvss: float | None,
                        recipient: str | None = None) -> None:
    """Envoie une alerte formatee pour un CVE critique donne.

    recipient : par defaut EMAIL_RECIPIENT (.env).
    """
    recipient = recipient or os.environ.get("EMAIL_RECIPIENT")
    if not recipient:
        raise RuntimeError("Aucun destinataire (EMAIL_RECIPIENT absent du .env).")

    subject = f"[ALERTE] Vulnérabilité critique {cve}"
    body = (
        f"Une vulnérabilité critique a été détectée.\n\n"
        f"CVE     : {cve}\n"
        f"Produit : {product}\n"
        f"CVSS    : {cvss if cvss is not None else 'N/A'}\n\n"
        f"Action recommandée : appliquer le correctif dès que possible."
    )
    send_email(recipient, subject, body)


def alert_critical(critical: list[dict], recipient: str | None = None) -> bool:
    """Envoie UN mail recapitulatif listant les CVE critiques fournies.

    critical : liste de dicts {cve, produit, cvss, epss}. Si la liste est vide,
    aucun mail n'est envoye. Retourne True si un mail a ete envoye.
    """
    if not critical:
        print("[INFO] Aucune CVE critique : pas d'alerte envoyee.")
        return False

    recipient = recipient or os.environ.get("EMAIL_RECIPIENT")
    if not recipient:
        raise RuntimeError("Aucun destinataire (EMAIL_RECIPIENT absent du .env).")

    lines = [
        f"- {c['cve']} | {c.get('product') or 'N/A'} | "
        f"CVSS {c['cvss'] if c.get('cvss') is not None else 'N/A'} | "
        f"EPSS {c['epss'] if c.get('epss') is not None else 'N/A'}"
        for c in critical
    ]
    subject = f"[ALERTE] {len(critical)} vulnérabilité(s) critique(s) détectée(s)"
    body = (
        f"Vulnérabilités dépassant les seuils critiques "
        f"(CVSS ≥ {config.CVSS_ALERT_THRESHOLD} ou EPSS ≥ {config.EPSS_ALERT_THRESHOLD}) :\n\n"
        + "\n".join(lines)
        + "\n\nAction recommandée : appliquer les correctifs dès que possible."
    )
    send_email(recipient, subject, body)
    return True


if __name__ == "__main__":
    # Test manuel : envoie une alerte d'exemple au destinataire du .env.
    alert_vulnerability(
        cve="CVE-2023-46805",
        product="Ivanti Connect Secure",
        cvss=9.8,
    )
