"""Etape 1 & 2 : Extraction des bulletins ANSSI (avis / alertes) et de leurs CVE.

Approche conforme au sujet :
  - On consulte les flux RSS du CERT-FR pour reperer les bulletins (titre, date, lien).
  - On accede ensuite au JSON detaille de chaque bulletin pour en extraire les CVE.

Pour l'enrichissement (etape 3), les reponses JSON sont disponibles en local
(dossiers data/mitre et data/first) afin de menager les serveurs externes.
"""

from __future__ import annotations

import json
import os
import re
import time

import feedparser
import requests

# Flux RSS officiels du CERT-FR (on ne garde que avis et alertes, cf. sujet)
FLUX_RSS = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

# Delai entre deux requetes externes (section 8 du sujet : usage responsable)
DELAI_REQUETE = 2.0

# Regex d'identifiant CVE (filet de securite si la cle "cves" est absente)
MOTIF_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def extraire_bulletins_rss(flux: dict[str, str] = FLUX_RSS) -> list[dict]:
    """Parcourt les flux RSS et renvoie la liste des bulletins reperes.

    Chaque bulletin est un dict : id, type (Avis/Alerte), titre, date, lien.
    """
    bulletins: list[dict] = []
    for type_bulletin, url in flux.items():
        feed = feedparser.parse(url)
        if feed.bozo:  # flux mal forme ou inaccessible
            print(f"[ATTENTION] Flux illisible pour {type_bulletin} : {url}")
            continue
        for entry in feed.entries:
            lien = entry.link.rstrip("/") + "/"  # lien normalise (se termine par /)
            bulletins.append(
                {
                    "id": _id_depuis_lien(lien),
                    "type": type_bulletin,
                    "titre": entry.title,
                    "date": entry.get("published", ""),
                    "lien": lien,
                }
            )
    return bulletins


def _id_depuis_lien(lien: str) -> str:
    """Extrait l'identifiant CERTFR-AAAA-XXX-NNNN depuis l'URL du bulletin."""
    found = re.search(r"CERTFR-\d{4}-(?:AVI|ALE)-\d+", lien)
    return found.group(0) if found else lien


# Dossiers locaux des bulletins (copies fournies par le prof) et URL de base
SOURCES_LOCALES = {
    "Avis": ("data/Avis", "https://www.cert.ssi.gouv.fr/avis/"),
    "Alerte": ("data/alertes", "https://www.cert.ssi.gouv.fr/alerte/"),
}


def lister_bulletins_locaux(annees: tuple[int, ...] | None = None) -> list[dict]:
    """Liste les bulletins depuis le snapshot local (data/Avis, data/alertes).

    annees : si fourni (ex: (2024, 2025, 2026)), ne garde que ces annees.
    Renvoie des dicts homogenes avec extraire_bulletins_rss : id, type, titre,
    date, lien. La date est la date de premiere publication (revision initiale).
    """
    bulletins: list[dict] = []
    for type_bulletin, (dossier, url_base) in SOURCES_LOCALES.items():
        if not os.path.isdir(dossier):
            print(f"[ATTENTION] Dossier local absent : {dossier}")
            continue
        for nom in os.listdir(dossier):
            annee = _annee_depuis_id(nom)
            if annees and annee not in annees:
                continue
            try:
                with open(os.path.join(dossier, nom), encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"[ATTENTION] Bulletin local illisible ({nom}) : {e}")
                continue
            revisions = data.get("revisions") or []
            date = revisions[0].get("revision_date", "") if revisions else ""
            bulletins.append(
                {
                    "id": data.get("reference", nom),
                    "type": type_bulletin,
                    "titre": data.get("title", ""),
                    "date": date,
                    "lien": f"{url_base}{nom}/",
                }
            )
    return bulletins


def _annee_depuis_id(id_bulletin: str) -> int | None:
    """Extrait l'annee (AAAA) d'un identifiant CERTFR-AAAA-..."""
    m = re.search(r"CERTFR-(\d{4})-", id_bulletin)
    return int(m.group(1)) if m else None


def charger_json_bulletin(bulletin: dict, dossier_local: str | None = None) -> dict | None:
    """Charge le JSON detaille d'un bulletin.

    - Si dossier_local est fourni (ex: data/avis), on lit le fichier local.
    - Sinon on telecharge le JSON en ligne (lien + "json/") avec un delai.
    Gere les exceptions et renvoie None en cas d'echec.
    """
    if dossier_local:
        chemin = os.path.join(dossier_local, bulletin["id"])
        try:
            with open(chemin, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[INFO] JSON local absent pour {bulletin['id']}, bascule en ligne.")
        except (json.JSONDecodeError, OSError) as e:
            print(f"[ATTENTION] Lecture locale impossible ({bulletin['id']}) : {e}")

    # Recuperation en ligne (fallback ou mode 100% en ligne)
    try:
        time.sleep(DELAI_REQUETE)
        reponse = requests.get(bulletin["lien"] + "json/", timeout=10)
        reponse.raise_for_status()
        return reponse.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[ATTENTION] Telechargement JSON echoue ({bulletin['id']}) : {e}")
        return None


def extraire_cve(data: dict) -> list[str]:
    """Extrait les identifiants CVE d'un bulletin.

    Strategie : on lit d'abord la cle structuree "cves" ; on complete avec une
    regex sur tout le contenu pour ne rien manquer.
    """
    cves: set[str] = set()
    for item in data.get("cves", []):
        nom = item.get("name") if isinstance(item, dict) else item
        if nom:
            cves.add(nom)
    cves.update(MOTIF_CVE.findall(json.dumps(data)))
    return sorted(cves)


if __name__ == "__main__":
    # Petit test manuel : on liste les bulletins et les CVE des 3 premiers.
    bulletins = extraire_bulletins_rss()
    print(f"{len(bulletins)} bulletins reperes via RSS.")
    for b in bulletins[:3]:
        data = charger_json_bulletin(b)
        cves = extraire_cve(data) if data else []
        print(f"- {b['id']} ({b['type']}) : {len(cves)} CVE -> {cves}")
