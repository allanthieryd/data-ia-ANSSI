"""Etape 1 & 2 : Extraction des bulletins ANSSI (avis / alertes) et de leurs CVE.

Approche conforme au sujet :
  - On consulte les flux RSS du CERT-FR pour reperer les bulletins (titre, date, lien).
  - On accede ensuite au JSON detaille de chaque bulletin pour en extraire les CVE.

Pour l'enrichissement (etape 3), les reponses JSON sont disponibles en local
(dossiers data/mitre et data/first) afin de menager les serveurs externes.

Execution directe : ``python -m scripts.extraction``
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import feedparser
import requests

import config

# Regex d'identifiant CVE (filet de securite si la cle "cves" est absente)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def extract_rss_bulletins(feeds: dict[str, str] | None = None) -> list[dict]:
    """Parcourt les flux RSS et renvoie la liste des bulletins reperes.

    Chaque bulletin est un dict : id, type (Avis/Alerte), titre, date, lien.
    """
    feeds = feeds or config.RSS_FEEDS
    bulletins: list[dict] = []
    for bulletin_type, url in feeds.items():
        feed = feedparser.parse(url)
        if feed.bozo:  # flux mal forme ou inaccessible
            print(f"[ATTENTION] Flux illisible pour {bulletin_type} : {url}")
            continue
        for entry in feed.entries:
            link = entry.link.rstrip("/") + "/"  # lien normalise (se termine par /)
            bulletins.append(
                {
                    "id": _id_from_link(link),
                    "type": bulletin_type,
                    "title": entry.title,
                    "date": entry.get("published", ""),
                    "link": link,
                }
            )
    return bulletins


def _id_from_link(link: str) -> str:
    """Extrait l'identifiant CERTFR-AAAA-XXX-NNNN depuis l'URL du bulletin."""
    found = re.search(r"CERTFR-\d{4}-(?:AVI|ALE)-\d+", link)
    return found.group(0) if found else link


def list_local_bulletins(years: tuple[int, ...] | None = None) -> list[dict]:
    """Liste les bulletins depuis le snapshot local (data/Avis, data/alertes).

    years : si fourni (ex: (2024, 2025, 2026)), ne garde que ces annees.
    Renvoie des dicts homogenes avec extract_rss_bulletins : id, type, title,
    date, link. La date est la date de premiere publication (revision initiale).
    """
    bulletins: list[dict] = []
    for bulletin_type, (directory, base_url) in config.BULLETIN_SOURCES.items():
        directory = Path(directory)
        if not directory.is_dir():
            print(f"[ATTENTION] Dossier local absent : {directory}")
            continue
        for path in directory.iterdir():
            name = path.name
            year = _year_from_id(name)
            if years and year not in years:
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"[ATTENTION] Bulletin local illisible ({name}) : {e}")
                continue
            revisions = data.get("revisions") or []
            date = revisions[0].get("revision_date", "") if revisions else ""
            bulletins.append(
                {
                    "id": data.get("reference", name),
                    "type": bulletin_type,
                    "title": data.get("title", ""),
                    "date": date,
                    "link": f"{base_url}{name}/",
                }
            )
    return bulletins


def _year_from_id(bulletin_id: str) -> int | None:
    """Extrait l'annee (AAAA) d'un identifiant CERTFR-AAAA-..."""
    m = re.search(r"CERTFR-(\d{4})-", bulletin_id)
    return int(m.group(1)) if m else None


def load_bulletin_json(bulletin: dict, local_dir: str | Path | None = None) -> dict | None:
    """Charge le JSON detaille d'un bulletin.

    - Si local_dir est fourni (ex: data/avis), on lit le fichier local.
    - Sinon on telecharge le JSON en ligne (lien + "json/") avec un delai.
    Gere les exceptions et renvoie None en cas d'echec.
    """
    if local_dir:
        path = Path(local_dir) / bulletin["id"]
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[INFO] JSON local absent pour {bulletin['id']}, bascule en ligne.")
        except (json.JSONDecodeError, OSError) as e:
            print(f"[ATTENTION] Lecture locale impossible ({bulletin['id']}) : {e}")

    # Recuperation en ligne (fallback ou mode 100% en ligne)
    try:
        time.sleep(config.REQUEST_DELAY)
        response = requests.get(bulletin["link"] + "json/", timeout=config.REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[ATTENTION] Telechargement JSON echoue ({bulletin['id']}) : {e}")
        return None


def extract_cves(data: dict) -> list[str]:
    """Extrait les identifiants CVE d'un bulletin.

    Strategie : on lit d'abord la cle structuree "cves" ; on complete avec une
    regex sur tout le contenu pour ne rien manquer.
    """
    cves: set[str] = set()
    for item in data.get("cves", []):
        name = item.get("name") if isinstance(item, dict) else item
        if name:
            cves.add(name)
    cves.update(CVE_PATTERN.findall(json.dumps(data)))
    return sorted(cves)


if __name__ == "__main__":
    # Petit test manuel : on liste les bulletins et les CVE des 3 premiers.
    bulletins = extract_rss_bulletins()
    print(f"{len(bulletins)} bulletins reperes via RSS.")
    for b in bulletins[:3]:
        data = load_bulletin_json(b)
        cves = extract_cves(data) if data else []
        print(f"- {b['id']} ({b['type']}) : {len(cves)} CVE -> {cves}")
