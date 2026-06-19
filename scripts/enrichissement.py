"""Etape 3 : Enrichissement des CVE via les API MITRE (CVE) et FIRST (EPSS).

Les reponses sont lues en local (data/mitre, data/first) pour menager les
serveurs externes ; un repli en ligne est prevu si le fichier local manque
(active via config.ONLINE_FALLBACK).

On extrait pour chaque CVE :
  - description, score CVSS, severite, type CWE (+ description)  -> MITRE
  - produits affectes (editeur / produit / versions)            -> MITRE
  - score EPSS (probabilite d'exploitation)                     -> FIRST

Execution directe : ``python -m scripts.enrichissement``
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import requests

import config


def _load_json_local_or_online(cve: str, directory: str | Path | None, url: str) -> dict | None:
    """Lit le JSON local data/<dossier>/<cve>, sinon (option) telecharge en ligne."""
    if directory:
        path = Path(directory) / cve
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            if not config.ONLINE_FALLBACK:
                return None  # mode local strict : pas de requete reseau
        except (json.JSONDecodeError, OSError) as e:
            print(f"[ATTENTION] Lecture locale impossible ({cve}) : {e}")
            return None
    try:
        time.sleep(config.REQUEST_DELAY)
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[ATTENTION] Recuperation en ligne echouee ({cve}) : {e}")
        return None


def severity_from_cvss(score: float | None) -> str:
    """Traduit un score CVSS en categorie de gravite (bareme du sujet)."""
    if score is None:
        return "Inconnue"
    for threshold, label in config.SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Inconnue"


def enrich_mitre(cve: str, mitre_dir: str | Path | None = None) -> dict:
    """Renvoie description, CVSS, CWE et produits affectes pour un CVE."""
    mitre_dir = config.MITRE_DIR if mitre_dir is None else mitre_dir
    result = {
        "description": None,
        "cvss": None,
        "cwe": None,
        "cwe_desc": None,
        "products": [],  # liste de dicts {vendor, product, versions}
    }
    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    data = _load_json_local_or_online(cve, mitre_dir, url)
    if not data:
        return result

    cna = data.get("containers", {}).get("cna", {})

    descriptions = cna.get("descriptions", [])
    if descriptions:
        result["description"] = descriptions[0].get("value")

    # Le score CVSS peut etre sous plusieurs cles selon la version de la metrique.
    for metric in cna.get("metrics", []):
        for key in config.CVSS_KEYS:
            if key in metric and "baseScore" in metric[key]:
                result["cvss"] = metric[key]["baseScore"]
                break
        if result["cvss"] is not None:
            break

    problemtypes = cna.get("problemTypes", [])
    if problemtypes and problemtypes[0].get("descriptions"):
        desc0 = problemtypes[0]["descriptions"][0]
        result["cwe"] = desc0.get("cweId")
        result["cwe_desc"] = desc0.get("description")

    for product in cna.get("affected", []):
        versions = [
            v.get("version")
            for v in product.get("versions", [])
            if v.get("status") == "affected" and v.get("version")
        ]
        result["products"].append(
            {
                "vendor": product.get("vendor"),
                "product": product.get("product"),
                "versions": versions,
            }
        )
    return result


def enrich_epss(cve: str, first_dir: str | Path | None = None) -> float | None:
    """Renvoie le score EPSS (probabilite d'exploitation) d'un CVE."""
    first_dir = config.FIRST_DIR if first_dir is None else first_dir
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    data = _load_json_local_or_online(cve, first_dir, url)
    if not data:
        return None
    rows = data.get("data", [])
    if rows:
        try:
            return float(rows[0]["epss"])
        except (KeyError, ValueError, TypeError):
            return None
    return None


def enrich_cve(cve: str) -> dict:
    """Enrichissement complet d'un CVE (MITRE + EPSS) sous forme de dict plat."""
    info = enrich_mitre(cve)
    info["epss"] = enrich_epss(cve)
    info["cve"] = cve
    info["base_severity"] = severity_from_cvss(info["cvss"])
    return info


if __name__ == "__main__":
    for cve in ["CVE-2023-46805", "CVE-2023-24488", "CVE-2026-6517"]:
        info = enrich_cve(cve)
        print(f"\n=== {cve} ===")
        print(f"  CVSS  : {info['cvss']} ({info['base_severity']})")
        print(f"  CWE   : {info['cwe']} - {info['cwe_desc']}")
        print(f"  EPSS  : {info['epss']}")
        print(f"  Produits : {len(info['products'])}")
        if info["products"]:
            p = info["products"][0]
            print(f"    ex: {p['vendor']} / {p['product']} / {p['versions'][:3]}")
