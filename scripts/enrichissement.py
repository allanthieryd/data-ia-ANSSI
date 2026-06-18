"""Etape 3 : Enrichissement des CVE via les API MITRE (CVE) et FIRST (EPSS).

Les reponses sont lues en local (data/mitre, data/first) pour menager les
serveurs externes ; un repli en ligne est prevu si le fichier local manque.

On extrait pour chaque CVE :
  - description, score CVSS, severite, type CWE (+ description)  -> MITRE
  - produits affectes (editeur / produit / versions)            -> MITRE
  - score EPSS (probabilite d'exploitation)                     -> FIRST
"""

from __future__ import annotations

import json
import os
import time

import requests

DELAI_REQUETE = 2.0

# Si True, on tente un telechargement en ligne quand le fichier local manque.
# Desactive par defaut : pipeline 100% local, rapide et reproductible.
REPLI_EN_LIGNE = False

# Cles CVSS possibles, par ordre de preference (le sujet previent qu'elles varient)
CLES_CVSS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def _charger_json_local_ou_ligne(cve: str, dossier: str | None, url: str) -> dict | None:
    """Lit le JSON local data/<dossier>/<cve>, sinon (option) telecharge en ligne."""
    if dossier:
        chemin = os.path.join(dossier, cve)
        try:
            with open(chemin, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            if not REPLI_EN_LIGNE:
                return None  # mode local strict : pas de requete reseau
        except (json.JSONDecodeError, OSError) as e:
            print(f"[ATTENTION] Lecture locale impossible ({cve}) : {e}")
            return None
    try:
        time.sleep(DELAI_REQUETE)
        rep = requests.get(url, timeout=10)
        rep.raise_for_status()
        return rep.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[ATTENTION] Recuperation en ligne echouee ({cve}) : {e}")
        return None


def severite_depuis_cvss(score: float | None) -> str:
    """Traduit un score CVSS en categorie de gravite (bareme du sujet)."""
    if score is None:
        return "Inconnue"
    if score >= 9:
        return "Critique"
    if score >= 7:
        return "Elevee"
    if score >= 4:
        return "Moyenne"
    return "Faible"


def enrichir_mitre(cve: str, dossier_mitre: str | None = "data/mitre") -> dict:
    """Renvoie description, CVSS, CWE et produits affectes pour un CVE."""
    base = {
        "description": None,
        "cvss": None,
        "cwe": None,
        "cwe_desc": None,
        "produits": [],  # liste de dicts {editeur, produit, versions}
    }
    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    data = _charger_json_local_ou_ligne(cve, dossier_mitre, url)
    if not data:
        return base

    cna = data.get("containers", {}).get("cna", {})

    # Description
    descriptions = cna.get("descriptions", [])
    if descriptions:
        base["description"] = descriptions[0].get("value")

    # Score CVSS : on cherche la premiere cle disponible parmi les variantes
    for metric in cna.get("metrics", []):
        for cle in CLES_CVSS:
            if cle in metric and "baseScore" in metric[cle]:
                base["cvss"] = metric[cle]["baseScore"]
                break
        if base["cvss"] is not None:
            break

    # Type CWE
    problemtypes = cna.get("problemTypes", [])
    if problemtypes and problemtypes[0].get("descriptions"):
        desc0 = problemtypes[0]["descriptions"][0]
        base["cwe"] = desc0.get("cweId")
        base["cwe_desc"] = desc0.get("description")

    # Produits affectes
    for produit in cna.get("affected", []):
        versions = [
            v.get("version")
            for v in produit.get("versions", [])
            if v.get("status") == "affected" and v.get("version")
        ]
        base["produits"].append(
            {
                "editeur": produit.get("vendor"),
                "produit": produit.get("product"),
                "versions": versions,
            }
        )
    return base


def enrichir_epss(cve: str, dossier_first: str | None = "data/first") -> float | None:
    """Renvoie le score EPSS (probabilite d'exploitation) d'un CVE."""
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    data = _charger_json_local_ou_ligne(cve, dossier_first, url)
    if not data:
        return None
    lignes = data.get("data", [])
    if lignes:
        try:
            return float(lignes[0]["epss"])
        except (KeyError, ValueError, TypeError):
            return None
    return None


def enrichir_cve(cve: str) -> dict:
    """Enrichissement complet d'un CVE (MITRE + EPSS) sous forme de dict plat."""
    info = enrichir_mitre(cve)
    info["epss"] = enrichir_epss(cve)
    info["cve"] = cve
    info["base_severity"] = severite_depuis_cvss(info["cvss"])
    return info


if __name__ == "__main__":
    for cve in ["CVE-2023-46805", "CVE-2023-24488", "CVE-2026-6517"]:
        info = enrichir_cve(cve)
        print(f"\n=== {cve} ===")
        print(f"  CVSS  : {info['cvss']} ({info['base_severity']})")
        print(f"  CWE   : {info['cwe']} - {info['cwe_desc']}")
        print(f"  EPSS  : {info['epss']}")
        print(f"  Produits : {len(info['produits'])}")
        if info["produits"]:
            p = info["produits"][0]
            print(f"    ex: {p['editeur']} / {p['produit']} / {p['versions'][:3]}")
