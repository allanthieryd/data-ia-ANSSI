"""Etape 4 : Consolidation des donnees enrichies dans un DataFrame pandas.

Granularite : une ligne par couple (bulletin, CVE), conformement au sujet
("une alerte/avis peut se trouver repete sur plusieurs lignes selon le nombre
de CVE"). Les produits affectes (souvent multiples) sont agreges en chaines.

Execution directe : ``python -m scripts.consolidation``
"""

from __future__ import annotations

import pandas as pd

import config
from scripts.extraction import charger_json_bulletin, extraire_cve
from scripts.enrichissement import enrichir_cve


def _produits_en_chaines(produits: list[dict]) -> tuple[str, str, str]:
    """Agrege la liste de produits en 3 chaines : editeurs, produits, versions."""
    editeurs, noms, versions = [], [], []
    for p in produits:
        if p.get("editeur"):
            editeurs.append(str(p["editeur"]).strip())
        if p.get("produit"):
            noms.append(str(p["produit"]).strip())
        versions.extend(p.get("versions", []))
    # dict.fromkeys deduplique en conservant l'ordre (lisibilite)
    uniq = lambda xs: " | ".join(dict.fromkeys(xs))
    return uniq(editeurs), uniq(noms), uniq(versions)


def consolider(bulletins: list[dict]) -> pd.DataFrame:
    """Construit le DataFrame consolide a partir de la liste de bulletins.

    Met en cache l'enrichissement par CVE (un meme CVE peut apparaitre dans
    plusieurs bulletins) pour eviter des lectures/requetes redondantes.
    """
    cache_cve: dict[str, dict] = {}
    lignes: list[dict] = []

    for i, b in enumerate(bulletins, 1):
        dossier, _ = config.SOURCES_BULLETINS.get(b["type"], (None, None))
        data = charger_json_bulletin(b, dossier_local=dossier)
        if not data:
            continue
        cves = extraire_cve(data)
        print(f"[{i}/{len(bulletins)}] {b['id']} ({b['type']}) : {len(cves)} CVE")

        for cve in cves:
            if cve not in cache_cve:
                cache_cve[cve] = enrichir_cve(cve)
            info = cache_cve[cve]
            editeurs, noms, versions = _produits_en_chaines(info["produits"])
            lignes.append(
                {
                    "id_anssi": b["id"],
                    "titre_anssi": b["titre"],
                    "type": b["type"],
                    "date": b["date"],
                    "cve": cve,
                    "cvss": info["cvss"],
                    "base_severity": info["base_severity"],
                    "cwe": info["cwe"],
                    "cwe_desc": info["cwe_desc"],
                    "epss": info["epss"],
                    "lien": b["lien"],
                    "description": info["description"],
                    "editeur": editeurs,
                    "produit": noms,
                    "versions": versions,
                }
            )

    df = pd.DataFrame(lignes, columns=config.COLONNES)
    # Normalisation de la date en datetime (utile pour les analyses temporelles)
    df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True)
    return df


if __name__ == "__main__":
    from scripts.extraction import lister_bulletins_locaux

    bulletins = lister_bulletins_locaux(annees=config.ANNEES)[:5]
    print(f"Test sur {len(bulletins)} bulletins locaux.")
    df = consolider(bulletins)
    print(df.head())
