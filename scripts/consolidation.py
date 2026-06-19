"""Etape 4 : Consolidation des donnees enrichies dans un DataFrame pandas.

Granularite : une ligne par couple (bulletin, CVE), conformement au sujet
("une alerte/avis peut se trouver repete sur plusieurs lignes selon le nombre
de CVE"). Les produits affectes (souvent multiples) sont agreges en chaines.

Execution directe : ``python -m scripts.consolidation``
"""

from __future__ import annotations

import pandas as pd

import config
from scripts.extraction import load_bulletin_json, extract_cves
from scripts.enrichissement import enrich_cve


def _products_to_strings(products: list[dict]) -> tuple[str, str, str]:
    """Agrege la liste de produits en 3 chaines : editeurs, produits, versions."""
    vendors, names, versions = [], [], []
    for p in products:
        if p.get("vendor"):
            vendors.append(str(p["vendor"]).strip())
        if p.get("product"):
            names.append(str(p["product"]).strip())
        versions.extend(p.get("versions", []))
    # dict.fromkeys deduplique en conservant l'ordre (lisibilite)
    uniq = lambda xs: " | ".join(dict.fromkeys(xs))
    return uniq(vendors), uniq(names), uniq(versions)


def consolidate(bulletins: list[dict]) -> pd.DataFrame:
    """Construit le DataFrame consolide a partir de la liste de bulletins.

    Met en cache l'enrichissement par CVE (un meme CVE peut apparaitre dans
    plusieurs bulletins) pour eviter des lectures/requetes redondantes.
    """
    cve_cache: dict[str, dict] = {}
    rows: list[dict] = []

    for i, b in enumerate(bulletins, 1):
        directory, _ = config.BULLETIN_SOURCES.get(b["type"], (None, None))
        data = load_bulletin_json(b, local_dir=directory)
        if not data:
            continue
        cves = extract_cves(data)
        print(f"[{i}/{len(bulletins)}] {b['id']} ({b['type']}) : {len(cves)} CVE")

        for cve in cves:
            if cve not in cve_cache:
                cve_cache[cve] = enrich_cve(cve)
            info = cve_cache[cve]
            vendors, names, versions = _products_to_strings(info["products"])
            rows.append(
                {
                    "id_anssi": b["id"],
                    "title_anssi": b["title"],
                    "type": b["type"],
                    "date": b["date"],
                    "cve": cve,
                    "cvss": info["cvss"],
                    "base_severity": info["base_severity"],
                    "cwe": info["cwe"],
                    "cwe_desc": info["cwe_desc"],
                    "epss": info["epss"],
                    "link": b["link"],
                    "description": info["description"],
                    "vendor": vendors,
                    "product": names,
                    "versions": versions,
                }
            )

    df = pd.DataFrame(rows, columns=config.COLUMNS)
    # Normalisation de la date en datetime (utile pour les analyses temporelles)
    df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True)
    return df


if __name__ == "__main__":
    from scripts.extraction import list_local_bulletins

    bulletins = list_local_bulletins(years=config.YEARS)[:5]
    print(f"Test sur {len(bulletins)} bulletins locaux.")
    df = consolidate(bulletins)
    print(df.head())
