"""Pipeline complet ANSSI : RSS -> CVE -> enrichissement -> CSV consolide.

Usage :
    python main.py
Produit le fichier output/data_consolidee.csv puis, si le .env est configure,
envoie un mail recapitulatif des CVE critiques.
"""

from __future__ import annotations

import os

import pandas as pd

import config
from scripts.extraction import lister_bulletins_locaux
from scripts.consolidation import consolider
from scripts.alerte import alerter_critiques


def _cves_critiques(df: pd.DataFrame) -> list[dict]:
    """Selectionne les CVE critiques (CVSS >= seuil OU EPSS >= seuil).

    Triees par gravite decroissante puis dedupliquees par CVE (on conserve la
    ligne au plus haut score).
    """
    df = df.assign(
        _cvss=pd.to_numeric(df["cvss"], errors="coerce"),
        _epss=pd.to_numeric(df["epss"], errors="coerce"),
    )
    critiques = df[(df["_cvss"] >= config.SEUIL_CVSS_ALERTE)
                   | (df["_epss"] >= config.SEUIL_EPSS_ALERTE)]
    critiques = critiques.sort_values(["_cvss", "_epss"], ascending=False)
    critiques = critiques.drop_duplicates("cve")
    return critiques[["cve", "produit", "cvss", "epss"]].to_dict("records")


def _alerter(df: pd.DataFrame) -> None:
    """Envoie l'alerte email si le .env est configure ; ne bloque jamais le pipeline."""
    critiques = _cves_critiques(df)
    print(f"\n== Etape 6 : {len(critiques)} CVE critiques "
          f"(CVSS >= {config.SEUIL_CVSS_ALERTE} ou EPSS >= {config.SEUIL_EPSS_ALERTE}) ==")
    if not critiques:
        return
    if not os.environ.get("EMAIL_SENDER"):
        print("   [INFO] Email non configure (.env) : alerte non envoyee.")
        return
    try:
        alerter_critiques(critiques)
    except Exception as e:  # le CSV est deja ecrit : on n'echoue pas pour autant
        print(f"   [ATTENTION] Envoi de l'alerte echoue : {e}")


def main() -> None:
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"== Etape 1 : recensement des bulletins locaux (annees {config.ANNEES}) ==")
    bulletins = lister_bulletins_locaux(annees=config.ANNEES)
    print(f"  -> {len(bulletins)} bulletins reperes\n")

    print("== Etapes 2-4 : extraction CVE, enrichissement, consolidation ==")
    df = consolider(bulletins)

    df.to_csv(config.FICHIER_SORTIE, index=False, encoding="utf-8-sig")
    print(f"\n== Termine : {len(df)} lignes ecrites dans {config.FICHIER_SORTIE} ==")
    print(f"   {df['cve'].nunique()} CVE uniques, "
          f"{df['id_anssi'].nunique()} bulletins.")

    _alerter(df)


if __name__ == "__main__":
    main()
