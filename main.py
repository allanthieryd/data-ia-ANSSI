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
from scripts.extraction import list_local_bulletins
from scripts.consolidation import consolidate
from scripts.alerte import alert_critical


def _critical_cves(df: pd.DataFrame) -> list[dict]:
    """Selectionne les CVE critiques (CVSS >= seuil OU EPSS >= seuil).

    Triees par gravite decroissante puis dedupliquees par CVE (on conserve la
    ligne au plus haut score).
    """
    df = df.assign(
        _cvss=pd.to_numeric(df["cvss"], errors="coerce"),
        _epss=pd.to_numeric(df["epss"], errors="coerce"),
    )
    critical = df[(df["_cvss"] >= config.CVSS_ALERT_THRESHOLD)
                  | (df["_epss"] >= config.EPSS_ALERT_THRESHOLD)]
    critical = critical.sort_values(["_cvss", "_epss"], ascending=False)
    critical = critical.drop_duplicates("cve")
    return critical[["cve", "product", "cvss", "epss"]].to_dict("records")


def _alert(df: pd.DataFrame) -> None:
    """Envoie l'alerte email si le .env est configure ; ne bloque jamais le pipeline."""
    critical = _critical_cves(df)
    print(f"\n== Etape 6 : {len(critical)} CVE critiques "
          f"(CVSS >= {config.CVSS_ALERT_THRESHOLD} ou EPSS >= {config.EPSS_ALERT_THRESHOLD}) ==")
    if not critical:
        return
    if not os.environ.get("EMAIL_SENDER"):
        print("   [INFO] Email non configure (.env) : alerte non envoyee.")
        return
    try:
        alert_critical(critical)
    except Exception as e:  # le CSV est deja ecrit : on n'echoue pas pour autant
        print(f"   [ATTENTION] Envoi de l'alerte echoue : {e}")


def main() -> None:
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"== Etape 1 : recensement des bulletins locaux (annees {config.YEARS}) ==")
    bulletins = list_local_bulletins(years=config.YEARS)
    print(f"  -> {len(bulletins)} bulletins reperes\n")

    print("== Etapes 2-4 : extraction CVE, enrichissement, consolidation ==")
    df = consolidate(bulletins)

    df.to_csv(config.OUTPUT_FILE, index=False, encoding="utf-8-sig")
    print(f"\n== Termine : {len(df)} lignes ecrites dans {config.OUTPUT_FILE} ==")
    print(f"   {df['cve'].nunique()} CVE uniques, "
          f"{df['id_anssi'].nunique()} bulletins.")

    _alert(df)


if __name__ == "__main__":
    main()
