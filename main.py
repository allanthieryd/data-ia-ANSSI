"""Pipeline complet ANSSI : RSS -> CVE -> enrichissement -> CSV consolide.

Usage :
    python main.py
Produit le fichier output/data_consolidee.csv.
"""

from __future__ import annotations

import config
from scripts.extraction import lister_bulletins_locaux
from scripts.consolidation import consolider


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


if __name__ == "__main__":
    main()
