"""Pipeline complet ANSSI : RSS -> CVE -> enrichissement -> CSV consolide.

Usage :
    python main.py
Produit le fichier data_consolidee.csv a la racine du projet.
"""

import sys
import os

# Permet d'importer les modules du dossier scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))

from extraction import lister_bulletins_locaux
from consolidation import consolider

DOSSIER_SORTIE = "output"
FICHIER_SORTIE = os.path.join(DOSSIER_SORTIE, "data_consolidee.csv")
ANNEES = (2024, 2025, 2026)  # filtre sur les bulletins recents


def main() -> None:
    os.makedirs(DOSSIER_SORTIE, exist_ok=True)

    print(f"== Etape 1 : recensement des bulletins locaux (annees {ANNEES}) ==")
    bulletins = lister_bulletins_locaux(annees=ANNEES)
    print(f"  -> {len(bulletins)} bulletins reperes\n")

    print("== Etapes 2-4 : extraction CVE, enrichissement, consolidation ==")
    df = consolider(bulletins)

    df.to_csv(FICHIER_SORTIE, index=False, encoding="utf-8-sig")
    print(f"\n== Termine : {len(df)} lignes ecrites dans {FICHIER_SORTIE} ==")
    print(f"   {df['cve'].nunique()} CVE uniques, "
          f"{df['id_anssi'].nunique()} bulletins.")


if __name__ == "__main__":
    main()
