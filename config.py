"""Configuration centrale du projet.

Regroupe les chemins (derives de la racine du projet via pathlib, donc
independants du repertoire courant) et les constantes partagees par les
differents modules. Importer ce module evite de disperser des chaines en dur.
"""

from __future__ import annotations

from pathlib import Path

# --- Racine du projet (dossier contenant ce fichier) ---
BASE_DIR = Path(__file__).resolve().parent

# --- Donnees sources (snapshots locaux) ---
DATA_DIR = BASE_DIR / "data"
DOSSIER_AVIS = DATA_DIR / "Avis"
DOSSIER_ALERTES = DATA_DIR / "alertes"
DOSSIER_MITRE = DATA_DIR / "mitre"
DOSSIER_FIRST = DATA_DIR / "first"

# --- Sorties ---
OUTPUT_DIR = BASE_DIR / "output"
FICHIER_SORTIE = OUTPUT_DIR / "data_consolidee.csv"
IMAGES_DIR = BASE_DIR / "images"

# Dossiers locaux des bulletins, par type, avec l'URL de base correspondante.
# Utilise par extraction.py (recensement) et consolidation.py (chargement JSON).
SOURCES_BULLETINS = {
    "Avis": (DOSSIER_AVIS, "https://www.cert.ssi.gouv.fr/avis/"),
    "Alerte": (DOSSIER_ALERTES, "https://www.cert.ssi.gouv.fr/alerte/"),
}

# --- Flux RSS officiels du CERT-FR (avis et alertes uniquement, cf. sujet) ---
FLUX_RSS = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

# --- Acces reseau ---
# Delai entre deux requetes externes (section 8 du sujet : usage responsable).
DELAI_REQUETE = 2.0
# Timeout des requetes HTTP (secondes).
TIMEOUT_REQUETE = 10
# Si True, telecharge en ligne quand un fichier local manque. Desactive par
# defaut : pipeline 100% local, rapide et reproductible.
REPLI_EN_LIGNE = False

# --- Filtre par defaut sur les annees de bulletins ---
ANNEES = (2024, 2025, 2026)

# --- Enrichissement MITRE : cles CVSS possibles, par ordre de preference ---
# (le sujet previent que la cle varie selon la version de la metrique)
CLES_CVSS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

# --- Bareme de severite CVSS (sujet, etape 3) ---
SEUILS_SEVERITE = (
    (9.0, "Critique"),
    (7.0, "Elevee"),
    (4.0, "Moyenne"),
    (0.0, "Faible"),
)

# --- Seuils de declenchement de l'alerte email (etape 6) ---
# Une CVE est jugee critique si CVSS >= seuil OU EPSS >= seuil.
SEUIL_CVSS_ALERTE = 9.0
SEUIL_EPSS_ALERTE = 0.5

# --- Colonnes finales du DataFrame consolide (ordre du sujet, etape 4) ---
COLONNES = [
    "id_anssi", "titre_anssi", "type", "date", "cve",
    "cvss", "base_severity", "cwe", "cwe_desc", "epss",
    "lien", "description", "editeur", "produit", "versions",
]
