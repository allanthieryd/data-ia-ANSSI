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
AVIS_DIR = DATA_DIR / "Avis"
ALERTES_DIR = DATA_DIR / "alertes"
MITRE_DIR = DATA_DIR / "mitre"
FIRST_DIR = DATA_DIR / "first"

# --- Sorties ---
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "data_consolidee.csv"
IMAGES_DIR = BASE_DIR / "images"

# Dossiers locaux des bulletins, par type, avec l'URL de base correspondante.
# Utilise par extraction.py (recensement) et consolidation.py (chargement JSON).
BULLETIN_SOURCES = {
    "Avis": (AVIS_DIR, "https://www.cert.ssi.gouv.fr/avis/"),
    "Alerte": (ALERTES_DIR, "https://www.cert.ssi.gouv.fr/alerte/"),
}

# --- Flux RSS officiels du CERT-FR (avis et alertes uniquement, cf. sujet) ---
RSS_FEEDS = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

# --- Acces reseau ---
# Delai entre deux requetes externes (section 8 du sujet : usage responsable).
REQUEST_DELAY = 2.0
# Timeout des requetes HTTP (secondes).
REQUEST_TIMEOUT = 10
# Si True, telecharge en ligne quand un fichier local manque. Desactive par
# defaut : pipeline 100% local, rapide et reproductible.
ONLINE_FALLBACK = False

# --- Filtre par defaut sur les annees de bulletins ---
YEARS = (2024, 2025, 2026)

# --- Enrichissement MITRE : cles CVSS possibles, par ordre de preference ---
# (le sujet previent que la cle varie selon la version de la metrique)
CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

# --- Bareme de severite CVSS (sujet, etape 3) ---
SEVERITY_THRESHOLDS = (
    (9.0, "Critique"),
    (7.0, "Elevee"),
    (4.0, "Moyenne"),
    (0.0, "Faible"),
)

# --- Seuils de declenchement de l'alerte email (etape 6) ---
# Une CVE est jugee critique si CVSS >= seuil OU EPSS >= seuil.
CVSS_ALERT_THRESHOLD = 9.0
EPSS_ALERT_THRESHOLD = 0.5

# --- Colonnes finales du DataFrame consolide (ordre du sujet, etape 4) ---
COLUMNS = [
    "id_anssi", "title_anssi", "type", "date", "cve",
    "cvss", "base_severity", "cwe", "cwe_desc", "epss",
    "link", "description", "vendor", "product", "versions",
]
