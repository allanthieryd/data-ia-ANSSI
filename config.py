"""Configuration centrale du projet.

Regroupe les chemins (derives de la racine du projet via pathlib, donc
independants du repertoire courant) et les constantes partagees par les
differents modules. Importer ce module evite de disperser des chaines en dur.
"""

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
AVIS_DIR = DATA_DIR / "Avis"
ALERTES_DIR = DATA_DIR / "alertes"
MITRE_DIR = DATA_DIR / "mitre"
FIRST_DIR = DATA_DIR / "first"

OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "data_consolidee.csv"
IMAGES_DIR = BASE_DIR / "images"

BULLETIN_SOURCES = {
    "Avis": (AVIS_DIR, "https://www.cert.ssi.gouv.fr/avis/"),
    "Alerte": (ALERTES_DIR, "https://www.cert.ssi.gouv.fr/alerte/"),
}

RSS_FEEDS = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

REQUEST_DELAY = 2.0
REQUEST_TIMEOUT = 10
ONLINE_FALLBACK = False

YEARS = (2024, 2025, 2026)

CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

SEVERITY_THRESHOLDS = (
    (9.0, "Critique"),
    (7.0, "Elevee"),
    (4.0, "Moyenne"),
    (0.0, "Faible"),
)

CVSS_ALERT_THRESHOLD = 9.0
EPSS_ALERT_THRESHOLD = 0.5

COLUMNS = [
    "id_anssi", "title_anssi", "type", "date", "cve",
    "cvss", "base_severity", "cwe", "cwe_desc", "epss",
    "link", "description", "vendor", "product", "versions",
]
