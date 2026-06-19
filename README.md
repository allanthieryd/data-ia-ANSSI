# Analyse des vulnérabilités ANSSI / CERT-FR

Pipeline de collecte, d'enrichissement et de visualisation des bulletins de
sécurité du [CERT-FR](https://www.cert.ssi.gouv.fr/) (avis et alertes).

Le projet récupère les bulletins, en extrait les CVE, les enrichit via les API
**MITRE** (score CVSS, CWE, produits affectés) et **FIRST** (score EPSS), puis
consolide le tout dans un CSV exploitable et une série de visualisations.

## Architecture

```
.
├── main.py              # Point d'entrée : lance le pipeline complet
├── config.py            # Chemins (pathlib) et constantes partagées
├── visualisation.py     # Étape 5 : génère 10 figures depuis le CSV
├── scripts/             # Package du pipeline
│   ├── extraction.py    #   Étapes 1-2 : bulletins (RSS / local) + CVE
│   ├── enrichissement.py#   Étape 3 : MITRE (CVSS, CWE) + FIRST (EPSS)
│   ├── consolidation.py #   Étape 4 : DataFrame consolidé
│   └── alerte.py        #   Étape 6 : envoi d'alerte email (SMTP)
├── data/                # Snapshots locaux (avis, alertes, mitre, first) — non versionné
├── output/              # CSV consolidé généré — non versionné
├── images/              # Visualisations PNG générées — non versionné
├── requirements.txt
└── .env.example         # Modèle de configuration des secrets SMTP
```

Le pipeline fonctionne **100 % en local** par défaut (lecture des snapshots du
dossier `data/`). Un repli en ligne sur les API est possible en activant
`REPLI_EN_LIGNE` dans [config.py](config.py).

## Prérequis

- Python 3.10+
- Les snapshots de données dans `data/` (`Avis/`, `alertes/`, `mitre/`, `first/`)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

## Utilisation

### 1. Générer le CSV consolidé

```bash
python main.py
```

Produit `output/data_consolidee.csv` (une ligne par couple bulletin × CVE).
Les années traitées se règlent via `ANNEES` dans [config.py](config.py).

### 2. Générer les visualisations

```bash
python visualisation.py
```

Produit 10 figures dans `images/` (distribution CVSS, top éditeurs/produits,
heatmap CVSS×EPSS, évolution temporelle, etc.).

### 3. Envoyer une alerte email (optionnel)

Copiez `.env.example` vers `.env` et renseignez vos identifiants SMTP Gmail
(utilisez un [mot de passe d'application](https://myaccount.google.com/apppasswords)) :

```bash
cp .env.example .env
python -m scripts.alerte    # envoie une alerte de test
```

### Exécuter un module du pipeline isolément

Chaque module embarque un test manuel exécutable depuis la racine :

```bash
python -m scripts.extraction
python -m scripts.enrichissement
python -m scripts.consolidation
```

## Configuration

Tous les chemins et constantes sont centralisés dans [config.py](config.py) :
dossiers de données/sortie, flux RSS, délai entre requêtes, barème de sévérité,
colonnes du DataFrame. Modifiez ce fichier plutôt que les modules.

## Sources de données

- **CERT-FR** — bulletins (avis / alertes) via flux RSS et JSON détaillé
- **MITRE** (`cveawg.mitre.org`) — description, CVSS, CWE, produits affectés
- **FIRST** (`api.first.org`) — score EPSS (probabilité d'exploitation)
