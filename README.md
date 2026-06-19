# Analyse des vulnérabilités ANSSI / CERT-FR

Pipeline de collecte, d'enrichissement et de visualisation des bulletins de
sécurité du [CERT-FR](https://www.cert.ssi.gouv.fr/) (avis et alertes).

Le projet récupère les bulletins, en extrait les CVE, les enrichit via les API
**MITRE** (score CVSS, CWE, produits affectés) et **FIRST** (score EPSS), puis
consolide le tout dans un CSV exploitable, une série de visualisations et un
**notebook d'analyse & Machine Learning**.

## Livrables

1. **Code Python** : pipeline complet (extraction → enrichissement → consolidation
   → alertes), documenté ci-dessous.
2. **Données consolidées** : [output/data_consolidee.csv](output/data_consolidee.csv)
   (CVE issues des bulletins ANSSI enrichies par MITRE & FIRST).
3. **Notebook d'analyse** : [notebooks/analyse_anssi.ipynb](notebooks/analyse_anssi.ipynb)
   et son export [notebooks/analyse_anssi.html](notebooks/analyse_anssi.html) —
   chargement du CSV, exploration, visualisations, **modèle supervisé** (classification
   de la haute sévérité) et **modèle non supervisé** (segmentation KMeans), avec
   validation des deux modèles.

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
├── notebooks/           # Livrable 3 : analyse & Machine Learning
│   ├── analyse_anssi.ipynb   #   Notebook (exploration, viz, ML supervisé + non supervisé)
│   └── analyse_anssi.html    #   Export HTML du notebook exécuté
├── data/                # Snapshots locaux (avis, alertes, mitre, first) — non versionné
├── output/              # CSV consolidé généré — non versionné
├── images/              # Visualisations PNG générées — non versionné
├── requirements.txt
└── .env.example         # Modèle de configuration des secrets SMTP
```

Le pipeline fonctionne **100 % en local** par défaut (lecture des snapshots du
dossier `data/`). Un repli en ligne sur les API est possible en activant
`ONLINE_FALLBACK` dans [config.py](config.py).

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
Les années traitées se règlent via `YEARS` dans [config.py](config.py).

### 2. Générer les visualisations

```bash
python visualisation.py
```

Produit 10 figures dans `images/` (distribution CVSS, top éditeurs/produits,
heatmap CVSS×EPSS, évolution temporelle, etc.).

### 3. Notebook d'analyse & Machine Learning

Le notebook [notebooks/analyse_anssi.ipynb](notebooks/analyse_anssi.ipynb)
charge le CSV consolidé puis enchaîne : exploration du DataFrame, une quinzaine
de visualisations, un **modèle supervisé** (classification de la haute sévérité
CVSS ≥ 7 à partir de la description TF-IDF, du CWE et de l'EPSS) et un **modèle
non supervisé** (segmentation KMeans des profils de risque dans le plan
CVSS × EPSS), chacun **validé** (validation croisée, ROC-AUC, matrice de
confusion / silhouette, Davies-Bouldin).

Ouvrir et exécuter le notebook :

```bash
# (une fois) enregistrer le venv comme kernel Jupyter
python -m ipykernel install --user --name anssi-venv --display-name "Python (ANSSI)"

# lancer Jupyter et ouvrir notebooks/analyse_anssi.ipynb
jupyter lab        # ou : jupyter notebook
```

Régénérer l'export HTML (et ré-exécuter toutes les cellules) en ligne de commande :

```bash
jupyter nbconvert --to notebook --execute --inplace \
    --ExecutePreprocessor.kernel_name=anssi-venv notebooks/analyse_anssi.ipynb
jupyter nbconvert --to html notebooks/analyse_anssi.ipynb
```

> Le notebook lit `output/data_consolidee.csv` : lancez `python main.py` au
> préalable s'il n'existe pas encore.

### 4. Envoyer une alerte email (optionnel)

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
