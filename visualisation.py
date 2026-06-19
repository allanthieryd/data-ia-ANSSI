"""Etape 5 : Interpretation et visualisation des donnees consolidees.

Genere 10 figures (PNG) dans le dossier images/ a partir du CSV produit par
main.py. Les fonctions de trace prennent le DataFrame en parametre (pas d'etat
global) et peuvent donc etre reutilisees dans un notebook.

Usage :
    python visualisation.py
"""

from __future__ import annotations

import matplotlib

# Backend non-interactif : permet de generer les PNG sans afficher de fenetre
# (utile en CI / execution batch). A definir avant d'importer pyplot.
matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402

import config  # noqa: E402


def charger_donnees() -> pd.DataFrame:
    """Charge et prepare le CSV consolide pour la visualisation.

    Renvoie un DataFrame avec colonnes renommees (libelles lisibles), types
    numeriques/date convertis et champs texte normalises.
    """
    if not config.OUTPUT_FILE.exists():
        raise FileNotFoundError(
            f"Fichier introuvable : {config.OUTPUT_FILE}\n"
            "Lancez d'abord le pipeline avec `python main.py`."
        )

    df = pd.read_csv(config.OUTPUT_FILE)
    df = df.rename(columns={
        "cvss": "CVSS", "epss": "EPSS", "date": "Date", "cve": "CVE",
        "cwe": "CWE", "type": "Type", "vendor": "Éditeur",
        "product": "Produit", "base_severity": "Base Severity",
    })

    df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
    df["EPSS"] = pd.to_numeric(df["EPSS"], errors="coerce")
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce", utc=True)
    for col in ["CWE", "Éditeur", "Produit"]:
        df[col] = df[col].fillna("")

    df = df[df["CVE"].notna()].copy()

    print(f"Données chargées : {len(df)} vulnérabilités")
    print(f"Score CVSS disponible : {df['CVSS'].notna().sum()}")
    print(f"Score EPSS disponible : {df['EPSS'].notna().sum()}")
    return df


def _sauver(fig, nom_fichier: str) -> None:
    """Finalise et enregistre une figure dans images/, puis la ferme."""
    fig.tight_layout()
    chemin = config.IMAGES_DIR / nom_fichier
    fig.savefig(chemin, dpi=150)
    plt.close(fig)
    print(f"  [OK] {chemin}")


def plot_cvss_histogram(df: pd.DataFrame) -> None:
    data = df["CVSS"].dropna()
    if data.empty:
        print("Pas de données CVSS disponibles.")
        return
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(data, bins=20, color="steelblue", edgecolor="black", alpha=0.7)
    ax.axvline(x=7.0, color="orange", linestyle="--", label="Seuil Élevé (7.0)")
    ax.axvline(x=9.0, color="red", linestyle="--", label="Seuil Critique (9.0)")
    ax.set_xlabel("Score CVSS")
    ax.set_ylabel("Nombre de vulnérabilités")
    ax.set_title("Distribution des scores CVSS")
    ax.legend()
    _sauver(fig, "viz_cvss_histogram.png")


def plot_cwe_pie(df: pd.DataFrame) -> None:
    cwe_counts = df[df["CWE"] != ""]["CWE"].value_counts().head(10)
    if cwe_counts.empty:
        print("Pas de données CWE disponibles.")
        return
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.pie(cwe_counts.values, labels=cwe_counts.index, autopct="%1.1f%%", startangle=140)
    ax.set_title("Top 10 des types de vulnérabilités (CWE)")
    _sauver(fig, "viz_cwe_pie.png")


def plot_epss_curve(df: pd.DataFrame) -> None:
    data = df["EPSS"].dropna().sort_values(ascending=False).reset_index(drop=True)
    if data.empty:
        print("Pas de données EPSS disponibles.")
        return
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(data.values, color="darkorange", linewidth=2)
    ax.axhline(y=0.5, color="red", linestyle="--", label="Seuil critique (0.5)")
    ax.set_xlabel("Vulnérabilités (triées par EPSS décroissant)")
    ax.set_ylabel("Score EPSS")
    ax.set_title("Courbe des scores EPSS")
    ax.legend()
    _sauver(fig, "viz_epss_curve.png")


def plot_top_vendors(df: pd.DataFrame) -> None:
    vendor_counts = df[df["Éditeur"] != ""]["Éditeur"].value_counts().head(15)
    if vendor_counts.empty:
        print("Pas de données éditeur disponibles.")
        return
    fig, ax = plt.subplots(figsize=(12, 6))
    vendor_counts.plot(kind="barh", ax=ax, color="teal", edgecolor="black")
    ax.set_xlabel("Nombre de vulnérabilités")
    ax.set_ylabel("Éditeur")
    ax.set_title("Top 15 des éditeurs les plus affectés")
    _sauver(fig, "viz_top_vendors.png")


def plot_cvss_epss_heatmap(df: pd.DataFrame) -> None:
    data = df[["CVSS", "EPSS"]].dropna()
    if data.empty:
        print("Pas assez de données CVSS/EPSS.")
        return
    data = data.copy()
    data["CVSS_bin"] = pd.cut(data["CVSS"], bins=[0, 4, 7, 9, 10],
                              labels=["Faible", "Moyen", "Élevé", "Critique"])
    data["EPSS_bin"] = pd.cut(data["EPSS"], bins=[0, 0.1, 0.3, 0.5, 1.0],
                              labels=["Très faible", "Faible", "Moyen", "Élevé"])
    pivot = data.groupby(["CVSS_bin", "EPSS_bin"], observed=True).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(pivot, annot=True, fmt="d", cmap="YlOrRd", ax=ax)
    ax.set_title("Heatmap : CVSS vs EPSS")
    ax.set_xlabel("Score EPSS")
    ax.set_ylabel("Score CVSS")
    _sauver(fig, "viz_heatmap_cvss_epss.png")


def plot_cvss_epss_scatter(df: pd.DataFrame) -> None:
    data = df[["CVSS", "EPSS"]].dropna()
    if data.empty:
        print("Pas assez de données CVSS/EPSS.")
        return
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(data["CVSS"], data["EPSS"], alpha=0.6, color="purple",
               edgecolors="black", linewidth=0.5)
    ax.set_xlabel("Score CVSS")
    ax.set_ylabel("Score EPSS")
    ax.set_title("Nuage de points : CVSS vs EPSS")
    ax.axhline(y=0.5, color="red", linestyle="--", alpha=0.7, label="EPSS > 0.5")
    ax.axvline(x=9.0, color="orange", linestyle="--", alpha=0.7, label="CVSS critique")
    ax.legend()
    _sauver(fig, "viz_scatter_cvss_epss.png")


def plot_cumulative_timeline(df: pd.DataFrame) -> None:
    data = df.dropna(subset=["Date"]).sort_values("Date")
    if data.empty:
        print("Pas de données de date disponibles.")
        return
    data = data.copy()
    data["cumul"] = range(1, len(data) + 1)
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(data["Date"], data["cumul"], color="darkgreen", linewidth=2)
    ax.set_xlabel("Date")
    ax.set_ylabel("Nombre cumulé de vulnérabilités")
    ax.set_title("Évolution temporelle des vulnérabilités détectées")
    ax.grid(True, alpha=0.3)
    _sauver(fig, "viz_cumulative_timeline.png")


def plot_cvss_boxplot_by_vendor(df: pd.DataFrame) -> None:
    data = df[df["Éditeur"] != ""].dropna(subset=["CVSS"])
    if data.empty:
        print("Pas assez de données.")
        return
    top_vendors = data["Éditeur"].value_counts().head(10).index
    data = data[data["Éditeur"].isin(top_vendors)]
    fig, ax = plt.subplots(figsize=(12, 6))
    # hue=Éditeur + legend=False : equivalent moderne de palette= (deprecie seul)
    sns.boxplot(data=data, x="Éditeur", y="CVSS", hue="Éditeur",
                palette="Set2", legend=False, ax=ax)
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    ax.set_title("Boxplot des scores CVSS par éditeur (Top 10)")
    ax.set_ylabel("Score CVSS")
    _sauver(fig, "viz_boxplot_cvss_vendor.png")


def plot_vendor_by_type(df: pd.DataFrame) -> None:
    data = df[df["Éditeur"] != ""]
    if data.empty:
        print("Pas de données éditeur.")
        return
    top_vendors = data["Éditeur"].value_counts().head(10).index
    data = data[data["Éditeur"].isin(top_vendors)]
    pivot = data.groupby(["Éditeur", "Type"]).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(12, 6))
    pivot.plot(kind="bar", ax=ax, edgecolor="black")
    ax.set_title("Vulnérabilités par éditeur et type de bulletin")
    ax.set_ylabel("Nombre de vulnérabilités")
    ax.set_xlabel("Éditeur")
    ax.legend(title="Type")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    _sauver(fig, "viz_vendor_by_type.png")


def plot_top_products(df: pd.DataFrame) -> None:
    product_counts = df[df["Produit"] != ""]["Produit"].value_counts().head(15)
    if product_counts.empty:
        print("Pas de données produit.")
        return
    fig, ax = plt.subplots(figsize=(12, 6))
    product_counts.plot(kind="barh", ax=ax, color="coral", edgecolor="black")
    ax.set_xlabel("Nombre de vulnérabilités")
    ax.set_ylabel("Produit")
    ax.set_title("Top 15 des produits les plus affectés")
    _sauver(fig, "viz_top_products.png")


# L'ordre du tuple definit l'ordre de generation des figures.
VISUALISATIONS = (
    plot_cvss_histogram,
    plot_cwe_pie,
    plot_epss_curve,
    plot_top_vendors,
    plot_cvss_epss_heatmap,
    plot_cvss_epss_scatter,
    plot_cumulative_timeline,
    plot_cvss_boxplot_by_vendor,
    plot_vendor_by_type,
    plot_top_products,
)


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 5 : Interprétation et Visualisation")
    print("=" * 60)

    config.IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    df = charger_donnees()

    for tracer in VISUALISATIONS:
        tracer(df)

    print(f"\nToutes les visualisations ont été générées dans '{config.IMAGES_DIR}/'.")


if __name__ == "__main__":
    main()
