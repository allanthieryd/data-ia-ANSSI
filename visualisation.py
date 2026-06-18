import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# --- Dossier de sortie des visualisations ---
IMAGES_DIR = "images"
os.makedirs(IMAGES_DIR, exist_ok=True)

# --- Chargement des données (CSV produit par main.py / consolidation.py) ---
df = pd.read_csv(os.path.join("output", "data_consolidee.csv"))

# Le pipeline modulaire utilise des noms de colonnes en minuscules ; on les
# renomme vers les libellés attendus par les fonctions de visualisation.
df = df.rename(columns={
    "cvss": "CVSS", "epss": "EPSS", "date": "Date", "cve": "CVE",
    "cwe": "CWE", "type": "Type", "editeur": "Éditeur",
    "produit": "Produit", "base_severity": "Base Severity",
})

# Conversion des types
df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
df["EPSS"] = pd.to_numeric(df["EPSS"], errors="coerce")
df["Date"] = pd.to_datetime(df["Date"], errors="coerce", utc=True)

# Les champs texte manquants (CWE, Éditeur, Produit) deviennent "" pour les filtres
for col in ["CWE", "Éditeur", "Produit"]:
    df[col] = df[col].fillna("")

# Filtrer les lignes sans CVE (par sécurité ; chaque ligne a normalement un CVE)
df_cve = df[df["CVE"].notna()].copy()

print(f"Données chargées : {len(df_cve)} vulnérabilités")
print(f"Score CVSS disponible : {df_cve['CVSS'].notna().sum()}")
print(f"Score EPSS disponible : {df_cve['EPSS'].notna().sum()}")

# --- 1. Histogramme des scores CVSS ---
def plot_cvss_histogram():
    fig, ax = plt.subplots(figsize=(10, 6))
    data = df_cve["CVSS"].dropna()
    ax.hist(data, bins=20, color="steelblue", edgecolor="black", alpha=0.7)
    ax.axvline(x=7.0, color="orange", linestyle="--", label="Seuil Élevé (7.0)")
    ax.axvline(x=9.0, color="red", linestyle="--", label="Seuil Critique (9.0)")
    ax.set_xlabel("Score CVSS")
    ax.set_ylabel("Nombre de vulnérabilités")
    ax.set_title("Distribution des scores CVSS")
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_cvss_histogram.png"), dpi=150)
    plt.show()


# --- 2. Diagramme circulaire des types CWE ---
def plot_cwe_pie():
    cwe_counts = df_cve[df_cve["CWE"] != ""]["CWE"].value_counts().head(10)
    if cwe_counts.empty:
        print("Pas de données CWE disponibles.")
        return
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.pie(cwe_counts.values, labels=cwe_counts.index, autopct="%1.1f%%", startangle=140)
    ax.set_title("Top 10 des types de vulnérabilités (CWE)")
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_cwe_pie.png"), dpi=150)
    plt.show()


# --- 3. Courbe des scores EPSS (triés) ---
def plot_epss_curve():
    data = df_cve["EPSS"].dropna().sort_values(ascending=False).reset_index(drop=True)
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
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_epss_curve.png"), dpi=150)
    plt.show()


# --- 4. Classement des éditeurs les plus affectés ---
def plot_top_vendors():
    vendor_counts = df_cve[df_cve["Éditeur"] != ""]["Éditeur"].value_counts().head(15)
    if vendor_counts.empty:
        print("Pas de données éditeur disponibles.")
        return
    fig, ax = plt.subplots(figsize=(12, 6))
    vendor_counts.plot(kind="barh", ax=ax, color="teal", edgecolor="black")
    ax.set_xlabel("Nombre de vulnérabilités")
    ax.set_ylabel("Éditeur")
    ax.set_title("Top 15 des éditeurs les plus affectés")
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_top_vendors.png"), dpi=150)
    plt.show()


# --- 5. Heatmap corrélation CVSS / EPSS ---
def plot_cvss_epss_heatmap():
    data = df_cve[["CVSS", "EPSS"]].dropna()
    if data.empty:
        print("Pas assez de données CVSS/EPSS.")
        return
    # Créer des bins pour la heatmap
    data["CVSS_bin"] = pd.cut(data["CVSS"], bins=[0, 4, 7, 9, 10], labels=["Faible", "Moyen", "Élevé", "Critique"])
    data["EPSS_bin"] = pd.cut(data["EPSS"], bins=[0, 0.1, 0.3, 0.5, 1.0], labels=["Très faible", "Faible", "Moyen", "Élevé"])
    pivot = data.groupby(["CVSS_bin", "EPSS_bin"], observed=True).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(pivot, annot=True, fmt="d", cmap="YlOrRd", ax=ax)
    ax.set_title("Heatmap : CVSS vs EPSS")
    ax.set_xlabel("Score EPSS")
    ax.set_ylabel("Score CVSS")
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_heatmap_cvss_epss.png"), dpi=150)
    plt.show()


# --- 6. Nuage de points CVSS vs EPSS ---
def plot_cvss_epss_scatter():
    data = df_cve[["CVSS", "EPSS"]].dropna()
    if data.empty:
        print("Pas assez de données CVSS/EPSS.")
        return
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(data["CVSS"], data["EPSS"], alpha=0.6, color="purple", edgecolors="black", linewidth=0.5)
    ax.set_xlabel("Score CVSS")
    ax.set_ylabel("Score EPSS")
    ax.set_title("Nuage de points : CVSS vs EPSS")
    ax.axhline(y=0.5, color="red", linestyle="--", alpha=0.7, label="EPSS > 0.5")
    ax.axvline(x=9.0, color="orange", linestyle="--", alpha=0.7, label="CVSS critique")
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_scatter_cvss_epss.png"), dpi=150)
    plt.show()


# --- 7. Courbe cumulative des vulnérabilités dans le temps ---
def plot_cumulative_timeline():
    data = df_cve.dropna(subset=["Date"]).sort_values("Date")
    if data.empty:
        print("Pas de données de date disponibles.")
        return
    data["cumul"] = range(1, len(data) + 1)
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(data["Date"], data["cumul"], color="darkgreen", linewidth=2)
    ax.set_xlabel("Date")
    ax.set_ylabel("Nombre cumulé de vulnérabilités")
    ax.set_title("Évolution temporelle des vulnérabilités détectées")
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_cumulative_timeline.png"), dpi=150)
    plt.show()


# --- 8. Boxplot des scores CVSS par éditeur ---
def plot_cvss_boxplot_by_vendor():
    data = df_cve[df_cve["Éditeur"] != ""].dropna(subset=["CVSS"])
    if data.empty:
        print("Pas assez de données.")
        return
    # Garder les top éditeurs
    top_vendors = data["Éditeur"].value_counts().head(10).index
    data = data[data["Éditeur"].isin(top_vendors)]
    fig, ax = plt.subplots(figsize=(12, 6))
    sns.boxplot(data=data, x="Éditeur", y="CVSS", ax=ax, palette="Set2")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
    ax.set_title("Boxplot des scores CVSS par éditeur (Top 10)")
    ax.set_ylabel("Score CVSS")
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_boxplot_cvss_vendor.png"), dpi=150)
    plt.show()


# --- 9. Nombre de vulnérabilités par éditeur et type de bulletin ---
def plot_vendor_by_type():
    data = df_cve[df_cve["Éditeur"] != ""]
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
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_vendor_by_type.png"), dpi=150)
    plt.show()


# --- 10. Top produits les plus affectés ---
def plot_top_products():
    product_counts = df_cve[df_cve["Produit"] != ""]["Produit"].value_counts().head(15)
    if product_counts.empty:
        print("Pas de données produit.")
        return
    fig, ax = plt.subplots(figsize=(12, 6))
    product_counts.plot(kind="barh", ax=ax, color="coral", edgecolor="black")
    ax.set_xlabel("Nombre de vulnérabilités")
    ax.set_ylabel("Produit")
    ax.set_title("Top 15 des produits les plus affectés")
    plt.tight_layout()
    plt.savefig(os.path.join(IMAGES_DIR, "viz_top_products.png"), dpi=150)
    plt.show()


# --- Exécution de toutes les visualisations ---
if __name__ == "__main__":
    print("=" * 60)
    print("ÉTAPE 5 : Interprétation et Visualisation")
    print("=" * 60)

    plot_cvss_histogram()
    plot_cwe_pie()
    plot_epss_curve()
    plot_top_vendors()
    plot_cvss_epss_heatmap()
    plot_cvss_epss_scatter()
    plot_cumulative_timeline()
    plot_cvss_boxplot_by_vendor()
    plot_vendor_by_type()
    plot_top_products()

    print(f"\nToutes les visualisations ont été générées et sauvegardées dans '{IMAGES_DIR}/'.")
