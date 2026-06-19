"""
Étape 6 : Machine Learning appliqué aux données de vulnérabilités ANSSI

Modèle non supervisé : KMeans Clustering
    - Objectif : Regrouper les vulnérabilités par profils de risque similaires
    - Features : CVSS, EPSS, type de bulletin (encodé)
    - Validation : Silhouette Score, méthode du coude (Elbow)

Modèle supervisé : Random Forest Classifier
    - Objectif : Prédire la criticité (Base Severity) d'une vulnérabilité
    - Features : CVSS, EPSS, CWE (encodé), Type bulletin, Éditeur (encodé)
    - Validation : Accuracy, Classification Report, Matrice de confusion, Courbe ROC
"""

import matplotlib

# Backend non-interactif : genere les PNG sans ouvrir de fenetre (cf. visualisation.py).
matplotlib.use("Agg")

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.metrics import (
    silhouette_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_curve,
    auc,
)
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier

import warnings

import config

warnings.filterwarnings("ignore")

# --- Chargement et préparation des données ---

def load_and_prepare_data():
    """Charge le CSV consolide et prépare les données pour le ML.

    Lit output/data_consolidee.csv (produit par main.py) et renomme les colonnes
    minuscules du pipeline vers les libellés attendus par les modèles.
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

    # Filtrer : garder uniquement les lignes avec CVE et scores disponibles
    df_ml = df[df["CVE"].notna() & df["CVSS"].notna() & df["EPSS"].notna()].copy()
    df_ml = df_ml.reset_index(drop=True)

    print(f"Données disponibles pour le ML : {len(df_ml)} lignes")
    print(f"Colonnes : {list(df_ml.columns)}")
    return df_ml


# =============================================================================
# MODÈLE NON SUPERVISÉ : KMeans Clustering
# =============================================================================

def clustering_analysis(df_ml):
    """
    Clustering KMeans pour regrouper les vulnérabilités par profil de risque.

    Justification :
    - Les vulnérabilités peuvent être regroupées selon leur combinaison CVSS/EPSS
    - Cela permet d'identifier des profils : critique & exploité, critique & peu exploité, etc.
    - Utile pour la priorisation sans labels prédéfinis
    """
    print("\n" + "=" * 60)
    print("MODÈLE NON SUPERVISÉ : KMeans Clustering")
    print("=" * 60)

    # Features pour le clustering
    features_cluster = ["CVSS", "EPSS"]
    # Ajouter le type de bulletin encodé
    df_ml["Type_encoded"] = LabelEncoder().fit_transform(df_ml["Type"])
    features_cluster.append("Type_encoded")

    X_cluster = df_ml[features_cluster].copy()

    # Normalisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_cluster)

    # --- Méthode du coude (Elbow) pour choisir k ---
    inertias = []
    silhouettes = []
    K_range = range(2, 8)

    for k in K_range:
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = km.fit_predict(X_scaled)
        inertias.append(km.inertia_)
        silhouettes.append(silhouette_score(X_scaled, labels))

    # Plot Elbow
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].plot(K_range, inertias, "bo-", linewidth=2)
    axes[0].set_xlabel("Nombre de clusters (k)")
    axes[0].set_ylabel("Inertie")
    axes[0].set_title("Méthode du coude (Elbow)")
    axes[0].grid(True, alpha=0.3)

    axes[1].plot(K_range, silhouettes, "rs-", linewidth=2)
    axes[1].set_xlabel("Nombre de clusters (k)")
    axes[1].set_ylabel("Silhouette Score")
    axes[1].set_title("Score Silhouette par nombre de clusters")
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_elbow_silhouette.png", dpi=150)
    plt.close()

    # Choisir le meilleur k (max silhouette)
    best_k = list(K_range)[np.argmax(silhouettes)]
    print(f"\nMeilleur nombre de clusters (silhouette max) : k = {best_k}")
    print(f"Silhouette Score : {max(silhouettes):.3f}")

    # --- Clustering final ---
    kmeans = KMeans(n_clusters=best_k, random_state=42, n_init=10)
    df_ml["Cluster"] = kmeans.fit_predict(X_scaled)

    # --- Visualisation PCA 2D ---
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)

    fig, ax = plt.subplots(figsize=(10, 7))
    scatter = ax.scatter(
        X_pca[:, 0], X_pca[:, 1],
        c=df_ml["Cluster"], cmap="viridis", alpha=0.7, edgecolors="black", linewidth=0.3
    )
    ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)")
    ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)")
    ax.set_title(f"Clustering des vulnérabilités (k={best_k}) - Projection PCA")
    plt.colorbar(scatter, label="Cluster")
    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_clustering_pca.png", dpi=150)
    plt.close()

    # --- Visualisation CVSS vs EPSS coloré par cluster ---
    fig, ax = plt.subplots(figsize=(10, 7))
    for cluster_id in range(best_k):
        mask = df_ml["Cluster"] == cluster_id
        ax.scatter(
            df_ml.loc[mask, "CVSS"], df_ml.loc[mask, "EPSS"],
            label=f"Cluster {cluster_id}", alpha=0.7, edgecolors="black", linewidth=0.3
        )
    ax.set_xlabel("Score CVSS")
    ax.set_ylabel("Score EPSS")
    ax.set_title("Clusters de vulnérabilités : CVSS vs EPSS")
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_clustering_cvss_epss.png", dpi=150)
    plt.close()

    # --- Statistiques par cluster ---
    print("\nStatistiques par cluster :")
    cluster_stats = df_ml.groupby("Cluster")[["CVSS", "EPSS"]].agg(["mean", "std", "count"])
    print(cluster_stats.to_string())

    # Interprétation des clusters
    print("\nInterprétation des clusters :")
    for c in range(best_k):
        subset = df_ml[df_ml["Cluster"] == c]
        cvss_mean = subset["CVSS"].mean()
        epss_mean = subset["EPSS"].mean()
        label = ""
        if cvss_mean >= 7 and epss_mean >= 0.3:
            label = "⚠️  CRITIQUE : Score élevé ET forte probabilité d'exploitation"
        elif cvss_mean >= 7:
            label = "🔶 Sévère mais peu exploité"
        elif epss_mean >= 0.3:
            label = "🔸 Score modéré mais activement exploité"
        else:
            label = "🟢 Risque faible"
        print(f"  Cluster {c} : CVSS moy={cvss_mean:.1f}, EPSS moy={epss_mean:.3f} → {label}")

    return df_ml


# =============================================================================
# MODÈLE SUPERVISÉ : Random Forest - Prédiction de la criticité
# =============================================================================

def supervised_classification(df_ml):
    """
    Classification Random Forest pour prédire la Base Severity.

    Justification :
    - Prédire automatiquement la criticité d'une vulnérabilité permet de prioriser
      les alertes même quand le score CVSS n'est pas encore disponible
    - Random Forest est robuste, gère bien les features mixtes, et fournit
      l'importance des variables
    - La validation croisée assure la fiabilité du modèle
    """
    print("\n" + "=" * 60)
    print("MODÈLE SUPERVISÉ : Random Forest - Prédiction de criticité")
    print("=" * 60)

    # Préparer la cible : Base Severity
    df_sup = df_ml[df_ml["Base Severity"] != ""].copy()
    df_sup = df_sup[df_sup["Base Severity"].notna()].copy()

    if len(df_sup) < 10:
        print("⚠️  Pas assez de données avec Base Severity pour entraîner un modèle supervisé.")
        print("   Élargissez le filtre d'années (config.YEARS) puis relancez `python main.py`.")
        return

    # Encodage de la cible
    le_target = LabelEncoder()
    df_sup["Severity_encoded"] = le_target.fit_transform(df_sup["Base Severity"])
    target_names = le_target.classes_
    print(f"\nClasses de criticité : {list(target_names)}")
    print(f"Distribution :\n{df_sup['Base Severity'].value_counts().to_string()}")

    # --- Préparation des features ---
    # IMPORTANT : on EXCLUT volontairement CVSS des features.
    # Base Severity est derivee deterministiquement de CVSS (cf. config.SEVERITY_THRESHOLDS),
    # donc l'inclure provoquerait une fuite de cible (accuracy artificielle de 100%).
    # On predit la criticite a partir des AUTRES signaux (EPSS, CWE, type, editeur),
    # ce qui correspond a l'objectif : estimer la criticite quand CVSS n'est pas dispo.
    feature_cols = ["EPSS"]

    # Encoder CWE
    df_sup["CWE_encoded"] = LabelEncoder().fit_transform(df_sup["CWE"].fillna("Inconnu"))
    feature_cols.append("CWE_encoded")

    # Encoder Type bulletin
    df_sup["Type_encoded"] = LabelEncoder().fit_transform(df_sup["Type"])
    feature_cols.append("Type_encoded")

    # Encoder Éditeur (top N pour éviter trop de dimensions)
    top_vendors = df_sup["Éditeur"].value_counts().head(20).index
    df_sup["Vendor_simplified"] = df_sup["Éditeur"].apply(lambda x: x if x in top_vendors else "Autre")
    df_sup["Vendor_encoded"] = LabelEncoder().fit_transform(df_sup["Vendor_simplified"])
    feature_cols.append("Vendor_encoded")

    X = df_sup[feature_cols].values
    y = df_sup["Severity_encoded"].values

    print(f"\nFeatures utilisées : {feature_cols}")
    print(f"Taille du dataset : {len(X)} échantillons")

    # --- Split train/test ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
    )

    # --- Entraînement ---
    rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
    rf.fit(X_train, y_train)

    # --- Prédiction ---
    y_pred = rf.predict(X_test)
    accuracy = rf.score(X_test, y_test)

    print(f"\n--- Résultats sur le jeu de test ---")
    print(f"Accuracy : {accuracy:.3f}")
    print(f"\nClassification Report :")
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))

    # --- Validation croisée ---
    cv_scores = cross_val_score(rf, X, y, cv=min(5, len(np.unique(y))), scoring="accuracy")
    print(f"Validation croisée (5-fold) : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # --- Matrice de confusion ---
    fig, ax = plt.subplots(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=target_names)
    disp.plot(ax=ax, cmap="Blues", values_format="d")
    ax.set_title("Matrice de confusion - Prédiction de criticité")
    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_confusion_matrix.png", dpi=150)
    plt.close()

    # --- Importance des features ---
    importances = rf.feature_importances_
    fig, ax = plt.subplots(figsize=(10, 6))
    sorted_idx = np.argsort(importances)
    ax.barh(range(len(feature_cols)), importances[sorted_idx], color="steelblue", edgecolor="black")
    ax.set_yticks(range(len(feature_cols)))
    ax.set_yticklabels([feature_cols[i] for i in sorted_idx])
    ax.set_xlabel("Importance")
    ax.set_title("Importance des features - Random Forest")
    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_feature_importance.png", dpi=150)
    plt.close()

    # --- Courbe ROC (multi-classe, One-vs-Rest) ---
    if len(target_names) >= 2:
        try:
            from sklearn.preprocessing import label_binarize
            y_test_bin = label_binarize(y_test, classes=range(len(target_names)))
            y_proba = rf.predict_proba(X_test)

            fig, ax = plt.subplots(figsize=(10, 7))
            for i, class_name in enumerate(target_names):
                if y_test_bin.shape[1] > 1:
                    fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_proba[:, i])
                else:
                    fpr, tpr, _ = roc_curve(y_test_bin.ravel(), y_proba[:, 1])
                roc_auc = auc(fpr, tpr)
                ax.plot(fpr, tpr, linewidth=2, label=f"{class_name} (AUC = {roc_auc:.2f})")

            ax.plot([0, 1], [0, 1], "k--", linewidth=1, label="Aléatoire")
            ax.set_xlabel("Taux de faux positifs (FPR)")
            ax.set_ylabel("Taux de vrais positifs (TPR)")
            ax.set_title("Courbes ROC - Classification de criticité")
            ax.legend(loc="lower right")
            ax.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(config.IMAGES_DIR / "ml_roc_curves.png", dpi=150)
            plt.close()
        except Exception as e:
            print(f"Courbe ROC non disponible : {e}")

    # --- Distribution des prédictions vs réalité ---
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    pd.Series(y_test).map(lambda x: target_names[x]).value_counts().plot(
        kind="bar", ax=axes[0], color="steelblue", edgecolor="black"
    )
    axes[0].set_title("Distribution réelle (test)")
    axes[0].set_ylabel("Count")

    pd.Series(y_pred).map(lambda x: target_names[x]).value_counts().plot(
        kind="bar", ax=axes[1], color="coral", edgecolor="black"
    )
    axes[1].set_title("Distribution prédite (test)")
    axes[1].set_ylabel("Count")

    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_distribution_pred_vs_real.png", dpi=150)
    plt.close()

    return rf, feature_cols, le_target


# =============================================================================
# VISUALISATIONS COMPLÉMENTAIRES ML
# =============================================================================

def plot_cluster_severity_distribution(df_ml):
    """Visualise la distribution de Base Severity dans chaque cluster."""
    data = df_ml[df_ml["Base Severity"].notna() & (df_ml["Base Severity"] != "")]
    if data.empty or "Cluster" not in data.columns:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    pivot = data.groupby(["Cluster", "Base Severity"]).size().unstack(fill_value=0)
    pivot.plot(kind="bar", ax=ax, edgecolor="black")
    ax.set_title("Distribution de la criticité par cluster")
    ax.set_xlabel("Cluster")
    ax.set_ylabel("Nombre de vulnérabilités")
    ax.legend(title="Severity")
    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_cluster_severity.png", dpi=150)
    plt.close()


def plot_cluster_cwe_analysis(df_ml):
    """Top CWE par cluster."""
    data = df_ml[(df_ml["CWE"] != "") & df_ml["CWE"].notna()]
    if data.empty or "Cluster" not in data.columns:
        return

    n_clusters = df_ml["Cluster"].nunique()
    fig, axes = plt.subplots(1, n_clusters, figsize=(6 * n_clusters, 5))
    if n_clusters == 1:
        axes = [axes]

    for i in range(n_clusters):
        cluster_data = data[data["Cluster"] == i]["CWE"].value_counts().head(5)
        if not cluster_data.empty:
            cluster_data.plot(kind="barh", ax=axes[i], color=f"C{i}", edgecolor="black")
            axes[i].set_title(f"Top CWE - Cluster {i}")
            axes[i].set_xlabel("Count")

    plt.tight_layout()
    plt.savefig(config.IMAGES_DIR / "ml_cluster_cwe.png", dpi=150)
    plt.close()


# =============================================================================
# EXÉCUTION
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("ÉTAPE 6 : Machine Learning")
    print("=" * 60)

    config.IMAGES_DIR.mkdir(parents=True, exist_ok=True)

    # Charger les données
    df_ml = load_and_prepare_data()

    if len(df_ml) < 5:
        print("\n⚠️  Pas assez de données pour le ML.")
        print("   Élargissez config.YEARS et relancez `python main.py`.")
    else:
        # Modèle non supervisé
        df_ml = clustering_analysis(df_ml)

        # Modèle supervisé
        result = supervised_classification(df_ml)

        # Visualisations complémentaires
        plot_cluster_severity_distribution(df_ml)
        plot_cluster_cwe_analysis(df_ml)

        print("\n" + "=" * 60)
        print("Toutes les analyses ML et visualisations ont été générées.")
        print(f"Fichiers sauvegardés : {config.IMAGES_DIR}/ml_*.png")
        print("=" * 60)
