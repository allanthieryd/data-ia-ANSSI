import feedparser
import requests
import re
import pandas as pd

# --- Fonctions utilitaires ---

def get_bulletins_anssi(limit=None):
    """Récupère les bulletins ANSSI (avis + alertes) depuis les flux RSS.
    
    Args:
        limit: Nombre max de bulletins à récupérer (None = tous)
    """
    bulletins = []
    feeds = [
        ("https://www.cert.ssi.gouv.fr/avis/feed/", "Avis"),
        ("https://www.cert.ssi.gouv.fr/alerte/feed/", "Alerte"),
    ]
    for feed_url, type_bulletin in feeds:
        rss_feed = feedparser.parse(feed_url)
        for entry in rss_feed.entries:
            if limit and len(bulletins) >= limit:
                break
            id_match = re.search(r"(CERTFR-\d{4}-[A-Z]+-\d+)", entry.link)
            id_anssi = id_match.group(1) if id_match else "Inconnu"
            bulletins.append({
                "id_anssi": id_anssi,
                "titre": entry.title,
                "type": type_bulletin,
                "date": entry.published,
                "lien": entry.link,
            })
        if limit and len(bulletins) >= limit:
            break
    return bulletins


def get_cves_from_bulletin(bulletin_url):
    """Extrait les CVE depuis le JSON d'un bulletin ANSSI."""
    json_url = bulletin_url.rstrip("/") + "/json/"
    try:
        response = requests.get(json_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        # Méthode 1 : clé "cves"
        cve_ids = [cve["name"] for cve in data.get("cves", [])]
        # Méthode 2 : regex en complément
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_ids_regex = re.findall(cve_pattern, str(data))
        return list(set(cve_ids + cve_ids_regex))
    except Exception:
        return []


def get_cve_details(cve_id):
    """Récupère les détails d'un CVE via l'API MITRE."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        cna = data.get("containers", {}).get("cna", {})

        # Description
        descriptions = cna.get("descriptions", [])
        description = descriptions[0].get("value", "") if descriptions else ""

        # CVSS
        cvss_score = None
        base_severity = ""
        metrics = cna.get("metrics", [])
        for metric in metrics:
            for key in ["cvssV3_1", "cvssV3_0", "cvssV4_0"]:
                if key in metric:
                    cvss_score = metric[key].get("baseScore")
                    base_severity = metric[key].get("baseSeverity", "")
                    break
            if cvss_score:
                break

        # CWE
        cwe = "Non disponible"
        problemtypes = cna.get("problemTypes", [])
        if problemtypes and "descriptions" in problemtypes[0]:
            cwe = problemtypes[0]["descriptions"][0].get("cweId", "Non disponible")

        # Produits affectés
        affected = cna.get("affected", [])
        products = []
        for product in affected:
            vendor = product.get("vendor", "Inconnu")
            product_name = product.get("product", "Inconnu")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            products.append({
                "vendor": vendor,
                "product": product_name,
                "versions": ", ".join(versions) if versions else "Non spécifié",
            })

        return {
            "description": description,
            "cvss_score": cvss_score,
            "base_severity": base_severity,
            "cwe": cwe,
            "products": products,
        }
    except Exception:
        return {
            "description": "",
            "cvss_score": None,
            "base_severity": "",
            "cwe": "Non disponible",
            "products": [],
        }


def get_epss_score(cve_id):
    """Récupère le score EPSS d'un CVE."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        epss_data = data.get("data", [])
        if epss_data:
            return epss_data[0].get("epss")
    except Exception:
        pass
    return None


# --- Étape 4 : Consolidation ---

def build_dataframe(limit=10):
    """Construit le DataFrame consolidé.
    
    Args:
        limit: Nombre max de bulletins à traiter (défaut: 10)
    """
    rows = []
    bulletins = get_bulletins_anssi(limit=limit)

    for bulletin in bulletins:
        cve_ids = get_cves_from_bulletin(bulletin["lien"])

        if not cve_ids:
            # Garder le bulletin même sans CVE
            rows.append({
                "ID ANSSI": bulletin["id_anssi"],
                "Titre ANSSI": bulletin["titre"],
                "Type": bulletin["type"],
                "Date": bulletin["date"],
                "CVE": "",
                "CVSS": None,
                "Base Severity": "",
                "CWE": "",
                "EPSS": None,
                "Lien": bulletin["lien"],
                "Description": "",
                "Éditeur": "",
                "Produit": "",
                "Versions affectées": "",
            })
            continue

        for cve_id in cve_ids:
            details = get_cve_details(cve_id)
            epss = get_epss_score(cve_id)

            products = details["products"] if details["products"] else [{"vendor": "", "product": "", "versions": ""}]

            for prod in products:
                rows.append({
                    "ID ANSSI": bulletin["id_anssi"],
                    "Titre ANSSI": bulletin["titre"],
                    "Type": bulletin["type"],
                    "Date": bulletin["date"],
                    "CVE": cve_id,
                    "CVSS": details["cvss_score"],
                    "Base Severity": details["base_severity"],
                    "CWE": details["cwe"],
                    "EPSS": epss,
                    "Lien": bulletin["lien"],
                    "Description": details["description"],
                    "Éditeur": prod["vendor"],
                    "Produit": prod["product"],
                    "Versions affectées": prod["versions"],
                })

    df = pd.DataFrame(rows)
    return df


# --- Exécution ---
if __name__ == "__main__":
    MAX_BULLETINS = 2 
    print(f"Récupération et consolidation des {MAX_BULLETINS} premiers bulletins ANSSI...")
    df = build_dataframe(limit=MAX_BULLETINS)
    print(f"\n{len(df)} lignes récupérées.")
    print(df.head(10).to_string())
    # Export CSV
    df.to_csv("data_anssi_consolidated.csv", index=False, encoding="utf-8")
    print("\nDonnées exportées dans data_anssi_consolidated.csv")
