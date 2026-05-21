import json
import os
import sys
import threading
import requests
import sqlite3
import yaml
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


# ──────────────────────────────────────────────────────────────────────────────
#  Seuil EPSS au-delà duquel exploit_available = True même sans CISA KEV/OTX.
#  0.50 = 50 % de probabilité d'exploitation réelle selon le modèle FIRST EPSS.
# ──────────────────────────────────────────────────────────────────────────────
EPSS_EXPLOIT_THRESHOLD = 0.50


class ThreatEnricher:
    def __init__(self, config_path="config.yaml"):
        self.config       = self._load_config(config_path)
        self.nvd_api_key  = os.environ.get("NVD_API_KEY",  "")
        self.otx_api_key  = os.environ.get("OTX_API_KEY",  "")
        self._cisa_cache  = None
        self._cisa_lock   = threading.Lock()
        self.cache_path   = Path(__file__).parent / "cache.sqlite"
        self._init_db()

    # ──────────────────────────────────────────────────────────────────────────
    # Config & I/O
    # ──────────────────────────────────────────────────────────────────────────
    def _load_config(self, config_path):
        try:
            with open(config_path, encoding="utf-8") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[!] Config file {config_path} not found, using defaults")
            return {}
        except yaml.YAMLError as e:
            print(f"[!] Error parsing config: {e}")
            return {}

    def load_raw_data(self, input_path):
        try:
            with open(input_path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Input file {input_path} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] JSON parse error: {e}")
            sys.exit(1)

    # ──────────────────────────────────────────────────────────────────────────
    # SQLite cache
    # ──────────────────────────────────────────────────────────────────────────
    def _init_db(self):
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        cve_id        TEXT PRIMARY KEY,
                        enriched_data TEXT,
                        timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except sqlite3.Error as e:
            print(f"[!] DB init error: {e}")

    def _get_cached_vuln(self, cve_id):
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                row = conn.execute(
                    "SELECT enriched_data FROM cve_cache WHERE cve_id = ?",
                    (cve_id,)
                ).fetchone()
                return json.loads(row[0]) if row else None
        except Exception:
            return None

    def _save_to_cache(self, cve_id, enriched_data):
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache (cve_id, enriched_data) VALUES (?, ?)",
                    (cve_id, json.dumps(enriched_data))
                )
        except sqlite3.Error as e:
            print(f"[!] Cache write error: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Enrichissement principal
    # ──────────────────────────────────────────────────────────────────────────
    def enrich_vulnerability(self, vuln):
        cve_id = vuln.get("cve_id", "")
        cached = self._get_cached_vuln(cve_id)
        if cached:
            return cached

        enriched = vuln.copy()
        ti = {}

        # ── NVD (public, pas besoin de clé ; clé = rate limit plus élevé) ──
        ti["nvd"] = self.get_nvd_data(cve_id)

        # ── OTX (seulement si clé configurée) ──
        if self.otx_api_key:
            otx_data = self.get_otx_data(cve_id)
            ti["otx_indicators"] = otx_data
            if "error" not in otx_data and otx_data.get("pulses"):
                enriched["otx_indicators"] = [otx_data]
        else:
            ti["otx_indicators"] = {"error": "OTX_API_KEY not set – skipped"}
            print(f"[!] OTX_API_KEY manquant – OTX ignoré pour {cve_id}")

        # ── CISA KEV (pas de clé requise) ──
        cisa_data = self.get_cisa_data(cve_id)
        ti["cisa_kev"]        = cisa_data
        enriched["cisa_kev"] = cisa_data

        # ── FIX : exploit_available enrichi avec EPSS en plus de CISA+OTX ──
        epss_score = float(enriched.get("epss_score", 0.0))

        otx_has_pulses = (
            "error" not in ti.get("otx_indicators", {})
            and ti.get("otx_indicators", {}).get("indicators_count", 0) > 0
        )

        exploit_reason = []
        if cisa_data.get("known_exploited"):
            exploit_reason.append("CISA_KEV")
        if otx_has_pulses:
            exploit_reason.append("OTX_PULSES")
        if epss_score >= EPSS_EXPLOIT_THRESHOLD:
            exploit_reason.append(f"EPSS={epss_score:.4f}")

        ti["exploit_available"]        = bool(exploit_reason)
        ti["exploit_available_reason"] = ", ".join(exploit_reason) if exploit_reason else "none"

        # ── Résumé du risque ──
        ti["risk_summary"] = self._compute_risk_summary(enriched, ti)

        enriched["threat_intelligence"] = ti
        self._save_to_cache(cve_id, enriched)
        return enriched

    # ──────────────────────────────────────────────────────────────────────────
    # Calcul du niveau de risque (CRITICAL / HIGH / MEDIUM / LOW)
    # Logique : CISA KEV > EPSS élevé > CVSS seul
    # ──────────────────────────────────────────────────────────────────────────
    def _compute_risk_summary(self, enriched, ti):
        cisa_known = ti.get("cisa_kev", {}).get("known_exploited", False)
        epss       = float(enriched.get("epss_score", 0.0))
        cvss       = float(enriched.get("cvss_score", 0.0))

        if cisa_known:
            return "CRITICAL – exploité dans la nature (CISA KEV)"
        if epss >= 0.90:
            return f"CRITICAL – EPSS {epss:.0%} : exploitation très probable"
        if epss >= 0.50:
            return f"HIGH – EPSS {epss:.0%} : exploitation probable"
        if cvss >= 9.0:
            return f"HIGH – CVSS {cvss} sans exploitation connue"
        if cvss >= 7.0:
            return f"MEDIUM – CVSS {cvss}"
        return f"LOW – CVSS {cvss}"

    # ──────────────────────────────────────────────────────────────────────────
    # NVD
    # ──────────────────────────────────────────────────────────────────────────
    def get_nvd_data(self, cve_id):
        if not cve_id.startswith("CVE-"):
            return {"error": "Not a CVE identifier – NVD skipped"}
        try:
            url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
            resp    = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data  = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve     = vulns[0].get("cve", {})
                    metrics = cve.get("metrics", {})
                    # Préférer CVSSv3.1, fallback v3.0 puis v2.0
                    cvss_list = (
                        metrics.get("cvssMetricV31")
                        or metrics.get("cvssMetricV30")
                        or metrics.get("cvssMetricV2")
                        or [{}]
                    )
                    cvss_data = cvss_list[0].get("cvssData", {})
                    # Récupérer la description en anglais (en priorité)
                    descriptions = cve.get("descriptions", [])
                    desc = next(
                        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                        descriptions[0].get("value", "No description") if descriptions else "No description"
                    )
                    return {
                        "description":    desc,
                        "published_date": cve.get("published", ""),
                        "modified_date":  cve.get("lastModified", ""),
                        "cvss_score":     cvss_data.get("baseScore", 0.0),
                        "severity":       cvss_data.get("baseSeverity", "UNKNOWN"),
                        "vector_string":  cvss_data.get("vectorString", ""),
                    }
                return {"error": f"CVE not found in NVD: {cve_id}"}
            if resp.status_code == 404:
                return {"error": f"NVD 404 for {cve_id}"}
            return {"error": f"NVD HTTP {resp.status_code}"}
        except requests.Timeout:
            print(f"[!] NVD timeout pour {cve_id}")
            return {"error": "NVD request timed out"}
        except Exception as e:
            print(f"[!] NVD erreur pour {cve_id}: {e}")
            return {"error": f"NVD error: {e}"}

    # ──────────────────────────────────────────────────────────────────────────
    # OTX – endpoint corrigé (pulse search)
    # ──────────────────────────────────────────────────────────────────────────
    def get_otx_data(self, cve_id):
        """
        Endpoint correct : /api/v1/search/pulses/?q={cve_id}
        L'ancien /api/v1/indicators/vulnerability/{id} renvoie 404 sur la plupart des CVE.
        Timeout augmenté à 30 s pour les connexions lentes.
        """
        try:
            url     = f"https://otx.alienvault.com/api/v1/search/pulses/?q={cve_id}&limit=10"
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            resp    = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                data   = resp.json()
                pulses = data.get("results", [])
                return {
                    "pulses":           pulses,
                    "indicators_count": len(pulses),
                    "last_seen":        pulses[0].get("created", "") if pulses else "",
                }
            if resp.status_code == 401:
                return {"error": "OTX 401 – clé API invalide"}
            return {"error": f"OTX HTTP {resp.status_code}"}
        except requests.Timeout:
            print(f"[!] OTX timeout pour {cve_id}")
            return {"error": "OTX request timed out"}
        except Exception as e:
            print(f"[!] OTX erreur pour {cve_id}: {e}")
            return {"error": f"OTX error: {e}"}

    # ──────────────────────────────────────────────────────────────────────────
    # CISA KEV – thread-safe, téléchargement unique par run
    # ──────────────────────────────────────────────────────────────────────────
    def get_cisa_data(self, cve_id):
        if self._cisa_cache is not None:
            return self._search_cisa(cve_id)

        with self._cisa_lock:
            if self._cisa_cache is None:
                try:
                    url  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                    resp = requests.get(url, timeout=20)
                    if resp.status_code == 200:
                        self._cisa_cache = resp.json()
                        count = len(self._cisa_cache.get("vulnerabilities", []))
                        print(f"[*] CISA KEV chargé – {count} entrées")
                    else:
                        self._cisa_cache = {}
                        print(f"[!] CISA KEV HTTP {resp.status_code}")
                except Exception as e:
                    self._cisa_cache = {}
                    print(f"[!] CISA KEV erreur de téléchargement : {e}")

        return self._search_cisa(cve_id)

    def _search_cisa(self, cve_id):
        for vuln in self._cisa_cache.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return {
                    "known_exploited": True,
                    "notes":           vuln.get("notes", ""),
                    "date_added":      vuln.get("dateAdded", ""),
                    "due_date":        vuln.get("dueDate", ""),
                    "required_action": vuln.get("requiredAction", "Apply updates"),
                    "product":         vuln.get("product", ""),
                    "vendor":          vuln.get("vendorProject", ""),
                }
        return {"known_exploited": False}

    # ──────────────────────────────────────────────────────────────────────────
    # Orchestration
    # ──────────────────────────────────────────────────────────────────────────
    def process_vulnerabilities(self, raw_data):
        vulns = raw_data.get("vulnerabilities", [])
        print(f"[*] Enrichissement de {len(vulns)} vulnérabilités (5 threads)…")
        # Pré-charger CISA avant les threads pour éviter la race condition
        self.get_cisa_data("__preload__")
        with ThreadPoolExecutor(max_workers=5) as ex:
            enriched = list(ex.map(self.enrich_vulnerability, vulns))
        return enriched

    def generate_enriched_report(self, enriched_vulns, output_path):
        # ── Statistiques de synthèse ──
        kev_hits     = sum(1 for v in enriched_vulns if v.get("cisa_kev", {}).get("known_exploited"))
        exploit_hits = sum(1 for v in enriched_vulns if v.get("threat_intelligence", {}).get("exploit_available"))
        high_epss    = sum(1 for v in enriched_vulns if float(v.get("epss_score", 0)) >= EPSS_EXPLOIT_THRESHOLD)
        critical_cnt = sum(1 for v in enriched_vulns if v.get("severity") == "CRITICAL")

        report = {
            "enrichment_metadata": {
                "timestamp":             datetime.utcnow().isoformat() + "Z",
                "enricher_version":      "1.2.0",
                "total_vulnerabilities": len(enriched_vulns),
                "sources_used":          ["NVD", "OTX", "CISA KEV", "EPSS"],
                "statistics": {
                    "in_cisa_kev":          kev_hits,
                    "exploit_available":    exploit_hits,
                    "high_epss":            high_epss,
                    "critical_severity":    critical_cnt,
                    "epss_threshold_used":  EPSS_EXPLOIT_THRESHOLD,
                },
            },
            "enriched_vulnerabilities": enriched_vulns,
        }

        os.makedirs(
            os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
            exist_ok=True
        )
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[*] Rapport enrichi sauvegardé → {output_path}")
        return report

    def run(self,
            input_path="../../shared/1_raw_results.json",
            output_path="../../shared/2_enriched.json"):
        print("=" * 60)
        print("  P2 THREAT INTELLIGENCE ENRICHER  (v1.2 – fixed)")
        print("=" * 60)
        print(f"[*] NVD API key  : {'configurée' if self.nvd_api_key else 'absente (rate limit public)'}")
        print(f"[*] OTX API key  : {'configurée' if self.otx_api_key else 'ABSENTE – OTX ignoré'}")
        print(f"[*] EPSS seuil   : {EPSS_EXPLOIT_THRESHOLD} (exploit_available=True si EPSS ≥ seuil)")
        print(f"[*] Lecture      : {input_path}")

        raw_data       = self.load_raw_data(input_path)
        enriched_vulns = self.process_vulnerabilities(raw_data)
        report         = self.generate_enriched_report(enriched_vulns, output_path)

        stats = report["enrichment_metadata"]["statistics"]
        print(f"\n{'='*60}")
        print("  RÉSUMÉ D'ENRICHISSEMENT")
        print(f"{'='*60}")
        print(f"  Total enrichi          : {len(enriched_vulns)}")
        print(f"  Dans CISA KEV          : {stats['in_cisa_kev']}")
        print(f"  exploit_available=True : {stats['exploit_available']}")
        print(f"    dont CISA KEV        : {stats['in_cisa_kev']}")
        print(f"    dont EPSS ≥ {EPSS_EXPLOIT_THRESHOLD}    : {stats['high_epss']}")
        print(f"  Sévérité CRITICAL      : {stats['critical_severity']}")
        print(f"  Sortie                 : {output_path}")
        print(f"{'='*60}\n")
        return report


def main():
    enricher = ThreatEnricher()
    return enricher.run()


if __name__ == "__main__":
    main()
