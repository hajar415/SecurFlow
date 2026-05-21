#!/usr/bin/env python3
"""
P2 Threat Intelligence Enricher  (FIXED)
Part of the CTI Pipeline Project

Bugs fixed vs original:
  1. NVD and OTX were gated behind `if self.nvd_api_key` / `if self.otx_api_key`,
     so they were NEVER called when the env-vars were absent.  NVD's public API
     works without a key (rate-limited); OTX still needs a key but the guard is
     now more informative instead of silently skipping.
  2. CISA KEV cache was initialised in __init__ but re-read on every thread because
     5 concurrent threads all saw `_cisa_cache is None` at the same moment.
     Fixed with a threading.Lock so the JSON is fetched exactly once.
  3. OTX endpoint was wrong for CVE lookups (/indicators/vulnerability/{id} returns
     404 for most IDs).  Correct endpoint is the pulse search API.
"""

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


class ThreatEnricher:
    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)
        self.nvd_api_key  = os.environ.get("NVD_API_KEY",  "")
        self.otx_api_key  = os.environ.get("OTX_API_KEY",  "")
        # CISA does not require a key
        self._cisa_cache  = None          # None = not loaded yet
        self._cisa_lock   = threading.Lock()   # FIX 2: single-load guarantee
        self.cache_path   = Path(__file__).parent / "cache.sqlite"
        self._init_db()

    # ------------------------------------------------------------------
    # Config & I/O
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # SQLite cache
    # ------------------------------------------------------------------
    def _init_db(self):
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        cve_id TEXT PRIMARY KEY,
                        enriched_data TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except sqlite3.Error as e:
            print(f"[!] DB init error: {e}")

    def _get_cached_vuln(self, cve_id):
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                row = conn.execute(
                    "SELECT enriched_data FROM cve_cache WHERE cve_id = ?", (cve_id,)
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

    # ------------------------------------------------------------------
    # Main enrichment
    # ------------------------------------------------------------------
    def enrich_vulnerability(self, vuln):
        cve_id = vuln.get("cve_id", "")
        cached = self._get_cached_vuln(cve_id)
        if cached:
            return cached

        enriched = vuln.copy()
        ti = {}

        # FIX 1a: Always try NVD (public rate-limited API works without a key).
        # If a key is present we pass it as a header for higher rate limits.
        ti["nvd"] = self.get_nvd_data(cve_id)

        # FIX 1b: Always try OTX if a key is configured; otherwise log clearly.
        if self.otx_api_key:
            otx_data = self.get_otx_data(cve_id)
            ti["otx_indicators"] = otx_data
            if "error" not in otx_data and otx_data.get("pulses"):
                enriched["otx_indicators"] = [otx_data]
        else:
            ti["otx_indicators"] = {"error": "OTX_API_KEY not set – skipped"}
            print(f"[!] OTX_API_KEY missing – skipping OTX for {cve_id}")

        # CISA KEV (no key needed) – FIX 2 ensures thread-safe single load
        cisa_data = self.get_cisa_data(cve_id)
        ti["cisa_kev"]        = cisa_data
        enriched["cisa_kev"] = cisa_data

        # exploit_available logic
        otx_has_pulses = (
            "error" not in ti.get("otx_indicators", {})
            and ti.get("otx_indicators", {}).get("indicators_count", 0) > 0
        )
        ti["exploit_available"] = bool(cisa_data.get("known_exploited") or otx_has_pulses)

        enriched["threat_intelligence"] = ti
        self._save_to_cache(cve_id, enriched)
        return enriched

    # ------------------------------------------------------------------
    # NVD
    # ------------------------------------------------------------------
    def get_nvd_data(self, cve_id):
        # Skip GHSA IDs – NVD only knows CVE-* identifiers
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
                    cve    = vulns[0].get("cve", {})
                    metrics = cve.get("metrics", {})
                    # Prefer CVSSv3.1, fall back to v3.0
                    cvss_list = (
                        metrics.get("cvssMetricV31")
                        or metrics.get("cvssMetricV30")
                        or [{}]
                    )
                    cvss_data = cvss_list[0].get("cvssData", {})
                    return {
                        "description":   cve.get("descriptions", [{}])[0].get("value", "No description"),
                        "published_date": cve.get("published", ""),
                        "modified_date":  cve.get("lastModified", ""),
                        "cvss_score":     cvss_data.get("baseScore", 0.0),
                        "severity":       cvss_data.get("baseSeverity", "UNKNOWN"),
                    }
                return {"error": f"CVE not found in NVD: {cve_id}"}
            if resp.status_code == 404:
                return {"error": f"NVD 404 for {cve_id}"}
            return {"error": f"NVD HTTP {resp.status_code}"}
        except requests.Timeout:
            print(f"[!] NVD timeout for {cve_id}")
            return {"error": "NVD request timed out"}
        except Exception as e:
            print(f"[!] NVD error for {cve_id}: {e}")
            return {"error": f"NVD error: {e}"}

    # ------------------------------------------------------------------
    # OTX  (FIX 3: corrected endpoint)
    # ------------------------------------------------------------------
    def get_otx_data(self, cve_id):
        """
        Correct OTX endpoint for CVE pulse search.
        The old URL  /api/v1/indicators/vulnerability/{id}  returns 404 for most IDs.
        Use the pulse search API instead: /api/v1/search/pulses/?q={cve_id}
        """
        try:
            url     = f"https://otx.alienvault.com/api/v1/search/pulses/?q={cve_id}&limit=10"
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            resp    = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data   = resp.json()
                pulses = data.get("results", [])
                return {
                    "pulses":            pulses,
                    "indicators_count":  len(pulses),
                    "last_seen":         pulses[0].get("created", "") if pulses else "",
                }
            if resp.status_code == 401:
                return {"error": "OTX 401 – invalid API key"}
            return {"error": f"OTX HTTP {resp.status_code}"}
        except requests.Timeout:
            print(f"[!] OTX timeout for {cve_id}")
            return {"error": "OTX request timed out"}
        except Exception as e:
            print(f"[!] OTX error for {cve_id}: {e}")
            return {"error": f"OTX error: {e}"}

    # ------------------------------------------------------------------
    # CISA KEV  (FIX 2: thread-safe single download)
    # ------------------------------------------------------------------
    def get_cisa_data(self, cve_id):
        """
        Downloads the CISA KEV JSON exactly once per process run, protected
        by a threading.Lock so that multiple threads don't all see
        `_cisa_cache is None` at startup and fire 5 concurrent downloads.
        """
        # Fast path: already loaded
        if self._cisa_cache is not None:
            return self._search_cisa(cve_id)

        with self._cisa_lock:
            # Another thread may have loaded it while we waited for the lock
            if self._cisa_cache is None:
                try:
                    url  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                    resp = requests.get(url, timeout=20)
                    if resp.status_code == 200:
                        self._cisa_cache = resp.json()
                        print(f"[*] CISA KEV loaded – "
                              f"{len(self._cisa_cache.get('vulnerabilities', []))} entries")
                    else:
                        self._cisa_cache = {}   # Mark as "tried and failed"
                        print(f"[!] CISA KEV HTTP {resp.status_code}")
                except Exception as e:
                    self._cisa_cache = {}
                    print(f"[!] CISA KEV download error: {e}")

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
                }
        return {"error": "Not in CISA KEV catalog"}

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def process_vulnerabilities(self, raw_data):
        vulns = raw_data.get("vulnerabilities", [])
        print(f"[*] Enriching {len(vulns)} vulnerabilities (5 threads)…")
        # Pre-load CISA before spawning threads to avoid the race condition
        # even on the very first call.
        self.get_cisa_data("__preload__")
        with ThreadPoolExecutor(max_workers=5) as ex:
            enriched = list(ex.map(self.enrich_vulnerability, vulns))
        return enriched

    def generate_enriched_report(self, enriched_vulns, output_path):
        report = {
            "enrichment_metadata": {
                "timestamp":             datetime.utcnow().isoformat() + "Z",
                "enricher_version":      "1.1.0",
                "total_vulnerabilities": len(enriched_vulns),
                "sources_used":          ["NVD", "OTX", "CISA KEV"],
            },
            "enriched_vulnerabilities": enriched_vulns,
        }
        os.makedirs(
            os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
            exist_ok=True
        )
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[*] Enriched report saved → {output_path}")
        return report

    def run(self,
            input_path="../../shared/1_raw_results.json",
            output_path="../../shared/2_enriched.json"):
        print("=" * 60)
        print("  P2 THREAT INTELLIGENCE ENRICHER  (v1.1 – fixed)")
        print("=" * 60)
        print(f"[*] NVD API key : {'set' if self.nvd_api_key else 'not set (public rate limit)'}")
        print(f"[*] OTX API key : {'set' if self.otx_api_key else 'NOT SET – OTX will be skipped'}")
        print(f"[*] Loading raw data from: {input_path}")

        raw_data      = self.load_raw_data(input_path)
        enriched_vulns = self.process_vulnerabilities(raw_data)
        report        = self.generate_enriched_report(enriched_vulns, output_path)

        kev_hits = sum(
            1 for v in enriched_vulns
            if v.get("cisa_kev", {}).get("known_exploited")
        )
        exploit_hits = sum(
            1 for v in enriched_vulns
            if v.get("threat_intelligence", {}).get("exploit_available")
        )
        print(f"\n{'='*60}")
        print("  ENRICHMENT SUMMARY")
        print(f"{'='*60}")
        print(f"  Total enriched        : {len(enriched_vulns)}")
        print(f"  In CISA KEV           : {kev_hits}")
        print(f"  exploit_available=True: {exploit_hits}")
        print(f"  Output                : {output_path}")
        print(f"{'='*60}\n")
        return report


def main():
    enricher = ThreatEnricher()
    return enricher.run()


if __name__ == "__main__":
    main()
