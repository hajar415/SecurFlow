#!/usr/bin/env python3
"""
P2 Threat Intelligence Enricher
Part of the CTI Pipeline Project

This module processes raw vulnerability data from P1 and enriches it with
threat intelligence from multiple sources (NVD, OTX, CISA KEV).
"""

import json
import os
import sys
import requests
import sqlite3
import time
import yaml
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

class ThreatEnricher:
    def __init__(self, config_path="config.yaml"):
        """Initialize the threat enricher with configuration."""
        self.config = self.load_config(config_path)
        self.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        self.otx_api_key = os.environ.get("OTX_API_KEY", "")
        self.cisa_api_key = os.environ.get("CISA_API_KEY", "")
        self._cisa_cache = None  # Session cache to avoid redundant downloads
        self.cache_path = Path(__file__).parent / "cache.sqlite"
        self._init_db()
        
    def load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[!] Config file {config_path} not found, using defaults")
            return {}
        except yaml.YAMLError as e:
            print(f"[!] Error parsing config file: {e}")
            return {}
    
    def load_raw_data(self, input_path):
        """Load raw vulnerability data from P1."""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Input file {input_path} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing JSON file: {e}")
            sys.exit(1)
    
    def _init_db(self):
        """Initialize the SQLite cache database."""
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
            print(f"[!] Database initialization error: {e}")

    def _get_cached_vuln(self, cve_id):
        """Retrieve enriched data from cache if it exists."""
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                cursor = conn.execute("SELECT enriched_data FROM cve_cache WHERE cve_id = ?", (cve_id,))
                row = cursor.fetchone()
                return json.loads(row[0]) if row else None
        except Exception:
            return None

    def _save_to_cache(self, cve_id, enriched_data):
        """Save enriched data to the SQLite cache."""
        try:
            with sqlite3.connect(self.cache_path, timeout=20) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache (cve_id, enriched_data) VALUES (?, ?)",
                    (cve_id, json.dumps(enriched_data))
                )
        except sqlite3.Error as e:
            print(f"[!] Error saving to cache: {e}")

    def enrich_vulnerability(self, vuln):
        """Enrich a single vulnerability with threat intelligence."""
        cve_id = vuln.get("cve_id", "")
        cached_data = self._get_cached_vuln(cve_id)
        if cached_data:
            return cached_data

        enriched = vuln.copy()
        enriched["threat_intelligence"] = {}
        
        # NVD enrichment
        if self.nvd_api_key:
            enriched["threat_intelligence"]["nvd"] = self.get_nvd_data(cve_id)
        
        # OTX enrichment
        if self.otx_api_key:
            otx_data = self.get_otx_data(cve_id)
            enriched["threat_intelligence"]["otx_indicators"] = otx_data
            # Only expose at root if actual threat pulses were found
            if "error" not in otx_data and otx_data.get("pulses"):
                enriched["otx_indicators"] = [otx_data]
        
        # CISA KEV enrichment
        cisa_data = self.get_cisa_data(cve_id)
        enriched["threat_intelligence"]["cisa_kev"] = cisa_data
        enriched["cisa_kev"] = cisa_data

        # exploit_available = True si CISA KEV OU OTX a des pulses
        otx_has_pulses = (
            "error" not in enriched["threat_intelligence"].get("otx_indicators", {})
            and enriched["threat_intelligence"].get("otx_indicators", {}).get("indicators_count", 0) > 0
        )

        if cisa_data.get("known_exploited") or otx_has_pulses:
            enriched["threat_intelligence"]["exploit_available"] = True
        else:
            enriched["threat_intelligence"]["exploit_available"] = False

        self._save_to_cache(cve_id, enriched)
        return enriched
    
    def get_nvd_data(self, cve_id):
        """Get vulnerability data from NVD."""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("vulnerabilities"):
                    vuln_data = data["vulnerabilities"][0]
                    return {
                        "description": vuln_data.get("cve", {}).get("description", "No description"),
                        "published_date": vuln_data.get("cve", {}).get("published", ""),
                        "modified_date": vuln_data.get("cve", {}).get("lastModified", ""),
                        "cvss_score": vuln_data.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0.0),
                        "severity": vuln_data.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    }
            return {"error": "NVD data not available"}
        except Exception as e:
            print(f"[!] NVD API error for {cve_id}: {e}")
            return {"error": f"NVD API error: {str(e)}"}
    
    def get_otx_data(self, cve_id):
        """Get threat indicators from OTX."""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/vulnerability/{cve_id}"
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "pulses": data.get("pulses", []),
                    "indicators_count": len(data.get("pulses", [])),
                    "last_seen": data.get("pulses", [{}])[0].get("created", "") if data.get("pulses") else ""
                }
            return {"error": "OTX data not available"}
        except Exception as e:
            print(f"[!] OTX API error for {cve_id}: {e}")
            return {"error": f"OTX API error: {str(e)}"}
    
    def get_cisa_data(self, cve_id):
        """Get vulnerability data from CISA KEV catalog."""
        try:
            if self._cisa_cache is None:
                url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    self._cisa_cache = response.json()

            if self._cisa_cache:
                for vuln in self._cisa_cache.get("vulnerabilities", []):
                    if vuln.get("cveID") == cve_id:
                        return {
                            "known_exploited": True,
                            "notes": vuln.get("notes", "Known to be exploited"),
                            "date_added": vuln.get("dateAdded", ""),
                            "due_date": vuln.get("dueDate", ""),
                            "required_action": vuln.get("requiredAction", "Apply updates")
                        }
            return {"error": "Not in CISA KEV catalog"}
        except Exception as e:
            print(f"[!] CISA API error for {cve_id}: {e}")
            return {"error": f"CISA API error: {str(e)}"}
    
    def process_vulnerabilities(self, raw_data):
        """Process all vulnerabilities with enrichment."""
        vulnerabilities = raw_data.get("vulnerabilities", [])
        
        print(f"[*] Enriching {len(vulnerabilities)} vulnerabilities using 5 parallel threads...")

        with ThreadPoolExecutor(max_workers=5) as executor:
            # Correctly map the class method and use the local list variable
            enriched_vulns = list(executor.map(self.enrich_vulnerability, vulnerabilities))

        return enriched_vulns
    
    def generate_enriched_report(self, enriched_vulns, output_path):
        """Generate and save the enriched vulnerability report."""
        report_data = {
            "enrichment_metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "enricher_version": "1.0.0",
                "total_vulnerabilities": len(enriched_vulns),
                "sources_used": ["NVD", "OTX", "CISA KEV"]
            },
            "enriched_vulnerabilities": enriched_vulns
        }
        
        # Save to file
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[*] Enriched report saved to: {output_path}")
        return report_data
    
    def run(self, input_path="../../shared/1_raw_results.json", output_path="../../shared/2_enriched.json"):
        """Run the complete enrichment process."""
        print("=" * 60)
        print("  P2 THREAT INTELLIGENCE ENRICHER")
        print("=" * 60)
        
        # Load raw data
        print(f"[*] Loading raw data from: {input_path}")
        raw_data = self.load_raw_data(input_path)
        
        # Process vulnerabilities
        enriched_vulns = self.process_vulnerabilities(raw_data)
        
        # Generate report
        report_data = self.generate_enriched_report(enriched_vulns, output_path)
        
        # Print summary
        print(f"\n{'='*60}")
        print("  ENRICHMENT SUMMARY")
        print(f"{'='*60}")
        print(f"  Total vulnerabilities enriched: {len(enriched_vulns)}")
        print(f"  Enrichment report: {output_path}")
        print(f"{'='*60}\n")
        
        return report_data


def main():
    """Main entry point for the threat enricher."""
    # Initialize and run enricher
    enricher = ThreatEnricher()
    return enricher.run()


if __name__ == "__main__":
    main()