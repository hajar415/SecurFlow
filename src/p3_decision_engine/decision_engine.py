#!/usr/bin/env python3
"""
P3 Decision Engine - AI-Powered Security Decision Making
Part of the CTI Pipeline Project

This module processes enriched vulnerability data from P2 and applies
mathematical risk scoring with AI-powered decision making.
"""

import json
import yaml
import os
import time
import sys
import re
from datetime import datetime
from pathlib import Path
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor


class DecisionEngine:
    def __init__(self, config_path=None):
        """Initialize the decision engine with configuration."""
        self.base_dir = Path(__file__).parent
        effective_config = config_path if config_path else self.base_dir / "config.yaml"
        self.config = self.load_config(effective_config)
        self.high_context_components = set(self.config.get("high_context_components", []))

        # AI Configuration from config file
        ai_config = self.config.get("ai_config", {})
        featherless_api_key = os.environ.get("FEATHERLESS_API_KEY", "")
        self.ai_client = OpenAI(
            base_url=ai_config.get("base_url", "https://api.featherless.ai/v1"),
            api_key=featherless_api_key
        ) if featherless_api_key else None

        self.model_name     = ai_config.get("model_name")
        if not self.model_name:
            print("[!] ERREUR : 'model_name' manquant dans ai_config du config.yaml")
            sys.exit(1)
        self.temperature    = ai_config.get("temperature",      0.1)
        self.max_tokens     = ai_config.get("max_tokens",       1000)
        self.timeout_seconds= ai_config.get("timeout_seconds",  30)
        self.retry_attempts = ai_config.get("retry_attempts",   3)

        # Pré-chargement des prompts
        self.system_prompt = self._load_prompt_file("prompts/system_prompt.txt")
        self.user_template = self._load_prompt_file("prompts/user_prompt_template.txt")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_prompt_file(self, relative_path):
        """Charge un fichier de prompt de manière sécurisée."""
        path = self.base_dir / relative_path
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"[!] Impossible de charger le prompt {path}: {e}")
            return ""

    def load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[!] Config file {config_path} not found, using defaults")
            return {"high_context_components": []}
        except yaml.YAMLError as e:
            print(f"[!] Error parsing config file: {e}")
            return {"high_context_components": []}

    def load_enriched_data(self, input_path):
        """Load enriched vulnerability data from P2."""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Input file {input_path} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing JSON file: {e}")
            sys.exit(1)

    # ------------------------------------------------------------------
    # SRP Scoring
    # ------------------------------------------------------------------

    def calculate_srp(self, vulnerability):
        """
        Calculate SRP (Score de Risque Pipeline) for a vulnerability.

        FORMULE DU SRP:
        SRP = [(CVSS × 0.4) + (EPSS × 10 × 0.3) + (Exploit_Public × 0.2) + (Threat_Actor × 0.1)]
              × Modificateur_Contexte
        """
        cvss = float(vulnerability.get("cvss_score", 0.0))
        epss = float(vulnerability.get("epss_score", 0.0))

        threat_intel   = vulnerability.get("threat_intelligence", {})
        exploit_public = 10 if threat_intel.get("exploit_available", False) else 0

        otx_indicators = vulnerability.get("otx_indicators", [])
        threat_actor   = 10 if len(otx_indicators) > 0 else 0

        package_name      = vulnerability.get("package", "")
        context_modifier  = 1.5 if package_name in self.high_context_components else 1.0

        srp_base  = (cvss * 0.4) + (epss * 10 * 0.3) + (exploit_public * 0.2) + (threat_actor * 0.1)
        srp_score = srp_base * context_modifier

        return min(srp_score, 10.0)

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------

    def make_decision(self, srp_score):
        """
        Make decision based on SRP score.

        RÈGLES DE DÉCISION:
        - SRP > 7.0  -> "BLOQUER"
        - SRP >= 4.0 -> "ALERTER"
        - SRP < 4.0  -> "PASSER"
        """
        decision_config  = self.config.get("decision_thresholds", {})
        block_threshold  = decision_config.get("block_threshold", 7.0)
        alert_threshold  = decision_config.get("alert_threshold", 4.0)

        if srp_score > block_threshold:
            return "BLOQUER"
        elif srp_score >= alert_threshold:
            return "ALERTER"
        else:
            return "PASSER"

    # ------------------------------------------------------------------
    # AI Analysis
    # ------------------------------------------------------------------

    def _extract_description(self, vulnerability):
        """
        Cherche la description dans plusieurs emplacements possibles du JSON enrichi.
        Retourne un fallback unique (basé sur CVE + package + version) si rien n'est trouvé,
        ce qui garantit que deux CVEs similaires ne reçoivent jamais le même prompt.
        """
        desc = (
            vulnerability.get("description")
            or vulnerability.get("threat_intelligence", {}).get("nvd", {}).get("description")
            or vulnerability.get("threat_intelligence", {}).get("description")
        )
        if not desc:
            cve_id  = vulnerability.get("cve_id",  "CVE-INCONNU")
            package = vulnerability.get("package", "package-inconnu")
            version = vulnerability.get("version", "version-inconnue")
            desc = (
                f"Vulnérabilité {cve_id} affectant {package} version {version}. "
                "Aucune description NVD disponible."
            )
        return desc

    def get_ai_analysis(self, vulnerability, srp_score, decision):
        """Appelle Featherless AI pour générer une explication DevSecOps."""
        # Capture locale immédiate — immunisé contre le changement entre threads
        local_cve_id = str(vulnerability.get("cve_id",  "Unknown"))
        local_package= str(vulnerability.get("package", "Unknown"))
        local_version= str(vulnerability.get("version", "inconnue"))
        local_cvss   = vulnerability.get("cvss_score", "N/A")
        local_epss   = vulnerability.get("epss_score", "N/A")

        # Fallback sans client AI
        if not self.ai_client:
            return {
                "ai_explanation": (
                    f"Vulnérabilité {local_cve_id} dans {local_package} v{local_version} "
                    f"avec un SRP de {srp_score:.1f}/10. Risque {decision}."
                ),
                "ai_fix": f"Planifier la mise à jour de {local_package} lors d'un prochain sprint."
            }

        # --- Extraction des données CTI ---
        description  = self._extract_description(vulnerability)

        cisa_data    = vulnerability.get("cisa_kev", {})
        cisa_notes   = (
            cisa_data.get("notes", "Non listé dans le KEV")
            if isinstance(cisa_data, dict)
            else "Non listé"
        )

        otx_data      = vulnerability.get("otx_indicators", [])
        threat_actors = [
            pulse.get("name")
            for indicator in otx_data
            for pulse in indicator.get("pulses", [])
        ]
        actors_str    = ", ".join(threat_actors) if threat_actors else "Aucun acteur spécifique identifié"

        # --- Construction du prompt ---
        user_prompt = self.user_template.format(
            decision   = decision,
            srp_score  = srp_score,
            cve_id     = local_cve_id,
            package    = local_package,
            version    = local_version,
            cvss       = local_cvss,
            epss       = local_epss,
            desc       = description,
            cisa_notes = cisa_notes,
            actors_str = actors_str,
        )

        # --- Boucle de retry ---
        for attempt in range(self.retry_attempts):
            try:
                print(f"    [IA] Début de l'analyse pour {local_cve_id} (Tentative {attempt + 1})...")

                response = self.ai_client.chat.completions.create(
                    model           = self.model_name,
                    messages        = [
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                    response_format = {"type": "json_object"},
                    max_tokens      = self.max_tokens,
                    timeout         = self.timeout_seconds,
                    temperature     = self.temperature,
                )

                raw_content = response.choices[0].message.content.strip()
                print(f"    [RAW] {repr(raw_content[:120])}...")

                # --- Extraction JSON robuste ---
                result = None
                try:
                    start = raw_content.find('{')
                    end   = raw_content.rfind('}')
                    if start != -1 and end != -1:
                        result = json.loads(raw_content[start:end + 1])
                except Exception:
                    pass

                # Fallback regex si le JSON est encore cassé
                if not result:
                    exp_match = re.search(r'"ai_explanation"\s*:\s*"(.*?)"', raw_content, re.DOTALL)
                    fix_match = re.search(r'"ai_fix"\s*:\s*"(.*?)"',         raw_content, re.DOTALL)
                    if exp_match:
                        result = {
                            "ai_explanation": exp_match.group(1).strip(),
                            "ai_fix": fix_match.group(1).strip() if fix_match else "Mise à jour recommandée.",
                        }
                    else:
                        print(f"    [!] JSON non parseable pour {local_cve_id}, retry...")
                        continue

                preview = result.get("ai_explanation", "")[:75]
                print(f"    [IA] Analyse terminée pour {local_cve_id}. Réponse: {preview}...")

                # Délai pour éviter les 429 sur Featherless
                time.sleep(0.5)

                return {
                    "ai_explanation": result.get("ai_explanation", "Alerte CTI critique."),
                    "ai_fix":         result.get("ai_fix",         "Mettre à jour le package immédiatement."),
                }

            except Exception as e:
                err_str = str(e).lower()
                is_rate_limit = "429" in err_str or "concurrency_limit_exceeded" in err_str

                if is_rate_limit and attempt < self.retry_attempts - 1:
                    wait_time = (attempt + 1) * 2
                    print(f"    [!] Limite de confluence atteinte (429). Pause de {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"    [!] Erreur IA critique pour {local_cve_id}: {e}")
                    return {
                        "ai_explanation": f"Alerte CTI de niveau {decision} pour {local_cve_id}. (Erreur API IA).",
                        "ai_fix":         f"Vérifiez les correctifs de sécurité pour {local_package} v{local_version}.",
                    }

        return {
            "ai_explanation": f"Analyse IA échouée après {self.retry_attempts} tentatives pour {local_cve_id}.",
            "ai_fix":         "Vérification manuelle requise.",
        }
    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def _process_single_vuln(self, vuln):
        """Process a single vulnerability with SRP calculation and AI analysis."""
        cve_id = vuln.get("cve_id", "Inconnu")
        print(f"[*] Processing vulnerability: {cve_id}")

        srp_score = round(self.calculate_srp(vuln), 1)
        decision  = self.make_decision(srp_score)
        ai_analysis = self.get_ai_analysis(vuln, srp_score, decision)

        report_entry = {
            "cve_id":          vuln.get("cve_id", ""),
            "package":         vuln.get("package", ""),
            "version":         vuln.get("version", "inconnue"),
            "srp_score":       srp_score,
            "decision":        decision,
            "ai_explanation":  ai_analysis["ai_explanation"],
            "ai_fix":          ai_analysis["ai_fix"],
            "timestamp":       datetime.utcnow().isoformat() + "Z",
        }

        print(f"    SRP: {srp_score:.1f} -> {decision}")
        return report_entry

    def process_vulnerabilities(self, enriched_data):
        """Process all vulnerabilities and generate final report."""
        enriched_vulns = enriched_data.get("enriched_vulnerabilities", [])

        perf_config = self.config.get("performance", {})
        max_workers = perf_config.get("max_workers", 1)

        print(f"[*] Processing {len(enriched_vulns)} vulnerabilities with {max_workers} parallel thread(s)...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            final_report = list(executor.map(self._process_single_vuln, enriched_vulns))
        final_report.sort(key=lambda x: x["srp_score"], reverse=True)
        return final_report

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def generate_final_report(self, final_report, output_path):
        """Generate and save the final report."""
        reporting = self.config.get("reporting", {})
        include_ai          = reporting.get("include_ai_explanations",    True)
        include_fix         = reporting.get("include_fix_recommendations", True)
        sort_desc           = reporting.get("sort_by_srp_desc",           True)
        generate_summary    = reporting.get("generate_summary",           True)

        # Apply reporting flags — strip fields if disabled
        processed = []
        for r in final_report:
            entry = dict(r)
            if not include_ai:
                entry.pop("ai_explanation", None)
            if not include_fix:
                entry.pop("ai_fix", None)
            processed.append(entry)

        if sort_desc:
            processed.sort(key=lambda x: x["srp_score"], reverse=True)

        decisions_count = {
            "BLOQUER": sum(1 for r in processed if r["decision"] == "BLOQUER"),
            "ALERTER": sum(1 for r in processed if r["decision"] == "ALERTER"),
            "PASSER":  sum(1 for r in processed if r["decision"] == "PASSER"),
        }
        avg_srp = (
            round(sum(r["srp_score"] for r in processed) / len(processed), 1)
            if processed else 0.0
        )

        report_data = {
            "decision_metadata": {
                "timestamp":      datetime.utcnow().isoformat() + "Z",
                "engine_version": "1.0.0",
                "config_used": {
                    "high_context_components": list(self.high_context_components),
                    "block_threshold": self.config.get("decision_thresholds", {}).get("block_threshold", 7.0),
                    "alert_threshold": self.config.get("decision_thresholds", {}).get("alert_threshold", 4.0),
                    "model":           self.model_name,
                },
                "total_processed": len(processed),
                "decisions":       decisions_count,
                "average_srp":     avg_srp,
            },
            "vulnerability_decisions": processed,
        }

        # Log si database.enabled (placeholder pour future intégration)
        db_config = self.config.get("database", {})
        if db_config.get("enabled", False):
            print("[DB] Database export enabled — not yet implemented, skipping.")

        os.makedirs(
            os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
            exist_ok=True
        )
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        print(f"[*] Final report saved to: {output_path}")

        if generate_summary:
            meta = report_data["decision_metadata"]
            print(f"\n{'='*60}")
            print("  DECISION ENGINE SUMMARY")
            print(f"{'='*60}")
            print(f"  Total vulnerabilities processed : {meta['total_processed']}")
            print(f"  BLOQUER (critical)              : {meta['decisions']['BLOQUER']}")
            print(f"  ALERTER (moderate)              : {meta['decisions']['ALERTER']}")
            print(f"  PASSER  (low)                   : {meta['decisions']['PASSER']}")
            print(f"  Average SRP score               : {meta['average_srp']}")
            print(f"  Model used                      : {meta['config_used']['model']}")
            print(f"  Final report                    : {output_path}")
            print(f"{'='*60}\n")

        return report_data

    # ------------------------------------------------------------------
    # Entrypoint
    # ------------------------------------------------------------------

    def run(self, input_path=None, output_path=None):
        """Run the complete decision engine process."""
        config_paths = self.config.get("paths", {})
        input_path  = input_path  or config_paths.get("input_file",  "../../shared/2_enriched.json")
        output_path = output_path or config_paths.get("output_file", "../../shared/3_final_report.json")

        print("=" * 60)
        print("  P3 DECISION ENGINE - AI-POWERED SECURITY ANALYSIS")
        print("=" * 60)

        print(f"[*] Loading enriched data from: {input_path}")
        enriched_data = self.load_enriched_data(input_path)

        final_report = self.process_vulnerabilities(enriched_data)
        report_data  = self.generate_final_report(final_report, output_path)

        print(f"\n{'='*60}")
        print("  🔍 ANALYSE SECURFLOW TERMINÉE")
        print(f"  🌐 Dashboard : https://itsnoha0x.github.io/SecurFlow/")
        print(f"{'='*60}\n")

        if report_data["decision_metadata"]["decisions"]["BLOQUER"] > 0:
            print("[!] Critical vulnerabilities detected - pipeline should be blocked!")
            sys.exit(2)

        print("[✓] No critical decisions - pipeline can continue")
        return report_data


# ----------------------------------------------------------------------

def main():
    engine = DecisionEngine()
    return engine.run()


if __name__ == "__main__":
    main()