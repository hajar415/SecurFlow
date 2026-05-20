import subprocess
import json
import os
import sys
import argparse
import yaml
from datetime import datetime

# ── Charge la config ──────────────────────────────────────────
def load_config(config_path="config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

# ── Lance Trivy sur un chemin ─────────────────────────────────
def run_trivy_scan(target_path, severity_filter):
    print(f"[*] Scan de : {target_path}")
    print(f"[*] Severites : {', '.join(severity_filter)}")

    output_file = "results/trivy_raw.json"
    os.makedirs("results", exist_ok=True)

    cmd = [
        "trivy", "fs", target_path,
        "--scanners", "vuln",
        "--format", "json",
        "--severity", ",".join(severity_filter),
        "--quiet",
        "--output", output_file
    ]

    subprocess.run(cmd)

    with open(output_file, "r", encoding="utf-8") as f:
        return json.load(f)
    
# ── Lance Grype sur un chemin ─────────────────────────────────
def run_grype_scan(target_path, severity_filter):
    print(f"[*] Grype scan de : {target_path}")

    output_file = "results/grype_raw.json"
    os.makedirs("results", exist_ok=True)

    cmd = [
        "grype", f"dir:{target_path}",
        "--output", "json",
        "--file", output_file,
        "--quiet"
    ]

    subprocess.run(cmd)

    if not os.path.exists(output_file):
        print("[!] Grype n'a produit aucun fichier de sortie.")
        return [], {}

    with open(output_file, "r", encoding="utf-8") as f:
        raw = json.load(f)

    vulnerabilities = []
    epss_map = {}

    for match in raw.get("matches", []):
        vuln     = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = vuln.get("severity", "UNKNOWN").upper()

        if severity not in [s.upper() for s in severity_filter]:
            continue

        # ── Récupère le vrai CVE-ID depuis relatedVulnerabilities ──
        cve_id = vuln.get("id", "")
        related = match.get("relatedVulnerabilities", [])
        for rel in related:
            if rel.get("id", "").startswith("CVE-"):
                cve_id = rel["id"]
                break

        # ── Récupère le score EPSS (dans vuln ou dans related) ────
        epss_score      = 0.0
        epss_percentile = 0.0

        epss_list = vuln.get("epss", [])
        if not epss_list and related:
            epss_list = related[0].get("epss", [])

        if epss_list:
            epss_score      = epss_list[0].get("epss", 0.0)
            epss_percentile = epss_list[0].get("percentile", 0.0)

        # Stocke dans la map CVE-ID → scores EPSS
        if cve_id.startswith("CVE-") and epss_score > 0:
            epss_map[cve_id] = {
                "epss_score":       round(epss_score, 4),
                "epss_percentile":  round(epss_percentile * 100, 1)
            }

        cve_obj = {
            "cve_id":            cve_id,
            "package":           artifact.get("name", ""),
            "version_installed": artifact.get("version", ""),
            "version_fixed":     extract_grype_fix(vuln),
            "severity":          severity,
            "cvss_score":        extract_grype_cvss(vuln),
            "description":       vuln.get("description", "")[:300],
            "target_file":       artifact.get("locations", [{}])[0].get("path", "unknown"),
            "ecosystem":         artifact.get("type", "unknown"),
            "references":        vuln.get("urls", [])[:3],
            "source":            "grype",
            "epss_score":        round(epss_score, 4),
            "epss_percentile":   round(epss_percentile * 100, 1),
        }
        vulnerabilities.append(cve_obj)

    print(f"[*] Grype : {len(vulnerabilities)} CVE trouvees, {len(epss_map)} scores EPSS recuperes")
    return vulnerabilities, epss_map


# ── Extrait le fix depuis Grype ───────────────────────────────
def extract_grype_fix(vuln):
    try:
        versions = vuln["fix"]["versions"]
        return ", ".join(versions) if versions else "aucun"
    except (KeyError, TypeError):
        return "aucun"


# ── Extrait le CVSS depuis Grype ──────────────────────────────
def extract_grype_cvss(vuln):
    try:
        for cvss in vuln.get("cvss", []):
            if cvss.get("version", "").startswith("3"):
                return cvss["metrics"]["baseScore"]
        return 0.0
    except (KeyError, TypeError):
        return 0.0


# ── Fusionne les résultats Trivy + Grype ──────────────────────
def merge_results(trivy_vulns, grype_vulns, epss_map):
    merged = []
    seen_cve = set()
    seen_pkg_ver = set()

    # Priorité à Trivy + injection des scores EPSS de Grype
    for v in trivy_vulns:
        v["source"] = "trivy"

        # Injecte le score EPSS si disponible
        if v["cve_id"] in epss_map:
            v["epss_score"] = epss_map[v["cve_id"]]["epss_score"]
            v["epss_percentile"] = epss_map[v["cve_id"]]["epss_percentile"]
        else:
            v["epss_score"] = 0.0
            v["epss_percentile"] = 0.0

        seen_cve.add(v["cve_id"])
        seen_pkg_ver.add(v["package"] + v["version_installed"])
        merged.append(v)

    # Grype : ajoute seulement ce qui est vraiment nouveau
    new_from_grype = 0
    for v in grype_vulns:
        cve_id = v["cve_id"]
        pkg_key = v["package"] + v["version_installed"]

        if cve_id in seen_cve:
            continue
        if cve_id.startswith("GHSA") and pkg_key in seen_pkg_ver:
            continue

        seen_cve.add(cve_id)
        merged.append(v)
        new_from_grype += 1

    epss_enriched = sum(1 for v in merged if v.get("epss_score", 0) > 0)
    print(f"[*] Fusion : {len(trivy_vulns)} Trivy + {new_from_grype} nouvelles Grype = {len(merged)} total")
    print(f"[*] EPSS : {epss_enriched} CVE enrichies avec score EPSS")
    return merged

# ── Charge les CVE à ignorer (.trivyignore) ───────────────────
def load_ignored_cves(ignore_file=".trivyignore"):
    ignored = []
    if not os.path.exists(ignore_file):
        return ignored
    with open(ignore_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ignored.append(line.split()[0])
    return ignored

# ── Transforme la sortie Trivy en format standard ─────────────
def parse_trivy_output(raw_data, ignored_cves):
    vulnerabilities = []
    ignored_count = 0

    results = raw_data.get("Results", [])

    for result in results:
        target = result.get("Target", "unknown")
        pkg_type = result.get("Type", "unknown")
        vulns = result.get("Vulnerabilities") or []

        for vuln in vulns:
            cve_id = vuln.get("VulnerabilityID", "")

            if cve_id in ignored_cves:
                ignored_count += 1
                continue

            cve_obj = {
                "cve_id": cve_id,
                "package": vuln.get("PkgName", ""),
                "version_installed": vuln.get("InstalledVersion", ""),
                "version_fixed": vuln.get("FixedVersion", ""),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cvss_score": extract_cvss(vuln),
                "description": vuln.get("Description", "")[:300],
                "target_file": target,
                "ecosystem": pkg_type,
                "references": vuln.get("References", [])[:3],
            }
            vulnerabilities.append(cve_obj)

    return vulnerabilities, ignored_count

# ── Extrait le score CVSS ─────────────────────────────────────
def extract_cvss(vuln):
    try:
        return vuln["CVSS"]["nvd"]["V3Score"]
    except (KeyError, TypeError):
        try:
            return vuln["CVSS"]["redhat"]["V3Score"]
        except (KeyError, TypeError):
            return 0.0

# ── Construit le JSON final ───────────────────────────────────
def build_output(vulnerabilities, ignored_count, target_path, config):
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulnerabilities:
        sev = v["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "scan_metadata": {
            "tool": "trivy",
            "version": get_trivy_version(),
            "target": target_path,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity_filter": config.get("severity_filter", []),
        },
        "summary": {
            "total_found": len(vulnerabilities),
            "total_ignored": ignored_count,
            "by_severity": severity_counts,
        },
        "vulnerabilities": vulnerabilities,
    }

# ── Récupère la version de Trivy ─────────────────────────────
def get_trivy_version():
    try:
        r = subprocess.run(["trivy", "--version"], capture_output=True, text=True)
        return r.stdout.split("\n")[0].replace("Version: ", "").strip()
    except Exception:
        return "unknown"
# ── Point d'entrée principal ──────────────────────────────────
def main():
    # ── Arguments ligne de commande ───────────────────────────
    parser = argparse.ArgumentParser(
        description="CTI Scanner - Analyse les dependances et detecte les CVE",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--target", "-t",
        type=str,
        help="Chemin du projet a scanner (ex: projet-test)"
    )
    parser.add_argument(
        "--severity", "-s",
        type=str,
        help="Severites separees par virgule (ex: CRITICAL,HIGH,MEDIUM)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Fichier de sortie JSON (ex: results/results.json)"
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config.yaml",
        help="Fichier de configuration (defaut: config.yaml)"
    )
    args = parser.parse_args()

    # ── Charge la config ──────────────────────────────────────
    if not os.path.exists(args.config):
        print(f"[!] Erreur : fichier de config '{args.config}' introuvable.")
        sys.exit(1)

    config = load_config(args.config)

    # Les arguments CLI ont priorité sur config.yaml
    target = args.target or config.get("target_path", "target_app")
    output_file = args.output or config.get("output_file", "../../shared/1_raw_results.json")

    if args.severity:
        severity_filter = [s.strip() for s in args.severity.split(",")]
    else:
        severity_filter = config.get("severity_filter", ["CRITICAL", "HIGH"])

    # ── Vérifications avant de lancer ─────────────────────────
    if not os.path.exists(target):
        print(f"[!] Erreur : le dossier cible '{target}' n'existe pas.")
        sys.exit(1)

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    for s in severity_filter:
        if s not in valid_severities:
            print(f"[!] Erreur : severite invalide '{s}'. Valeurs acceptees : {valid_severities}")
            sys.exit(1)

    # ── Scan ──────────────────────────────────────────────────
    # ── Scan Trivy ────────────────────────────────────────────
    raw = run_trivy_scan(target, severity_filter)
    ignored_cves = load_ignored_cves(".trivyignore")
    trivy_vulns, ignored_count = parse_trivy_output(raw, ignored_cves)

    # ── Scan Grype ────────────────────────────────────────────
    grype_vulns, epss_map = run_grype_scan(target, severity_filter)

    # ── Fusion des deux scanners ──────────────────────────────
    vulns = merge_results(trivy_vulns, grype_vulns, epss_map)
    # ── Déduplication ─────────────────────────────────────────
    seen = set()
    unique_vulns = []
    for v in vulns:
        key = v["cve_id"] + v["package"]
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    duplicates_removed = len(vulns) - len(unique_vulns)

    # ── Construction du JSON final ────────────────────────────
    output = build_output(unique_vulns, ignored_count, target, config)
    output["summary"]["duplicates_removed"] = duplicates_removed

    # ── Sauvegarde JSON ───────────────────────────────────────
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # ── Rapport texte lisible ─────────────────────────────────
    report_path = output_file.replace(".json", "_report.txt")
    write_text_report(output, report_path)

    # ── Résumé terminal ───────────────────────────────────────
    print(f"\n{'='*50}")
    print(f"  SCAN TERMINE")
    print(f"{'='*50}")
    print(f"  Cible               : {target}")
    print(f"  Total CVE trouvees  : {output['summary']['total_found']}")
    print(f"  Ignorees            : {ignored_count}")
    print(f"  Doublons supprimes  : {duplicates_removed}")
    print(f"  CRITICAL            : {output['summary']['by_severity']['CRITICAL']}")
    print(f"  HIGH                : {output['summary']['by_severity']['HIGH']}")
    print(f"  MEDIUM              : {output['summary']['by_severity']['MEDIUM']}")
    print(f"  Rapport JSON        : {output_file}")
    print(f"  Rapport texte       : {report_path}")
    print(f"{'='*50}\n")

    # Code de sortie : 1 si CRITICAL trouvee (utile pour CI/CD)
    if output["summary"]["by_severity"]["CRITICAL"] > 0:
        print("[!] CVE CRITICAL detectee — le pipeline devrait etre bloque.")
        sys.exit(2)


# ── Rapport texte lisible ─────────────────────────────────────
def write_text_report(output, report_path):
    lines = []
    lines.append("=" * 60)
    lines.append("  RAPPORT DE SCAN CTI")
    lines.append("=" * 60)
    lines.append(f"  Outil     : {output['scan_metadata']['tool']} v{output['scan_metadata']['version']}")
    lines.append(f"  Cible     : {output['scan_metadata']['target']}")
    lines.append(f"  Date      : {output['scan_metadata']['timestamp']}")
    lines.append(f"  Severites : {', '.join(output['scan_metadata']['severity_filter'])}")
    lines.append("")
    lines.append("  RESUME")
    lines.append("-" * 60)
    lines.append(f"  Total CVE    : {output['summary']['total_found']}")
    lines.append(f"  CRITICAL     : {output['summary']['by_severity']['CRITICAL']}")
    lines.append(f"  HIGH         : {output['summary']['by_severity']['HIGH']}")
    lines.append(f"  MEDIUM       : {output['summary']['by_severity']['MEDIUM']}")
    lines.append(f"  Ignorees     : {output['summary']['total_ignored']}")
    lines.append(f"  Doublons     : {output['summary']['duplicates_removed']}")
    lines.append("")
    lines.append("  DETAIL DES VULNERABILITES")
    lines.append("-" * 60)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sorted_vulns = sorted(output["vulnerabilities"], key=lambda x: order.get(x["severity"], 5))

    for v in sorted_vulns:
        lines.append(f"\n  [{v['severity']}] {v['cve_id']} — {v['package']} v{v['version_installed']}")
        lines.append(f"  Fix disponible : {v['version_fixed'] or 'aucun'}")
        lines.append(f"  CVSS Score     : {v['cvss_score']}")
        lines.append(f"  Description    : {v['description'][:150]}...")

    lines.append("\n" + "=" * 60)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()