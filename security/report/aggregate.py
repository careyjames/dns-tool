#!/usr/bin/env python3
"""
Security Report Aggregator

Normalizes output from all scanners into a unified format:
  - security/reports/latest.md   (human-readable)
  - security/reports/latest.json (machine-readable)
  - security/reports/latest.sarif (SARIF 2.1.0)

Supports baseline diff mode: compares against security/reports/baseline.json
and only flags NEW critical/high findings as blocking.
"""

import json
import os
import sys
from datetime import datetime


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECURITY_DIR = os.path.dirname(SCRIPT_DIR)
REPORTS_DIR = os.path.join(SECURITY_DIR, "reports")
BASELINE_PATH = os.path.join(REPORTS_DIR, "baseline.json")


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def normalize_semgrep(data):
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
        raw_severity = result.get("extra", {}).get("severity", "INFO")
        severity = severity_map.get(raw_severity.upper(), "info")

        file_path = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)
        finding = {
            "id": f"semgrep-{result.get('check_id', 'unknown')}-{file_path}:{start_line}",
            "scanner": "semgrep",
            "rule_id": result.get("check_id", ""),
            "severity": severity,
            "message": result.get("extra", {}).get("message", ""),
            "file": result.get("path", ""),
            "line": result.get("start", {}).get("line", 0),
            "end_line": result.get("end", {}).get("line", 0),
            "cwe": result.get("extra", {}).get("metadata", {}).get("cwe", []),
            "remediation": "",
            "status": "new",
            "secintent_id": None,
        }
        findings.append(finding)
    return findings


def normalize_osv(data):
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        source = result.get("source", {})
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                severity = "medium"
                for sev in vuln.get("database_specific", {}).get("severity", []):
                    if isinstance(sev, str):
                        severity = sev.lower()
                        break

                for alias in vuln.get("aliases", []):
                    if alias.startswith("CVE-"):
                        pass

                finding = {
                    "id": f"osv-{vuln.get('id', 'unknown')}",
                    "scanner": "osv-scanner",
                    "rule_id": vuln.get("id", ""),
                    "severity": severity,
                    "message": vuln.get("summary", vuln.get("details", "")[:200]),
                    "file": source.get("path", ""),
                    "line": 0,
                    "end_line": 0,
                    "cwe": [],
                    "remediation": f"Update {pkg_info.get('name', '')} (current: {pkg_info.get('version', 'unknown')})",
                    "status": "new",
                    "secintent_id": None,
                    "package": pkg_info.get("name", ""),
                    "package_version": pkg_info.get("version", ""),
                }
                findings.append(finding)
    return findings


def normalize_gitleaks(data):
    if not data or not isinstance(data, list):
        return []
    findings = []
    for leak in data:
        finding = {
            "id": f"gitleaks-{leak.get('RuleID', 'unknown')}-{leak.get('StartLine', 0)}",
            "scanner": "gitleaks",
            "rule_id": leak.get("RuleID", ""),
            "severity": "high",
            "message": f"Secret detected: {leak.get('Description', leak.get('RuleID', ''))}",
            "file": leak.get("File", ""),
            "line": leak.get("StartLine", 0),
            "end_line": leak.get("EndLine", 0),
            "cwe": ["CWE-798"],
            "remediation": "Remove secret from source and rotate credential",
            "status": "new",
            "secintent_id": None,
        }
        findings.append(finding)
    return findings


def normalize_trivy(data):
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN").lower()
            finding = {
                "id": f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                "scanner": "trivy",
                "rule_id": vuln.get("VulnerabilityID", ""),
                "severity": severity,
                "message": vuln.get("Title", vuln.get("Description", "")[:200]),
                "file": target,
                "line": 0,
                "end_line": 0,
                "cwe": [],
                "remediation": f"Update {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest')}",
                "status": "new",
                "secintent_id": None,
            }
            findings.append(finding)
        for misconfig in result.get("Misconfigurations", []):
            severity = misconfig.get("Severity", "UNKNOWN").lower()
            finding = {
                "id": f"trivy-misconfig-{misconfig.get('ID', 'unknown')}",
                "scanner": "trivy",
                "rule_id": misconfig.get("ID", ""),
                "severity": severity,
                "message": misconfig.get("Title", misconfig.get("Message", "")),
                "file": target,
                "line": 0,
                "end_line": 0,
                "cwe": [],
                "remediation": misconfig.get("Resolution", ""),
                "status": "new",
                "secintent_id": None,
            }
            findings.append(finding)
        for secret in result.get("Secrets", []):
            finding = {
                "id": f"trivy-secret-{secret.get('RuleID', 'unknown')}-{secret.get('StartLine', 0)}",
                "scanner": "trivy",
                "rule_id": secret.get("RuleID", ""),
                "severity": "high",
                "message": f"Secret: {secret.get('Title', secret.get('Match', ''))}",
                "file": target,
                "line": secret.get("StartLine", 0),
                "end_line": secret.get("EndLine", 0),
                "cwe": ["CWE-798"],
                "remediation": "Remove secret from source and rotate",
                "status": "new",
                "secintent_id": None,
            }
            findings.append(finding)
    return findings


def normalize_dast(report_name, data):
    if not data:
        return []
    findings = []
    for f in data.get("findings", []):
        finding = {
            "id": f"dast-{report_name}-{f.get('type', 'unknown')}-{f.get('path', f.get('header', ''))}",
            "scanner": f"dast-{report_name}",
            "rule_id": f.get("type", ""),
            "severity": f.get("severity", "info"),
            "message": f.get("message", ""),
            "file": f.get("path", data.get("target", "")),
            "line": 0,
            "end_line": 0,
            "cwe": [],
            "remediation": "",
            "status": "new",
            "secintent_id": None,
        }
        findings.append(finding)
    return findings


def load_secintent_report():
    path = os.path.join(REPORTS_DIR, "secintent-report.json")
    return load_json(path)


def apply_baseline_diff(findings, baseline):
    if not baseline:
        return findings

    baseline_ids = {f["id"] for f in baseline.get("findings", [])}
    for f in findings:
        if f["id"] in baseline_ids:
            f["status"] = "existing"
    return findings


def classify_findings(findings):
    for f in findings:
        sev = f["severity"]
        if f["status"] == "existing":
            f["action"] = "accepted"
        elif sev in ("critical", "high"):
            f["action"] = "blocked"
        elif sev == "medium":
            f["action"] = "warned"
        else:
            f["action"] = "tracked"
    return findings


def generate_markdown(report):
    lines = []
    lines.append("# DNS Tool Security Scan Report\n")
    lines.append(f"**Generated**: {report['timestamp']}\n")
    lines.append(f"**Scanners**: {', '.join(report['scanners_run'])}\n")
    lines.append("")

    lines.append("## Summary\n")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total findings | {report['summary']['total']} |")
    lines.append(f"| Critical/High (blocking) | {report['summary']['blocked']} |")
    lines.append(f"| Medium (warning) | {report['summary']['warned']} |")
    lines.append(f"| Low/Info (tracked) | {report['summary']['tracked']} |")
    lines.append(f"| Existing (accepted) | {report['summary']['accepted']} |")
    lines.append(f"| New findings | {report['summary']['new']} |")
    lines.append("")

    lines.append(f"**Status**: {'FAIL' if report['summary']['blocked'] > 0 else 'PASS'}\n")

    if report["summary"]["blocked"] > 0:
        lines.append("## Blocking Findings (Critical/High)\n")
        for f in report["findings"]:
            if f["action"] == "blocked":
                lines.append(f"### {f['id']}\n")
                lines.append(f"- **Scanner**: {f['scanner']}")
                lines.append(f"- **Severity**: {f['severity']}")
                lines.append(f"- **File**: `{f['file']}`:{f['line']}")
                lines.append(f"- **Message**: {f['message']}")
                if f.get("remediation"):
                    lines.append(f"- **Remediation**: {f['remediation']}")
                lines.append("")

    warned = [f for f in report["findings"] if f["action"] == "warned"]
    if warned:
        lines.append("## Warnings (Medium)\n")
        for f in warned:
            lines.append(f"- **{f['id']}** ({f['scanner']}): {f['message']} — `{f['file']}`:{f['line']}")
        lines.append("")

    tracked = [f for f in report["findings"] if f["action"] == "tracked"]
    if tracked:
        lines.append("## Tracked (Low/Info)\n")
        for f in tracked:
            lines.append(f"- **{f['id']}** ({f['scanner']}): {f['message']}")
        lines.append("")

    accepted = [f for f in report["findings"] if f["action"] == "accepted"]
    if accepted:
        lines.append("## Accepted (Existing Baseline)\n")
        for f in accepted:
            lines.append(f"- **{f['id']}** ({f['scanner']}): {f['message']}")
        lines.append("")

    secintent = report.get("secintent")
    if secintent:
        lines.append("## SECINTENT Exceptions\n")
        lines.append(f"- Status: {secintent.get('status', 'N/A')}")
        lines.append(f"- Total intents: {secintent.get('total_intents', 0)}")
        lines.append(f"- Errors: {len(secintent.get('errors', []))}")
        lines.append(f"- Warnings: {len(secintent.get('warnings', []))}")
        lines.append("")

    return "\n".join(lines)


def generate_sarif(report):
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }

    scanners = {}
    for f in report["findings"]:
        scanner = f["scanner"]
        if scanner not in scanners:
            scanners[scanner] = {"rules": {}, "results": []}
        rule_id = f["rule_id"]
        if rule_id not in scanners[scanner]["rules"]:
            scanners[scanner]["rules"][rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f["message"][:200]},
            }
        sarif_severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        result = {
            "ruleId": rule_id,
            "level": sarif_severity_map.get(f["severity"], "note"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(f["line"], 1)},
                },
            }],
        }
        scanners[scanner]["results"].append(result)

    for scanner_name, scanner_data in scanners.items():
        run = {
            "tool": {
                "driver": {
                    "name": scanner_name,
                    "rules": list(scanner_data["rules"].values()),
                },
            },
            "results": scanner_data["results"],
        }
        sarif["runs"].append(run)

    if not sarif["runs"]:
        sarif["runs"].append({
            "tool": {"driver": {"name": "dns-tool-security", "rules": []}},
            "results": [],
        })

    return sarif


def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)

    all_findings = []
    scanners_run = []

    semgrep_data = load_json(os.path.join(REPORTS_DIR, "semgrep.json"))
    if semgrep_data:
        all_findings.extend(normalize_semgrep(semgrep_data))
        scanners_run.append("semgrep")

    osv_data = load_json(os.path.join(REPORTS_DIR, "osv-scanner.json"))
    if osv_data:
        all_findings.extend(normalize_osv(osv_data))
        scanners_run.append("osv-scanner")

    gitleaks_data = load_json(os.path.join(REPORTS_DIR, "gitleaks.json"))
    if gitleaks_data:
        all_findings.extend(normalize_gitleaks(gitleaks_data))
        scanners_run.append("gitleaks")

    trivy_data = load_json(os.path.join(REPORTS_DIR, "trivy.json"))
    if trivy_data:
        all_findings.extend(normalize_trivy(trivy_data))
        scanners_run.append("trivy")

    for dast_name in ("headers", "tls", "crawl"):
        dast_data = load_json(os.path.join(REPORTS_DIR, f"dast-{dast_name}.json"))
        if dast_data:
            all_findings.extend(normalize_dast(dast_name, dast_data))
            scanners_run.append(f"dast-{dast_name}")

    baseline = load_json(BASELINE_PATH)
    all_findings = apply_baseline_diff(all_findings, baseline)
    all_findings = classify_findings(all_findings)

    secintent = load_secintent_report()

    summary = {
        "total": len(all_findings),
        "blocked": len([f for f in all_findings if f["action"] == "blocked"]),
        "warned": len([f for f in all_findings if f["action"] == "warned"]),
        "tracked": len([f for f in all_findings if f["action"] == "tracked"]),
        "accepted": len([f for f in all_findings if f["action"] == "accepted"]),
        "new": len([f for f in all_findings if f["status"] == "new"]),
    }

    report = {
        "timestamp": datetime.now().isoformat(),
        "scanners_run": scanners_run,
        "baseline_used": baseline is not None,
        "summary": summary,
        "findings": all_findings,
        "secintent": secintent,
    }

    json_path = os.path.join(REPORTS_DIR, "latest.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    md_path = os.path.join(REPORTS_DIR, "latest.md")
    with open(md_path, "w") as f:
        f.write(generate_markdown(report))

    sarif_path = os.path.join(REPORTS_DIR, "latest.sarif")
    with open(sarif_path, "w") as f:
        json.dump(generate_sarif(report), f, indent=2)

    print(f"  Aggregated {len(all_findings)} findings from {len(scanners_run)} scanner(s)")
    print(f"  Blocked: {summary['blocked']} | Warned: {summary['warned']} | Tracked: {summary['tracked']} | Accepted: {summary['accepted']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
