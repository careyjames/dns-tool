#!/usr/bin/env python3
"""
SECINTENT Reconciliation Checker

Parses SECINTENT inline tags from source code, reconciles them against
the YAML registry, and reports violations:
  - Missing YAML entry for code tag
  - Orphaned YAML entry (no matching code tag)
  - Expired exceptions
  - Overly-broad scope (file pattern too wide)
  - Expiring soon (within 30 days)

Exit codes:
  0 = all checks pass
  1 = violations found (missing, orphaned, expired, overly-broad)
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timedelta

try:
    from ruamel.yaml import YAML
except ImportError:
    try:
        import yaml as pyyaml
        class YAML:
            def load(self, stream):
                return pyyaml.safe_load(stream)
    except ImportError:
        print("ERROR: Neither ruamel.yaml nor PyYAML is installed")
        sys.exit(2)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security-intents.yaml")
SECINTENT_PATTERN = re.compile(r"SECINTENT-(\d+)")
OVERLY_BROAD_PATTERNS = ["**/*", "*", "**"]


def load_registry():
    yaml = YAML()
    with open(REGISTRY_PATH, "r") as f:
        data = yaml.load(f)
    return data.get("intents", [])


def find_code_tags():
    tags = {}
    extensions = (".go", ".py", ".js", ".ts", ".html", ".css", ".yaml", ".yml", ".sh", ".toml", ".properties")
    exclude_dirs = {
        "vendor", "node_modules", ".cache", ".pythonlibs",
        "attached_assets", ".scannerwork", ".agents", ".local",
        "security",
    }

    root_config_files = [
        ".gitleaks.toml", ".semgrepignore", "sonar-project.properties",
    ]
    for cfg in root_config_files:
        cfg_path = os.path.join(REPO_ROOT, cfg)
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for match in SECINTENT_PATTERN.finditer(line):
                            tag_id = f"SECINTENT-{match.group(1)}"
                            if tag_id not in tags:
                                tags[tag_id] = []
                            tags[tag_id].append({"file": cfg, "line": lineno, "text": line.strip()})
            except (IOError, OSError):
                pass

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".")]
        for fname in files:
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, REPO_ROOT)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for match in SECINTENT_PATTERN.finditer(line):
                            tag_id = f"SECINTENT-{match.group(1)}"
                            if tag_id not in tags:
                                tags[tag_id] = []
                            tags[tag_id].append({"file": relpath, "line": lineno, "text": line.strip()})
            except (IOError, OSError):
                continue
    return tags


def file_matches_scope(filepath, scope_pattern):
    if "**" in scope_pattern or "*" in scope_pattern:
        return glob.fnmatch.fnmatch(filepath, scope_pattern)
    return filepath == scope_pattern or filepath.startswith(scope_pattern.rstrip("/") + "/")


def check_reconciliation(registry, code_tags):
    errors = []
    warnings = []
    registry_ids = {entry["id"] for entry in registry}
    code_tag_ids = set(code_tags.keys())
    today = datetime.now().date()
    soon = today + timedelta(days=30)

    for tag_id in code_tag_ids - registry_ids:
        locations = code_tags[tag_id]
        for loc in locations:
            errors.append(f"MISSING REGISTRY: {tag_id} found in {loc['file']}:{loc['line']} but not in security-intents.yaml")

    for entry in registry:
        eid = entry["id"]
        if eid not in code_tag_ids:
            errors.append(f"ORPHANED REGISTRY: {eid} ({entry.get('title', '')}) has no matching code tag")
        else:
            file_pattern = entry.get("file", "")
            if file_pattern:
                tag_locations = code_tags[eid]
                scoped = [loc for loc in tag_locations if file_matches_scope(loc["file"], file_pattern)]
                if not scoped:
                    warnings.append(
                        f"SCOPE MISMATCH: {eid} code tags found but none in expected scope '{file_pattern}' "
                        f"(found in: {', '.join(loc['file'] for loc in tag_locations)})"
                    )

        file_pattern = entry.get("file", "")
        if file_pattern in OVERLY_BROAD_PATTERNS:
            errors.append(f"OVERLY BROAD: {eid} file scope '{file_pattern}' is too broad — narrow to specific paths")

        expires_str = entry.get("expires", "")
        if expires_str:
            try:
                expires_date = datetime.strptime(str(expires_str), "%Y-%m-%d").date()
                if expires_date < today:
                    errors.append(f"EXPIRED: {eid} ({entry.get('title', '')}) expired on {expires_str}")
                elif expires_date <= soon:
                    warnings.append(f"EXPIRING SOON: {eid} ({entry.get('title', '')}) expires on {expires_str}")
            except ValueError:
                errors.append(f"INVALID DATE: {eid} has invalid expires date: {expires_str}")

    return errors, warnings


def generate_report(registry, code_tags, errors, warnings):
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_intents": len(registry),
        "total_code_tags": sum(len(v) for v in code_tags.values()),
        "unique_code_tags": len(code_tags),
        "errors": errors,
        "warnings": warnings,
        "status": "FAIL" if errors else "PASS",
        "intents": [],
    }

    for entry in registry:
        eid = entry["id"]
        intent_report = {
            "id": eid,
            "title": entry.get("title", ""),
            "category": entry.get("category", ""),
            "severity": entry.get("severity", ""),
            "expires": str(entry.get("expires", "")),
            "code_locations": code_tags.get(eid, []),
            "has_code_tag": eid in code_tags,
        }
        report["intents"].append(intent_report)

    return report


def main():
    print("═══════════════════════════════════════════")
    print("  SECINTENT Reconciliation Check")
    print("═══════════════════════════════════════════")
    print()

    if not os.path.exists(REGISTRY_PATH):
        print(f"ERROR: Registry not found: {REGISTRY_PATH}")
        sys.exit(2)

    registry = load_registry()
    print(f"  Registry entries: {len(registry)}")

    code_tags = find_code_tags()
    print(f"  Code tags found:  {len(code_tags)} unique IDs ({sum(len(v) for v in code_tags.values())} locations)")
    print()

    errors, warnings = check_reconciliation(registry, code_tags)

    if warnings:
        print("  WARNINGS:")
        for w in warnings:
            print(f"    ⚠ {w}")
        print()

    if errors:
        print("  ERRORS:")
        for e in errors:
            print(f"    ✗ {e}")
        print()

    report = generate_report(registry, code_tags, errors, warnings)

    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    report_path = os.path.join(reports_dir, "secintent-report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  Report written to: {report_path}")

    exceptions_md = os.path.join(reports_dir, "exceptions.md")
    with open(exceptions_md, "w") as f:
        f.write("# Security Intent Exceptions Report\n\n")
        f.write(f"Generated: {report['timestamp']}\n\n")
        f.write(f"| Status | Total |\n|--------|-------|\n")
        f.write(f"| Active intents | {len(registry)} |\n")
        f.write(f"| Code tags found | {report['unique_code_tags']} |\n")
        f.write(f"| Errors | {len(errors)} |\n")
        f.write(f"| Warnings | {len(warnings)} |\n\n")

        f.write("## Active Exceptions\n\n")
        for entry in registry:
            f.write(f"### {entry['id']}: {entry.get('title', '')}\n\n")
            f.write(f"- **Category**: {entry.get('category', '')}\n")
            f.write(f"- **Severity**: {entry.get('severity', '')}\n")
            f.write(f"- **File**: `{entry.get('file', '')}`\n")
            f.write(f"- **Expires**: {entry.get('expires', '')}\n")
            f.write(f"- **Owner**: {entry.get('owner', '')}\n")
            f.write(f"- **Justification**: {entry.get('justification', '').strip()}\n\n")

        if errors:
            f.write("## Violations\n\n")
            for e in errors:
                f.write(f"- ✗ {e}\n")
            f.write("\n")

        if warnings:
            f.write("## Warnings\n\n")
            for w in warnings:
                f.write(f"- ⚠ {w}\n")
            f.write("\n")

    print(f"  Exceptions report: {exceptions_md}")
    print()

    print("═══════════════════════════════════════════")
    if errors:
        print(f"  SECINTENT CHECK: FAILED ✗ ({len(errors)} error(s))")
        print("═══════════════════════════════════════════")
        return 1
    else:
        status = "PASSED ✓"
        if warnings:
            status += f" ({len(warnings)} warning(s))"
        print(f"  SECINTENT CHECK: {status}")
        print("═══════════════════════════════════════════")
        return 0


if __name__ == "__main__":
    sys.exit(main())
