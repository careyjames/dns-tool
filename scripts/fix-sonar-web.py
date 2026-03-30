#!/usr/bin/env python3
"""DEPRECATED: This script was used for the two-repo (dns-tool-web mirror) architecture.
Single-repo consolidation (2026-03) eliminated the need for sonar-project.properties rewriting.
SonarCloud now uses a single project key (dns-tool-full) for IT-Help-San-Diego/dns-tool.
This file can be safely deleted."""
import sys
print("DEPRECATED: fix-sonar-web.py is no longer needed (single-repo architecture).", file=sys.stderr)
sys.exit(0)
