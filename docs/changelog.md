## docs/changelog.md

# Changelog

All notable changes to DNS Tool are documented here. This project adheres to semantic versioning.

* **v1.2.3** – *Released 2025-05-17*
  **New Features:** Added support for BIMI and MTA-STS checks in the output (the tool now identifies BIMI records and validates MTA-STS policies). Improved DMARC feedback messages – the tool now explicitly warns when `p=none` and praises `p=reject` configurations.
  **Improvements:** Optimized interactive mode for faster start-up. Updated embedded dependencies to latest versions for security patches. Minor tweaks to color output for better readability on Windows.
  **Fixes:** Resolved a bug where multiple SPF records were not all detected in certain cases. Fixed an issue with DNSSEC detection on domains that have A records but no RRSIG (now correctly flags as not signed).

* **v1.2.2** – *Released 2025-04-10*
  **New Features:** Introduced DANE (TLSA) record checks for SMTP and HTTPS services. DNS Tool will now alert if your domain has no TLSA for SMTP (which is optional) and show any existing TLSA records. Added CAA record checking with a recommendation if none present.
  **Improvements:** Batch mode output formatting enhanced – each domain’s section is clearly separated with a header for easier parsing. Verbose mode now logs HTTP status codes for MTA-STS policy fetch attempts, helping debug MTA-STS deployment issues.
  **Fixes:** Fixed detection of deprecated Google MX records (aspmx2/3.googlemail.com) – now properly warns if those are present. Corrected some typos in output messages for clarity.

* **v1.2.1** – *Released 2025-03-01*
  Initial release of **DNS Tool (Python Edition)**. This version introduced the core functionality of the tool: interactive and batch modes, comprehensive DNS checks for NS, A, AAAA, MX, TXT, SPF, DKIM, DMARC, DNSSEC, PTR, etc., and integrated RDAP lookups for registrar info. The focus was on providing a unified output with clear indicators (✅/❌/⚠️) for each check. Packaged as a single-file executable via PyInstaller for easy distribution on Linux, macOS, and Windows.

*(For a detailed history and commit-by-commit information, see the Git repository logs. Future release notes will continue to document new features, improvements, and fixes.)*
