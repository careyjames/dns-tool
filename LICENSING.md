# Licensing Model (Open Core)

DNS Tool is licensed under **Business Source License 1.1 (BUSL-1.1)** with a rolling Change Date of **three years from the publication of each version**, after which it converts to **Apache-2.0**.

## What this means

### You can:
- Read, study, and learn from the source code
- Modify the code and create derivative works
- Use it for development, testing, research, and education
- Run it in production to audit domains you own or control
- Use it as a security consultant or MSP to audit domains on behalf of your clients
- Run it as an internal tool within your organization for security operations
- Contribute improvements back to the project

### You cannot:
- Offer it (or a derivative) as a hosted, managed, or API-based DNS audit service to third parties
- Embed it in a competing commercial product where DNS security audit functionality is material to the offering
- Sell a competing commercial service built on this code

### What is a "Competitive Offering"?
A product or service that is (a) offered to third parties on a Hosted, Managed, Embedded, or API-based basis AND (b) provides DNS security audit, DNS intelligence, or domain posture assessment functionality that is material to the value of the offering.

**Formal definitions:**

- **Hosted** — Making the functionality of the Licensed Work available to third parties as a service, where the service operator (not the end user) controls the infrastructure.
- **Managed** — Offering the Licensed Work to third parties as a managed service where the operator handles deployment, maintenance, upgrades, or operational responsibility on behalf of the end user.
- **Embedded** — Including the Licensed Work (in whole or in substantial part) in source code, executable code, or packaged form within another product, or packaging a product such that the Licensed Work must be accessed, downloaded, or invoked for it to operate.

### Security consultants and MSPs
Using DNS Tool to audit client domains as part of professional services (consulting, managed security, IT administration) is explicitly permitted. The restriction applies only to offering the tool itself as a standalone hosted or managed product to those clients.

### After the Change Date:
Each version automatically converts to **Apache-2.0** — fully permissive, no restrictions — three years after it is first publicly distributed. For versions published before 2026-02-14, the Change Date is 2029-02-14.

## What this repository contains

This repository contains the complete DNS Tool platform:

### Core platform (default build)
- Go/Gin web server, routing, middleware, templates
- DNS client (multi-resolver, DoH fallback, UDP fast-probe)
- SMTP transport probes
- Frontend (Bootstrap dark theme, PWA, dual intelligence products with TLP classification)
- Email Header Analyzer (SPF/DKIM/DMARC verification, spoofing detection, OpenPhish integration)
- IP Intelligence (reverse lookups, ASN attribution, geolocation)
- AI Surface Scanner (llms.txt, AI crawler governance, prompt injection detection)
- DKIM selector discovery and key strength analysis
- Enterprise DNS provider detection
- Edge/CDN vs. origin detection
- SaaS TXT footprint extraction and classification
- Posture drift detection (canonical SHA-3-512 hashing)
- Remediation engine with RFC-aligned Priority Actions
- OSS stub interfaces (`_oss.go` files providing safe defaults for the default build)
- Golden rules test suite
- Live integration test suite

### Extended intelligence (intel build — `go build -tags intel`)
The `_intel.go` files contain the extended intelligence modules that power active features in the running product. The default build provides the framework and safe defaults, while the intel build supplies the databases, patterns, and algorithms that produce full intelligence output.

### Provider Intelligence (providers.go)
- DMARC monitoring provider detection databases (vendor identification from rua/ruf domains)
- SPF flattening provider detection (include-pattern matching)
- Hosted DKIM provider identification and crediting
- Dynamic service detection (zone-based CNAME delegation scanning)
- CNAME-based provider classification database

### Infrastructure Classification (infrastructure.go)
- Self-hosted, managed, and government DNS tier databases
- Government domain recognition and classification
- Managed DNS provider tier detection
- Extended web, DNS, and email hosting detection patterns
- Email security management detection (provider-aware analysis)
- Alternative security posture item collection

### DKIM State Enrichment (dkim_state.go)
The DKIM state classification engine (Absent, Success, ProviderInferred, ThirdPartyOnly, Inconclusive, WeakKeysOnly, NoMailDomain) is fully implemented in the public repo. The private repo extends this with provider-aware state transitions that credit known hosted DKIM providers.

### Intelligence Confidence (confidence.go)
- Extended confidence levels beyond the base Observed/Inferred/Third-party system

### IP Investigation (ip_investigation.go)
- Full PTR record analysis and forward-confirmed reverse DNS (FCrDNS) verification
- ASN-to-CDN correlation and CDN/edge network detection
- Domain relationship classification (direct assets, email providers, SPF-authorized senders, CT subdomain matches)
- IP neighborhood analysis with executive verdicts
- SPF record deep-inspection and include-chain IP matching
- PTR-based hosting provider detection

### AI Surface Scanner (ai_surface/*.go)
- SSRF-hardened HTTP text file fetcher
- llms.txt detection, parsing, and structured field extraction
- Known AI crawler database for robots.txt governance analysis
- AI recommendation poisoning detection patterns (prefilled prompts, CSS-hidden prompt injection)

### Feature Parity Manifest (manifest.go)
- Build-time populated feature registry for internal quality assurance and coverage tracking

## How the build tags work

The default build runs standalone with full core functionality. Every section renders in the UI — `_oss.go` stub files return safe, non-nil defaults so the application works end-to-end. Some sections return baseline results in the default build; the `_intel.go` implementations produce the full intelligence output. Go's build tag system selects the appropriate implementation at compile time — `_oss.go` files are compiled by default, `_intel.go` files are compiled only with `-tags intel`.

## Contributing

By contributing code to this repository, you agree that your contributions may be used under the terms of the BUSL-1.1 (and the Apache-2.0 license after the Change Date). A Contributor License Agreement (CLA) may be required for substantial contributions.

## Commercial Licensing

For organizations that need capabilities beyond the BUSL-1.1-permitted uses, commercial licenses are available by arrangement. Contact us to discuss your specific requirements.

### What a commercial license can include
- All public repo capabilities plus the complete private intelligence databases
- Self-hosted deployment (on-premises or private cloud)
- Additional deployment and integration options as needed

### Who should contact us
- Security vendors who want to embed DNS audit capabilities in their platform
- Managed service providers who want to offer DNS Tool as a branded service
- Enterprises requiring dedicated deployment with custom integrations
- Organizations needing capabilities beyond the public open-core release

## Questions

For licensing inquiries or commercial arrangements, contact: licensing@it-help.tech
