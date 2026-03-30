# Security Policy

If you believe you found a security issue in systems operated by IT Help San Diego Inc., please report it responsibly.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest release on `main` | Yes |
| Older releases | Best-effort |

Only the latest deployed version receives active security patches. Older versions may receive fixes on a best-effort basis depending on severity.

## Reporting a Vulnerability

### Contact

- **Email:** [security@it-help.tech](mailto:security@it-help.tech)
  - Suggested subject: *Security Report — \<brief summary\>*
- **security.txt:** [/.well-known/security.txt](https://dnstool.it-help.tech/.well-known/security.txt) (RFC 9116)

Preferred language: English. If you need a different secure reporting channel, request one in your initial email.

### What to Include

Please include enough detail for reliable triage:

- A clear description of the issue and impact
- Exact URL(s), endpoint(s), or component(s) affected
- Reproduction steps and any prerequisites
- Proof of concept, logs, or screenshots (when safe to share)
- Your contact information for follow-up

## Scope

This policy applies to internet-facing assets owned and operated by IT Help San Diego Inc.:

| Asset | Type | Status |
| ----- | ---- | ------ |
| `dnstool.it-help.tech` | Web Application (DNS Tool) | In Scope |
| `www.it-help.tech` | Corporate Website | In Scope |
| `it-help.tech` | Domain & DNS Infrastructure | In Scope |
| `*.it-help.tech` | All Subdomains | In Scope |

If you report an issue in third-party infrastructure, include evidence showing how it directly affects our operated assets.

### Out of Scope

The following are generally out of scope unless there is demonstrable business impact:

- Social engineering, phishing, or red-team activity **without explicit written authorization**
- Physical attacks or local network attacks requiring physical access, unless expressly authorized in writing
- Denial-of-service (DoS/DDoS), traffic flooding, or resource exhaustion testing, unless expressly authorized in writing with defined scope, windows, and safeguards
- Vulnerabilities that depend on outdated/unpatched client software with no direct server-side impact
- Reports without reproducible evidence
- Findings from domains analyzed *by* DNS Tool (those belong to their respective owners)

## Response Timeline

| Milestone | Target |
| --------- | ------ |
| Initial acknowledgment | 3 business days |
| Triage / status update | 10 business days |
| Remediation | Risk-based, dependent on complexity |

We will keep you informed throughout the process.

## Safe Harbor

If you act in good faith and follow this policy, we will treat your research as **authorized for coordinated vulnerability disclosure** and will not pursue legal action for your report.

This policy does not limit or override permissions granted under separate written government, regulatory, or contractual testing agreements.

Good-faith testing means:

- Avoiding privacy violations, data destruction, and service disruption
- Accessing only the minimum data required to demonstrate the issue
- Stopping testing after obtaining proof and reporting promptly
- Not sharing, retaining, or reusing any non-public data

## Authorized Security Testing

IT Help San Diego participates in recurring external security assessments, including CISA Cyber Hygiene scanning and other explicitly authorized testing engagements.

Activities that may otherwise be out of scope are permitted when authorization exists in writing (for example: program agreement, statement of work, or rules of engagement).

## Public Disclosure

Please do not publicly disclose vulnerabilities until remediation is complete or a coordinated timeline is agreed upon in writing.

## Bug Bounty

IT Help San Diego Inc. does not currently operate a paid bug bounty program.

## Full Security Policy

The complete security policy, including security practices and privacy pledge, is available at:

- **Web:** [https://dnstool.it-help.tech/security-policy](https://dnstool.it-help.tech/security-policy)
- **security.txt:** [https://dnstool.it-help.tech/.well-known/security.txt](https://dnstool.it-help.tech/.well-known/security.txt)
