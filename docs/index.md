## docs/index.md

# Introduction to DNS Tool

> **Legacy CLI documentation**
>
> This docs set covers the DNS Tool command-line release line.
>
> For the actively developed version and current feature set, use the web app: https://dnstool.it-help.tech/

**DNS Tool** is an all-in-one command-line utility for checking critical DNS records like **DMARC**, **SPF**, **DKIM**, **DNSSEC**, and more. It gives you a bird’s-eye view of a domain’s DNS and email security posture, helping strengthen defenses against phishing and spoofing. Whether you’re a system administrator or a security analyst, DNS Tool streamlines the process of validating DNS configurations across your domains.

## Main Features

* **Comprehensive DNS & Email Security Checks:** Query all key record types in one go – NS, A/AAAA, MX, TXT, SPF, DMARC, DKIM, **etc.** – including advanced records like DNSSEC, DANE (TLSA), MTA-STS, CAA, and BIMI. No need to use multiple tools for different records.
* **Interactive and Batch Modes:** Run in an interactive prompt (with history navigation) for ad-hoc investigations, or supply a list of domains to scan many domains in batch. This flexibility fits both one-off troubleshooting and routine audits.
* **Clear, Color-Coded Output:** Results use intuitive symbols (✅ pass, ❌ fail, ⚠️ warning) and colors to highlight issues and recommendations. You can immediately spot misconfigurations, missing records, or weak policies without digging through verbose data.

## Quick Start

If you do not need local CLI execution, use the web app directly (no install required): https://dnstool.it-help.tech/

### Installation

**For Linux:** Download the `dnstool-linux` binary for your architecture from the [GitHub Releases](https://github.com/careyjames/dns-tool/releases) page. Make it executable with `chmod +x`, then run it with `./dnstool`. (You can optionally move it to `/usr/local/bin` for easier use.)

**For macOS:** Download the appropriate `dnstool-macos` binary. If blocked by Gatekeeper, right-click and Open, or run `xattr -d com.apple.quarantine` on it in Terminal to bypass Apple’s security check, then execute it.

**For Windows:** Download the `dnstool-windows-amd64.exe` file and run it. If SmartScreen prompts, choose “Run anyway” (the app is safe – it’s just not code-signed yet).

For more detailed setup instructions (including building from source if needed), see the [Installation guide](installation-and-setup.md).

### Getting Started

Once installed, start with the **Interactive Mode**:

```bash
$ dnstool
```

At the prompt, type a domain (for example, `example.com`) and hit Enter. DNS Tool will print a comprehensive report of that domain’s DNS records and security settings. Look for ✅, ❌, and ⚠️ symbols indicating passes, failures, or warnings on each check.

If you have multiple domains to check, try **Batch Mode** by listing domains as arguments:

```bash
$ dnstool example.com example.org test.co
```

The tool will output results for each domain in turn. You can also supply a file of domains with `dnstool -f domains.txt` for convenience.

Continue to the [Usage & Examples](usage-and-examples.md) section for a guided tour of DNS Tool’s interactive and batch usage, including example outputs and interpretations.
