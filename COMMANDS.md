# Verification Commands & One-Liners — Master Reference

> **Last updated**: 2026-02-22
> **Purpose**: Master database of all terminal one-liners generated for users,
> organized by section, with RFC references and expected output patterns.

---

## Command Architecture

Every domain analysis generates a set of RFC-cited verification commands that
users can run independently in their own terminal. This embodies the product
philosophy: **every claim is independently verifiable**.

Commands are generated dynamically in `go-server/internal/analyzer/commands.go`
via `GenerateVerificationCommands(domain, results)`. Each command includes:
- **Section**: Logical grouping (DNS Records, Email Authentication, etc.)
- **Description**: Human-readable explanation
- **Command**: Copy-paste terminal one-liner
- **RFC**: Standards reference

---

## Command Sections

### DNS Records (RFC 1035)
```bash
dig +noall +answer example.com A        # IPv4 addresses
dig +noall +answer example.com AAAA     # IPv6 addresses
dig +noall +answer example.com MX       # Mail servers
dig +noall +answer example.com NS       # Nameservers
dig +noall +answer example.com TXT      # TXT records
dig +noall +answer example.com HTTPS    # HTTPS/SVCB records (RFC 9460)
```

### Email Authentication
```bash
# SPF (RFC 7208)
dig +short example.com TXT | grep -i spf

# DMARC (RFC 7489)
dig +short _dmarc.example.com TXT

# DKIM (RFC 6376) — one per discovered selector
dig +short google._domainkey.example.com TXT
dig +short default._domainkey.example.com TXT
dig +short selector1._domainkey.example.com TXT

# External DMARC report authorization (RFC 7489 §7.1)
dig +short source.com._report._dmarc.target.com TXT
```

### Transport Security
```bash
# MTA-STS (RFC 8461)
dig +short _mta-sts.example.com TXT
curl -sL https://mta-sts.example.com/.well-known/mta-sts.txt

# TLS-RPT (RFC 8460)
dig +short _smtp._tls.example.com TXT

# DANE/TLSA (RFC 7672)
dig +noall +answer _25._tcp.mail.example.com TLSA

# STARTTLS verification (RFC 3207)
openssl s_client -starttls smtp -connect mail.example.com:25 \
  -servername mail.example.com </dev/null 2>/dev/null | head -5

# TLS certificate chain
openssl s_client -starttls smtp -connect mail.example.com:25 \
  -servername mail.example.com 2>/dev/null | openssl x509 -noout -subject -dates
```

### Domain Security
```bash
# DNSSEC (RFC 4035)
dig +dnssec +noall +answer example.com DNSKEY
dig +noall +answer example.com DS
dig +dnssec +cd example.com A @1.1.1.1   # Chain validation

# CDS/CDNSKEY automation (RFC 7344)
dig +noall +answer example.com CDS
```

### Brand & Trust
```bash
# BIMI (BIMI Draft)
dig +short default._bimi.example.com TXT

# CAA (RFC 8659)
dig +noall +answer example.com CAA
```

### Infrastructure Intelligence
```bash
# RDAP registration (RFC 9083)
curl -sL 'https://rdap.org/domain/example.com' | python3 -m json.tool | head -50

# Certificate Transparency (RFC 6962)
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | \
  python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
  sort -u | head -20

# ASN lookup via Team Cymru
dig +short 34.216.184.93.origin.asn.cymru.com TXT

# security.txt (RFC 9116)
curl -sL https://example.com/.well-known/security.txt | head -20
```

### AI Surface
```bash
# llms.txt presence
curl -sI https://example.com/llms.txt | head -5

# robots.txt AI crawler rules
curl -s https://example.com/robots.txt | \
  grep -i -E 'GPTBot|ChatGPT|Claude|Anthropic|Google-Extended|CCBot|PerplexityBot'
```

---

## Nmap DNS Security Commands (NEW)

These are executed automatically during analysis (not displayed as user commands):

```bash
# Zone transfer test (intrusive but standard audit)
nmap -sn -Pn -p 53 --script dns-zone-transfer \
  --script-args dns-zone-transfer.domain=example.com ns1.example.com

# Open recursion check (safe)
nmap -sn -Pn -p 53 --script dns-recursion ns1.example.com

# Nameserver identity disclosure (safe)
nmap -sn -Pn -p 53 --script dns-nsid ns1.example.com

# Cache snooping (nonrecursive mode — safe)
nmap -sn -Pn -p 53 --script dns-cache-snoop ns1.example.com
```

---

## Special Features

### SHA-3-512 Report Integrity Hash
Every analysis report is cryptographically sealed with a SHA-3-512 hash
(`X-SHA3-512` header). Users can verify report integrity independently.

### Covert Mode
Toggle via navbar icon. Switches UI to red-team/adversarial perspective:
- Normal: "Running Multi-Source Intelligence Audit"
- Covert: "Initiating Recon Sweep"
- ASCII art hero switches to alternate block-character rendering
- Phase descriptions change to adversarial language

### ASCII Art Hero
Homepage features Unicode block-character art "DNS" title on desktop
(768px+) with automatic text fallback on mobile.

---

## Testing One-Liners

All generated commands can be tested by running a domain analysis and
verifying the `VerifyCommand` output in the Go test suite:

```bash
go test ./go-server/internal/analyzer/ -run TestGenerate -v -count=1
```

Test coverage for commands: `commands_test.go` (287 lines, 22+ test cases).
