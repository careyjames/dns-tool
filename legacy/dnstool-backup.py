#!/usr/bin/env python3
"""
DNS Tool (Python Edition) + Prompt Toolkit arrow-key history
- Now using prompt_toolkit.formatted_text.ANSI for the domain prompt,
  so \033[1m etc. are correctly interpreted instead of printing ^[[1m.
"""

import os
import sys
import re
import argparse
import subprocess
from pathlib import Path
import logging

# Main dependencies
try:
    import requests
except ImportError:  # pragma: no cover - environment lacks requests
    print("Error: the 'requests' package is required.\nInstall it with 'pip install requests'.")
    sys.exit(1)

try:
    import dns.resolver
except ImportError:  # pragma: no cover - environment lacks dnspython
    print("Error: the 'dnspython' package is required.\nInstall it with 'pip install dnspython'.")
    sys.exit(1)

try:
    import idna
    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False

# Prompt Toolkit
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.formatted_text import ANSI
except ImportError:  # pragma: no cover - environment lacks prompt_toolkit
    print("Error: the 'prompt_toolkit' package is required.\nInstall it with 'pip install prompt_toolkit'.")
    sys.exit(1)

# ANSI Colors / Symbols
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
BOLD = "\033[1m"
NC = "\033[0m"

SYM_OK = "✅"
SYM_ERR = "❌"
SYM_WARN = "⚠️"

DNS_TIME = 3
DNS_TRIES = 2
RESOLVER_1 = "1.1.1.1"
RESOLVER_2 = "8.8.8.8"
RESOLVER_3 = "9.9.9.9"
DEFAULT_RESOLVERS = [RESOLVER_1, RESOLVER_2, RESOLVER_3]
RESOLVERS = DEFAULT_RESOLVERS.copy()

DOMAIN_HISTORY_FILE = os.path.expanduser("~/.domain_history_rdap_interactive")
VERBOSE = False
IANA_RDAP_MAP = {}

logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")

def shutil_which(cmd):
    """Return path to executable ``cmd`` if found on ``PATH``."""
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, cmd)
        if os.access(candidate, os.X_OK) and not os.path.isdir(candidate):
            return candidate
    return None

def domain_to_ascii(domain: str) -> str:
    """Convert Unicode domain names to ASCII using IDNA."""
    domain = domain.rstrip(".")
    if HAS_IDNA:
        try:
            return idna.encode(domain).decode("ascii")
        except idna.IDNAError:
            pass
    return domain

def validate_domain(d: str) -> bool:
    """Return ``True`` if ``d`` looks like a valid domain name."""
    pattern = r"^[A-Za-z0-9._-]+\.[A-Za-z0-9-]{2,}$"
    if not re.match(pattern, d):
        print(f"{SYM_ERR} {RED}Invalid domain:{NC} {d}")
        return False
    return True

def whois_lookup_registrar(domain: str) -> str:
    """Return registrar name using the ``whois`` command."""
    if not shutil_which("whois"):
        return ""
    try:
        out = subprocess.check_output(["whois", domain], stderr=subprocess.DEVNULL, timeout=5)
        lines = out.decode(errors="replace").splitlines()
        for ln in lines:
            if re.search(r"(?i)registrar:", ln) or re.search(r"(?i)sponsoring registrar:", ln):
                parts = ln.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return ""
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""

def fetch_iana_rdap_data():
    """Populate ``IANA_RDAP_MAP`` with TLD to RDAP endpoint mappings."""
    global IANA_RDAP_MAP
    url = "https://data.iana.org/rdap/dns.json"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        j = r.json()
        for svc in j.get("services", []):
            if len(svc) != 2:
                continue
            tlds, endpoints = svc
            if tlds and endpoints:
                for tld in tlds:
                    IANA_RDAP_MAP[tld.lower()] = endpoints
    except Exception as e:
        logging.error("Failed to fetch IANA RDAP data: %s", e)

def get_tld(domain: str) -> str:
    """Return the top-level domain from ``domain`` in lowercase."""
    return domain.rsplit(".", 1)[-1].lower()

def rdap_lookup(domain: str) -> dict:
    """Return RDAP JSON data for ``domain`` using IANA endpoints."""
    t = get_tld(domain)
    endpoints = IANA_RDAP_MAP.get(t, [])
    for ep in endpoints:
        url = f"{ep.rstrip('/')}/domain/{domain}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code < 400:
                data = resp.json()
                if "errorCode" not in data:
                    return data
        except Exception as e:
            logging.error("RDAP lookup error: %s", e)
    # fallback
    url = f"https://rdap.org/domain/{domain}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code < 400:
            data = resp.json()
            if "errorCode" not in data:
                return data
    except Exception as e:
        logging.error("RDAP fallback lookup error: %s", e)
    return {}

def dns_query(rdtype, domain):
    """Query ``domain`` for record type ``rdtype`` using several resolvers."""
    if not domain or not rdtype:
        return []
    resolvers_to_try = RESOLVERS
    final_data = []
    for r in resolvers_to_try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [r]
        resolver.timeout = DNS_TIME
        resolver.lifetime = DNS_TIME * DNS_TRIES
        try:
            ans = resolver.resolve(domain, rdtype)
            out = [str(rr) for rr in ans]
            if out:
                final_data = out
                break
        except Exception as e:
            logging.error("DNS query error: %s", e)
    return final_data

def get_registrar(domain: str):
    """Print registrar information obtained via RDAP or WHOIS."""
    print(f"\n{BLUE}🔍 Registrar & RDAP Info:{NC}")
    rdap_data = rdap_lookup(domain)
    if not rdap_data:
        print(f"{SYM_WARN} No RDAP data. Checking WHOIS...")
        w = whois_lookup_registrar(domain)
        if w:
            print(f"{SYM_OK} Registrar (WHOIS fallback): {GREEN}{w}{NC}")
        else:
            print(f"{SYM_ERR} {RED}No registrar found (RDAP/WHOIS both empty).{NC}")
        return

    registrar_name = ""
    entities = rdap_data.get("entities", [])
    for ent in entities:
        roles = ent.get("roles", [])
        if roles and "registrar" in [r.lower() for r in roles]:
            vcard = ent.get("vcardArray", [])
            if len(vcard) == 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if len(item) == 4 and item[0] == "fn":
                        registrar_name = item[3]
                        break
            if not registrar_name:
                registrar_name = ent.get("handle") or ent.get("name") or ""
            if registrar_name:
                break
    if not registrar_name:
        print(f"{SYM_WARN} Registrar not found in RDAP. Checking WHOIS...")
        fb = whois_lookup_registrar(domain)
        if fb:
            print(f"{SYM_OK} Registrar (WHOIS fallback): {GREEN}{fb}{NC}")
        else:
            print(f"{SYM_ERR} {RED}No registrar found in RDAP or WHOIS.{NC}")
    else:
        if registrar_name.isdigit():
            fw = whois_lookup_registrar(domain)
            if fw:
                print(f"{SYM_OK} Registrar (WHOIS fallback): {GREEN}{fw}{NC}")
            else:
                print(f"{SYM_OK} Registrar (RDAP handle): {YELLOW}{registrar_name}{NC}")
        else:
            print(f"{SYM_OK} Registrar (RDAP): {GREEN}{registrar_name}{NC}")

def get_spf_record(domain: str):
    """Display the SPF record for ``domain`` if present."""
    print(f"\n{BLUE}🔍 SPF (Sender Policy Framework):{NC}")
    all_txt = dns_query("TXT", domain)
    if not all_txt:
        print(f"{SYM_ERR} No TXT => no SPF record! ({SYM_ERR} Required for mail deliverability and DMARC compliance.)")
        return

    valid_spf_lines = []
    spfish_lines = []
    for txtline in all_txt:
        low = txtline.lower()
        if "v=spf1" in low:
            valid_spf_lines.append(txtline)
        elif "spf" in low:
            spfish_lines.append(txtline)

    count_valid = len(valid_spf_lines)
    if count_valid == 0:
        if spfish_lines:
            print(f"{SYM_WARN} Found {len(spfish_lines)} 'spf-like' line(s) that are not valid. {SYM_ERR} Required for mail deliverability and DMARC compliance.:\n")
            for s in spfish_lines:
                print(f"   \"{s}\"")
            print(f"{SYM_ERR} No valid SPF record. (These appear incorrect.) {SYM_ERR} Required for mail deliverability and DMARC compliance.")
        else:
            print(f"{SYM_ERR} No SPF record found. ({SYM_ERR} Required for mail deliverability and DMARC compliance.)")
    elif count_valid == 1:
        print(f"{SYM_OK} SPF found => \"Good, there is only one!\"")
        print(valid_spf_lines[0])
    else:
        print(f"{SYM_WARN} Multiple valid SPF lines => \"There can be only one!\"\n")
        for s in valid_spf_lines:
            print(f"   {s}")

def get_dmarc_record(domain: str):
    """Display the DMARC policy for ``domain``."""
    print(f"\n{BLUE}🔍 DMARC:{NC}")
    recs = dns_query("TXT", f"_dmarc.{domain}")
    if not recs:
        print(f"{SYM_ERR} No DMARC record found. (Helps prevent spoofing. Required for mail deliverability.)")
        return

    valid_dmarc_lines = []
    dmarc_like = []
    for line in recs:
        low = line.lower()
        if "v=dmarc1" in low:
            valid_dmarc_lines.append(line)
        elif "dmarc" in low:
            dmarc_like.append(line)
    count_valid = len(valid_dmarc_lines)
    if count_valid == 0:
        if dmarc_like:
            print(f"{SYM_WARN} Found DMARC-like lines, but not 'v=DMARC1':\n")
            for x in dmarc_like:
                print(f"   \"{x}\"")
            print(f"{SYM_ERR} No valid DMARC record (these appear incorrect). {SYM_ERR} Required for mail deliverability and DMARC compliance.")
        else:
            print(f"{SYM_ERR} No valid DMARC record found. (Required for mail deliverability.)")
    elif count_valid > 1:
        print(f"{SYM_WARN} Multiple DMARC lines => \"There can be only one!\"\n")
        for x in valid_dmarc_lines:
            print(f"   {x}")
    else:
        line = valid_dmarc_lines[0]
        lowered = line.lower()
        if "p=none" in lowered:
            print(f"{SYM_WARN} DMARC p=none => \"Your work’s not done!\"")
            print(line)
        elif "p=reject" in lowered:
            print(f"{SYM_OK} DMARC p=reject => Great anti-spoof!")
            print(line)
        elif "p=quarantine" in lowered:
            print(f"{SYM_OK} DMARC p=quarantine => Not as strong as reject, but still good!")
            print(line)
        else:
            print(f"{SYM_OK} DMARC record found (p=?).")
            print(line)

def get_dkim_record(domain: str):
    """Check common DKIM selectors for ``domain``."""
    print(f"\n{BLUE}🔍 DKIM (common selectors):{NC}")
    sels = ["default._domainkey", "google._domainkey", "selector1._domainkey", "selector2._domainkey"]
    found_any = False
    for s in sels:
        recs = dns_query("TXT", f"{s}.{domain}")
        if recs:
            print(f"   {SYM_OK} DKIM at {s}")
            for rr in recs:
                print(f"   {rr}")
            found_any = True
    if not found_any:
        print(f"{SYM_WARN} No DKIM found among default selectors.")

def get_dane_records(domain: str):
    """Display DANE TLSA records for SMTP and HTTPS."""
    print(f"\n{BLUE}🔍 DANE (TLSA):{NC}")
    s25 = dns_query("TLSA", f"_25._tcp.{domain}")
    if s25:
        print(f"{SYM_OK} SMTP TLSA found:")
        for rr in s25:
            print(rr)
    else:
        print(f"{SYM_ERR} No SMTP TLSA record (port 25).")
    s443 = dns_query("TLSA", f"_443._tcp.{domain}")
    if s443:
        print(f"{SYM_OK} HTTPS TLSA found:")
        for rr in s443:
            print(rr)
    else:
        print(f"{SYM_ERR} No HTTPS TLSA record (port 443).")

def get_bimi_record(domain: str):
    """Show BIMI TXT records for ``domain``."""
    print(f"\n{BLUE}🔍 BIMI:{NC}")
    recs = dns_query("TXT", f"default._bimi.{domain}")
    if recs:
        print(f"{SYM_OK} BIMI found:")
        for rr in recs:
            print(rr)
    else:
        print(f"{SYM_ERR} No default._bimi record.")

def get_mta_sts(domain: str):
    """Check MTA-STS TXT record and policy file."""
    print(f"\n{BLUE}🔍 MTA-STS:{NC}")
    txt = dns_query("TXT", f"_mta-sts.{domain}")
    if txt:
        print(f"{SYM_OK} _mta-sts.{domain} TXT => \"{txt[0]}\"")
    else:
        print(f"{SYM_ERR} No _mta-sts.{domain} TXT record.")
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    print(f"   Checking policy file: {url}")
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"   {SYM_OK} Policy file found (HTTP 200).")
        else:
            print(f"   {SYM_ERR} No policy file (HTTP {r.status_code}).")
    except Exception as e:
        logging.error("MTA-STS policy fetch error: %s", e)
        print(f"   {SYM_ERR} No policy file (HTTP 000).")

def get_dnssec_status(domain: str):
    """Check whether DNSSEC signatures are present."""
    print(f"\n{BLUE}🔍 DNSSEC:{NC}")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVERS[0]]
    resolver.use_edns(0, dns.flags.DO, 1232)
    resolver.timeout = DNS_TIME
    resolver.lifetime = DNS_TIME * DNS_TRIES
    try:
        ans = resolver.resolve(domain, "A", raise_on_no_answer=False)
        if ans.response and any(rr.rdtype == dns.rdatatype.RRSIG for rr in ans.response.answer):
            print(f"{SYM_OK} DNSSEC signatures present (RRSIG).")
        else:
            print(f"{SYM_ERR} DNSSEC not detected or not validated.")
    except Exception as e:
        logging.error("DNSSEC check error: %s", e)
        print(f"{SYM_ERR} DNSSEC not detected or no A record to check.")

def get_ns_records(domain: str):
    """Display NS records for ``domain``."""
    print(f"\n{BLUE}🔍 NS Records:{NC}")
    recs = dns_query("NS", domain)
    if recs:
        print(f"{SYM_OK} Found NS:")
        for rr in recs:
            print(rr)
    else:
        print(f"{SYM_ERR} No NS records found.")

def get_mx_records(domain: str):
    """Show MX records and flag deprecated Google lines."""
    print(f"\n{BLUE}🔍 MX Records:{NC}")
    mx_out = dns_query("MX", domain)
    if not mx_out:
        print(f"{SYM_ERR} No MX records found.\n{RED}(Likely why email is failing—this is big trouble!){NC}")
        return
    print(f"{SYM_OK} Found MX:")
    for line in mx_out:
        print(f"   {line}")
    uses_aspmx2 = any("aspmx2.googlemail.com" in x.lower() for x in mx_out)
    uses_aspmx3 = any("aspmx3.googlemail.com" in x.lower() for x in mx_out)
    if uses_aspmx2 or uses_aspmx3:
        print(f"{SYM_WARN} We see older Google MX lines (aspmx2/aspmx3).")
        print("   Google’s newer recommended config typically does not need them.")
        print("   For Google Workspace, recommended lines are more like smtp.google.com / altX.")

def get_txt_records(domain: str):
    """Print all TXT records for ``domain``."""
    print(f"\n{BLUE}🔍 TXT Records:{NC}")
    out = dns_query("TXT", domain)
    if not out:
        print(f"{SYM_ERR} No TXT records found.")
    else:
        print(f"{SYM_OK} Found TXT:")
        for rr in out:
            print(f"\"{rr}\"")

def get_a_record(domain: str):
    """Display the A record (IPv4) for ``domain``."""
    print(f"\n{BLUE}🔍 A (IPv4) Record:{NC}")
    a = dns_query("A", domain)
    if not a:
        print(f"{SYM_ERR} No A record found.")
    else:
        print(f"{SYM_OK} Found A:")
        for rr in a:
            print(rr)

def get_aaaa_record(domain: str):
    """Display the AAAA record (IPv6) for ``domain``."""
    print(f"\n{BLUE}🔍 AAAA (IPv6) Record:{NC}")
    out = dns_query("AAAA", domain)
    if not out:
        print(f"{SYM_ERR} No AAAA record found.")
    else:
        print(f"{SYM_OK} Found AAAA:")
        for rr in out:
            print(rr)

def get_caa_record(domain: str):
    """Display CAA records if they exist."""
    print(f"\n{BLUE}🔍 CAA (Certificate Authority Authorization):{NC}")
    out = dns_query("CAA", domain)
    if not out:
        print(f"{SYM_WARN} No CAA record found. (Optional but recommended to limit cert issuers.)")
    else:
        print(f"{SYM_OK} Found CAA:")
        for rr in out:
            print(rr)

def get_soa_record(domain: str):
    """Show the SOA record for ``domain``."""
    print(f"\n{BLUE}🔍 SOA (Start of Authority):{NC}")
    recs = dns_query("SOA", domain)
    if recs:
        print(f"{SYM_OK} Found SOA:")
        for rr in recs:
            print(rr)
    else:
        print(f"{SYM_ERR} No SOA record found.")

def ptr_lookup(ip: str) -> list:
    """Return PTR records for an IPv4 or IPv6 address."""
    try:
        rev_name = dns.reversename.from_address(ip)
    except Exception as e:
        logging.error("PTR lookup prepare error: %s", e)
        return []
    resolvers_to_try = RESOLVERS
    for r in resolvers_to_try:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [r]
        res.timeout = DNS_TIME
        res.lifetime = DNS_TIME * DNS_TRIES
        try:
            ans = res.resolve(rev_name, "PTR")
            return [str(rr).rstrip(".") for rr in ans]
        except Exception as e:
            logging.error("PTR lookup error with resolver %s: %s", r, e)
            pass
    return []

def get_ptr_record(domain: str):
    """Resolve PTR records for all A records of ``domain``."""
    a_recs = dns_query("A", domain)
    if not a_recs:
        print(f"\n{RED}No A record => no PTR check.{NC}")
        return
    mx_lc = [x.lower() for x in dns_query("MX", domain)]
    txt_lc = [x.lower() for x in dns_query("TXT", domain)]
    uses_google = any("google" in x for x in mx_lc) or any("_spf.google.com" in x for x in txt_lc)
    uses_ms = any("outlook" in x or "microsoft" in x for x in mx_lc) or \
              any("spf.protection.outlook.com" in x for x in txt_lc)

    for ip in a_recs:
        print(f"\n{BLUE}🔍 PTR for {ip}:{NC}")
        ptrs = ptr_lookup(ip)
        if ptrs:
            for p in ptrs:
                print(p)
        else:
            if uses_google or uses_ms:
                vendor = "Google" if uses_google else "Microsoft"
                print(f"{SYM_OK} No PTR found, but domain likely on shared {vendor} IP => normal.")
            else:
                print(f"{SYM_ERR} No PTR found for {ip}.")

def run_all_checks(domain: str):
    """Run all DNS and RDAP checks for ``domain``."""
    ascii_domain = domain_to_ascii(domain)
    if not validate_domain(ascii_domain):
        return

    print(f"\n{BLUE}{'='*42}{NC}")
    print(f"{BLUE}🔍 DNS / RDAP checks for:{NC} {YELLOW}{ascii_domain}{NC}")
    print(f"{BLUE}{'='*42}{NC}")

    get_registrar(ascii_domain)
    get_ns_records(ascii_domain)
    get_mx_records(ascii_domain)
    get_txt_records(ascii_domain)
    get_dmarc_record(ascii_domain)
    get_spf_record(ascii_domain)
    get_dkim_record(ascii_domain)
    get_mta_sts(ascii_domain)
    get_dane_records(ascii_domain)
    get_bimi_record(ascii_domain)
    get_dnssec_status(ascii_domain)
    get_a_record(ascii_domain)
    get_aaaa_record(ascii_domain)
    get_caa_record(ascii_domain)
    get_soa_record(ascii_domain)
    get_ptr_record(ascii_domain)

    print(f"\n{GREEN}✅ Done with {ascii_domain}.{NC}")

def load_domain_history():
    """Return a list of previously used domains from history file."""
    if not os.path.isfile(DOMAIN_HISTORY_FILE):
        return []
    lines = []
    with open(DOMAIN_HISTORY_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and line not in lines:
                lines.append(line)
    return lines

def append_domain_history(domain: str):
    """Append ``domain`` to the domain history file."""
    with open(DOMAIN_HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(domain + "\n")

def main():
    """Entry point for the command-line interface."""
    global VERBOSE, RESOLVERS
    parser = argparse.ArgumentParser(
        description="DNS Tool (Python Edition) + Prompt Toolkit arrow-key history, with ANSI prompt fix."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose/debug output")
    parser.add_argument("-f", "--file", type=str, help="Read domains from file")
    parser.add_argument("-r", "--resolver", action="append", help="Specify resolver IP (can be repeated)")
    parser.add_argument("domains", nargs="*", help="Domains to check")
    args = parser.parse_args()

    log_level = logging.ERROR if args.verbose else logging.CRITICAL
    logging.getLogger().setLevel(log_level)

    VERBOSE = args.verbose
    if args.resolver:
        RESOLVERS = args.resolver
    fetch_iana_rdap_data()

    domain_list = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{RED}File not found:{NC} {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    domain_list.append(line)

    if args.domains:
        domain_list.extend(args.domains)

    if domain_list:
        # batch mode
        for dm in domain_list:
            run_all_checks(dm)
        sys.exit(0)

    # Interactive mode with prompt_toolkit, using ANSI to parse color codes
    print(f"{YELLOW}Interactive Mode. Type a domain and press Enter to run checks immediately.{NC}")
    print(f"{YELLOW}Type 'exit' or press Enter on a blank line to quit.{NC}")

    Path(DOMAIN_HISTORY_FILE).touch(exist_ok=True)

    session = PromptSession(history=FileHistory(DOMAIN_HISTORY_FILE))

    while True:
        try:
            # Use ANSI(...) so prompt_toolkit parses the ANSI escapes
            dom = session.prompt(ANSI(f"\n{BOLD}Domain:{NC} ")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting DNS Tool...")
            break
        if not dom or dom.lower() == "exit":
            print("Exiting DNS Tool...")
            break
        run_all_checks(dom)
        append_domain_history(dom)

if __name__ == "__main__":
    main()