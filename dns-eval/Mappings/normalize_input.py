import json
import glob
import os
import sys

if len(sys.argv) >= 2:
    SOURCE = sys.argv[1]
else:
    files = glob.glob("Inputs/dns-intelligence-*.json")
    if not files:
        raise FileNotFoundError("Place DNS JSON into Inputs/ before running.")
    SOURCE = max(files, key=os.path.getmtime)

DEST = sys.argv[2] if len(sys.argv) >= 3 else "Mappings/normalized-from-dnstool.json"

with open(SOURCE, "r") as f:
    raw = json.load(f)

fr = raw.get("full_results", {})
domain = raw.get("domain", "unknown")

dnssec = fr.get("dnssec_analysis", {})
spf = fr.get("spf_analysis", {})
dmarc = fr.get("dmarc_analysis", {})
mail = fr.get("mail_posture", {})
tlsrpt = fr.get("tlsrpt_analysis", {})
mta_sts = fr.get("mta_sts_analysis", {})
caa = fr.get("caa_analysis", {})
dkim = fr.get("dkim_analysis", {})
dane = fr.get("dane_analysis", {})
bimi = fr.get("bimi_analysis", {})
security_txt = fr.get("security_txt", {})
dangling = fr.get("dangling_dns", {})
delegation = fr.get("delegation_consistency", {})
secret_exp = fr.get("secret_exposure", {})
https_svcb = fr.get("https_svcb", {})
cds_cdnskey = fr.get("cds_cdnskey", {})
smtp = fr.get("smtp_transport", {})
posture = fr.get("posture", {})
calibrated = fr.get("calibrated_confidence", {})

is_no_mail = fr.get("is_no_mail_domain", False) or mail.get("verdict") == "no_mail" or mail.get("is_no_mail", False)
is_mail = not is_no_mail

spf_is_softfail = spf.get("all_mechanism") == "~all"
spf_is_hardfail = spf.get("all_mechanism") == "-all"
dmarc_enforcing = dmarc.get("policy") in ("reject", "quarantine")
dmarc_reject = dmarc.get("policy") == "reject"

dnssec_ad = dnssec.get("ad_flag") is True
dnssec_chain = dnssec.get("chain_of_trust", "")
dnssec_chain_valid = dnssec_ad and dnssec_chain in ("complete", "inherited")

ns_delegation = fr.get("ns_delegation_analysis", {})
is_subdomain = ns_delegation.get("is_subdomain", False)

ns_fleet_data = fr.get("ns_fleet", {})
ns_names = [ns.get("name", "") for ns in ns_fleet_data.get("nameservers", [])] if isinstance(ns_fleet_data.get("nameservers"), list) else []
provider_hint = "route53" if any("awsdns" in n for n in ns_names) else "cloudflare" if any("cloudflare" in n for n in ns_names) else "other"

normalized = {
    "source_file": os.path.basename(SOURCE),
    "domain": domain,
    "is_mail_domain": is_mail,
    "is_no_mail_domain": is_no_mail,
    "is_subdomain": is_subdomain,
    "dns_provider_hint": provider_hint,
    "calibrated_confidence": calibrated,
    "observations": {
        "DNSSEC_VALID": dnssec.get("status") == "success" and dnssec_ad,
        "DNSSEC_CHAIN_VALID": dnssec_chain_valid,
        "DNSSEC_ROLLOVER_READY": (
            cds_cdnskey.get("has_cds", False) or
            cds_cdnskey.get("has_cdnskey", False) or
            cds_cdnskey.get("automation") == "active"
        ),
        "NULL_MX": fr.get("has_null_mx", False),
        "SPF_HARD_FAIL": spf_is_hardfail,
        "SPF_SOFTFAIL_WITH_DMARC": spf_is_softfail and dmarc_enforcing,
        "DMARC_REJECT": dmarc_reject,
        "DMARC_ENFORCING": dmarc_enforcing,
        "NO_MAIL_DOMAIN": is_no_mail,
        "MAIL_DOMAIN": is_mail,
        "TLS_RPT": tlsrpt.get("status") == "success",
        "MTA_STS_DNS": mta_sts.get("status") in ("success", "warning"),
        "CAA_PRESENT": caa.get("status") == "success" and bool(caa.get("records")),
        "DKIM_FOUND": dkim.get("status") in ("success", "warning") and dkim.get("primary_has_dkim", False),
        "DANE_PRESENT": dane.get("has_dane", False),
        "BIMI_VALID": bimi.get("status") == "success" and bimi.get("logo_valid", False),
        "SECURITY_TXT_FOUND": security_txt.get("found", False) and not security_txt.get("expired", True),
        "NO_DANGLING_DNS": dangling.get("status") == "success" and dangling.get("dangling_count", 1) == 0,
        "DELEGATION_OK": delegation.get("status") == "success",
        "NO_SECRETS_EXPOSED": secret_exp.get("status") == "clear" and secret_exp.get("finding_count", 1) == 0,
        "HTTPS_SVCB_PRESENT": https_svcb.get("has_https", False) or https_svcb.get("has_svcb", False)
    },
    "context": {
        "dnssec_chain_type": dnssec_chain,
        "spf_mechanism": spf.get("all_mechanism", ""),
        "dmarc_policy": dmarc.get("policy", ""),
        "spf_dmarc_effective": "enforced" if (spf_is_hardfail or (spf_is_softfail and dmarc_enforcing)) else "unenforced"
    }
}

with open(DEST, "w") as f:
    json.dump(normalized, f, indent=2)

print(json.dumps(normalized, indent=2))
