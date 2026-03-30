# ITHLPSDCA Vulnerability Assessment Response

**Application:** DNS Tool (dnstool.it-help.tech)
**Assessment Date:** February 18, 2026
**Scan Engine:** Qualys Web Application Scanner (WAS)
**Response Version:** 26.20.62

---

## Summary

Of the six (6) findings reported against dnstool.it-help.tech, three (3) have been remediated and three (3) are reported as false positives with supporting technical evidence below.

### Remediated Findings

| VULN_ID | QID | Finding | Severity | Status |
|---------|-----|---------|----------|--------|
| 40369922 | 150112 | Autocomplete not disabled (index) | 2 | **Fixed in v26.20.62** |
| 40369924 | 150112 | Autocomplete not disabled (investigate) | 2 | **Fixed in v26.20.62** |
| 40369926 | 150112 | Autocomplete not disabled (results) | 2 | **Fixed in v26.20.62** |

All three autocomplete findings have been remediated by setting `autocomplete="off"` on the SecurityTrails API Key and IPinfo.io Access Token input fields across all three pages. These are user-supplied API keys (not login credentials), and the change does not impact password manager functionality — 1Password, LastPass, and Bitwarden operate via browser extension DOM injection independent of the HTML `autocomplete` attribute (ref: 1Password Developer Documentation, "Compatible Website Design").

---

## False Positive Report

### 1. QID 150122 — Cookie Does Not Contain the "Secure" Attribute (VULN_ID 40369932)

**Classification: False Positive — Infrastructure Cookie, Not Application Cookie**

**Evidence from scan payload response:**

The scan captured the following `Set-Cookie` headers in the HTTP response:

```
set-cookie: _csrf=...; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict
GAESA=...; expires=Fri 20-Mar-2026 04:02:25 GMT; path=/
```

**Analysis:**

1. **Our application cookie (`_csrf`) correctly includes both `Secure` and `HttpOnly` attributes**, as well as `SameSite=Strict`. This can be verified in the scan's own payload response above.

2. The cookie triggering this finding is **`GAESA`** — a Google App Engine session affinity cookie set by **Google Frontend** (the `server: Google Frontend` response header confirms this). This cookie is injected by Google Cloud Run's serving infrastructure, not by our application code.

3. The `GAESA` cookie is a load-balancer persistence token used for request routing. It does not contain authentication data, session state, or any user-identifiable information. Per Qualys's own guidance on QID 150122, non-sensitive infrastructure cookies on HTTPS-only applications are recognized false positives (ref: Qualys Support Article on QID 150122, "cookies that hold non-critical data pose minimal risk").

4. Our application enforces HTTPS via `Strict-Transport-Security: max-age=63072000; includeSubDomains` and `upgrade-insecure-requests` in the Content-Security-Policy header. No HTTP listener exists.

5. All six (6) cookie-setting code paths in our application set both `Secure: true` and `HttpOnly: true`:
   - CSRF token cookie (middleware/csrf.go)
   - Rate limiter flash message cookie (middleware/ratelimit.go, 2 instances)
   - OAuth state cookie (handlers/auth.go)
   - PKCE code verifier cookie (handlers/auth.go)
   - Session cookie (handlers/auth.go)

**Recommendation:** Mark QID 150122 as false positive. The flagged cookie (`GAESA`) is a Google Cloud infrastructure cookie outside application control. Our application cookies are fully compliant.

---

### 2. QID 150123 — Cookie Does Not Contain the "HTTPOnly" Attribute (VULN_ID 40369930)

**Classification: False Positive — Same Infrastructure Cookie as Above**

**Evidence:** Identical to QID 150122 above. The scan's own payload response shows our `_csrf` cookie includes `HttpOnly`, while the `GAESA` cookie (Google Frontend infrastructure) does not.

**Analysis:** Same root cause as QID 150122. The `GAESA` cookie is set by Google's serving infrastructure. All application cookies include the `HttpOnly` attribute.

**Recommendation:** Mark QID 150123 as false positive.

---

### 3. QID 150258 — Out-of-Band Vulnerability Detected via External DNS (VULN_ID 40369928)

**Classification: False Positive — Expected Application Behavior (DNS Analysis Tool)**

**Evidence from scan request:**

```
GET https://dnstool.it-help.tech/analyze?domain=1f555aa82d61c7ca162bd8e9e785b58b4d3bb082
    .235145941075871703.103661431.ssrf02.ssrf.us3.qualysperiscope.com.
```

**Analysis:**

1. DNS Tool is a **domain security analysis platform**. Its core function is to perform DNS lookups on user-supplied domain names. The `/analyze?domain=` endpoint accepts a domain name and performs comprehensive DNS resolution (A, AAAA, MX, TXT, NS, SOA, CAA, DMARC, SPF, DKIM, TLSA, HTTPS records) as its primary and intended function.

2. Qualys Periscope injected a `qualysperiscope.com` subdomain into the `domain=` parameter. Our application performed a DNS lookup on that domain — **because that is exactly what the application is designed to do**. This is expected behavior, not a vulnerability.

3. This is **not SSRF** (CWE-918). The application does not make HTTP requests to user-supplied URLs. It performs DNS resolution only, using the system's recursive DNS resolver. DNS resolution is a read-only, non-destructive operation that cannot be used to access internal services, exfiltrate data, or pivot to internal networks.

4. The application validates domain input and restricts it to valid domain name characters. It does not permit IP addresses, port specifications, URL schemes, or path components in the domain parameter.

5. Per Qualys's own documentation on Periscope (ref: "Introducing Periscope: Out-of-Band Vulnerability Detection Mechanism in Qualys WAS," January 2020): "The DNS request reaching Periscope may NOT originate from your target application server" and non-CVE QIDs "may be false positives due to intermediary systems." In our case, the DNS query is expected behavior from the application itself, as DNS lookup is its core function.

6. **Severity context:** The finding was assessed at CVSS 2.6 (Low) by Qualys itself, reflecting the minimal risk profile.

**Recommendation:** Mark QID 150258 as false positive. DNS Tool is a DNS analysis application; performing DNS lookups on user-supplied domain names is its documented, intended, and sole purpose.

---

## Compliance Summary

| Finding | QID | Status | Action |
|---------|-----|--------|--------|
| Autocomplete (index) | 150112 | **Remediated** | Fixed in v26.20.62 |
| Autocomplete (investigate) | 150112 | **Remediated** | Fixed in v26.20.62 |
| Autocomplete (results) | 150112 | **Remediated** | Fixed in v26.20.62 |
| Cookie missing Secure | 150122 | **False Positive** | Infrastructure cookie (GAESA), not application |
| Cookie missing HTTPOnly | 150123 | **False Positive** | Infrastructure cookie (GAESA), not application |
| Out-of-band DNS | 150258 | **False Positive** | Expected behavior — DNS analysis is core function |

**Total findings:** 6
**Remediated:** 3
**False positives:** 3
**Open vulnerabilities:** 0

---

## References

1. Qualys Blog, "Detecting Insecure Cookies with Qualys Web Application Scanning," January 2019
2. Qualys Blog, "Introducing Periscope: Out-of-Band Vulnerability Detection Mechanism in Qualys WAS," January 2020
3. Qualys Blog, "Identify Server-Side Attacks Using Qualys Periscope," December 2022
4. 1Password Developer Documentation, "Design Your Website to Work Best with 1Password"
5. RFC 6265, "HTTP State Management Mechanism" (Cookie Security)
6. CWE-918, "Server-Side Request Forgery (SSRF)" — inapplicable; DNS resolution is not HTTP request forwarding
7. Google Cloud Run Documentation, "GAESA Cookie" — infrastructure session affinity token
