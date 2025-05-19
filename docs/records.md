## docs/records.md

# DNS Checks Explained

DNS Tool performs a variety of checks on different DNS records and related services. This section explains each category of checks, what they mean, and why they matter for security. Understanding the output will help you interpret DNS Tool’s findings and take the right action.

## Email Security Records: SPF, DKIM, DMARC, and BIMI

**SPF (Sender Policy Framework):** SPF is a DNS TXT record that lists which mail servers are allowed to send email on behalf of your domain. DNS Tool will look for a TXT record starting with `v=spf1`.

* *What DNS Tool checks:* It ensures there is **exactly one** SPF record and that it’s correctly formatted. If no SPF is found, you’ll see a ❌ “No SPF record” error, since the absence of SPF can cause email deliverability issues and makes it easier for attackers to spoof your domain. If multiple SPF records are found, DNS Tool will warn you (only one is allowed). A correct SPF will be displayed (✅) so you can verify its content.
* *Why it matters:* SPF helps receiving mail servers know whether an email claiming to come from your domain is being sent through an authorized server. A missing or broken SPF means receivers can’t validate your outbound emails, and spammers might forge your domain more easily.

**DKIM (DomainKeys Identified Mail):** DKIM uses a pair of cryptographic keys to sign outgoing emails. Public keys are published in DNS (typically as TXT records under a selector subdomain like `selector._domainkey.yourdomain.com`).

* *What DNS Tool checks:* It tries to find DKIM records for common selectors. By default, the tool checks selectors: `default._domainkey`, `google._domainkey`, `selector1._domainkey`, and `selector2._domainkey` (all appended to your domain). If it finds any DKIM public key records at these locations, it will mark them with ✅ and display the public key text. If no DKIM records are found among those common names, it will issue a ⚠️ warning “No DKIM found among default selectors”. (This doesn’t absolutely prove you lack DKIM – you might use a non-standard selector – but it covers the usual cases.)
* *Why it matters:* DKIM is one of the pillars of email authentication. If DKIM is not set up, your emails won’t be signed, and thus can’t be authenticated on the recipient side. DNS Tool’s DKIM check is a quick way to see if you have the expected DNS entries, especially for common providers (e.g., Google Workspace uses `google._domainkey`). If you use custom selectors, be sure to check those manually or add them to the tool’s check list.

**DMARC (Domain-based Message Authentication, Reporting, and Conformance):** DMARC ties together SPF and DKIM results and sets a policy for how recipients should treat emails that fail authentication. The DMARC record is a TXT record at `_dmarc.yourdomain.com`.

* *What DNS Tool checks:* It queries for a TXT record at `_dmarc.<domain>`. If none is found, you get a ❌ “No DMARC record” message, which is a serious gap because DMARC is critical for preventing direct domain spoofing. If a DMARC record exists, DNS Tool ensures it’s valid (starts with `v=DMARC1`). If it finds something that looks like a DMARC record but not quite right (e.g., a typo in `v=DMARC1`), it will warn you that an invalid DMARC-like record was found. Assuming a valid record is present, DNS Tool then checks the **policy** (`p=` tag) within it and reports:

  * **p=none:** This policy means “monitor only” – DNS Tool will flag this with a ⚠️ warning saying `p=none => "Your work's not done!"`. In other words, you’re only collecting reports and not protecting your domain from abuse yet.
  * **p=quarantine:** This tells receivers to treat failing emails with suspicion (usually send to spam). DNS Tool will mark this as a ✅ but note that quarantine is good, though not as strong as reject.
  * **p=reject:** This is the strongest policy, instructing receivers to outright reject emails that fail SPF/DKIM checks. DNS Tool gives a ✅ and a message like “DMARC p=reject => Great anti-spoof!”, confirming you’re at an optimal security stance.
  * Any other policy or syntax issue, the tool will simply show the DMARC record and indicate it found one, without a specific icon (or with a generic ✅ if the record is present but non-standard).
* *Why it matters:* DMARC is your domain’s last line of defense against spoofed emails. Without DMARC, anyone can send email pretending to be your domain and you’ll only know if you happen to see the abuse. With DMARC in “reject” or “quarantine”, recipients will actually block or flag those illegitimate emails. Industry best practices and regulatory bodies (like CISA) strongly recommend moving to **p=reject** as soon as you’re confident your mail streams are properly authenticated. In our blog post [*Defend Your Domain: Master DNS Security with DMARC, SPF, and DKIM*](https://www.it-help.tech/blog/defend-your-domain-master-dns-security-with-dmarc-spf-and-dkim), we outline how organizations should start with monitoring (p=none) and gradually step up to enforcement (p=quarantine, then p=reject) – DNS Tool makes it easy to verify each step of that journey.

**BIMI (Brand Indicators for Message Identification):** BIMI is an emerging standard that allows you to publish your brand’s logo in DNS so that supporting email clients can display it alongside authenticated emails from your domain. BIMI isn’t a security control per se, but it *requires* that you have a solid DMARC policy in place (usually p=reject) before you can use it, so it’s a good “bonus” indicator of strong email security posture.

* *What DNS Tool checks:* It looks for a BIMI record at `default._bimi.<domain>` (a TXT record). If found, it will show a ✅ and the record’s value (which typically includes a URL to an SVG file of your logo). If not found, it doesn’t raise a security warning (since BIMI is optional), but you simply won’t see a BIMI section in the output.
* *Why it matters:* Seeing a BIMI record in DNS Tool’s output (and thus a ✅) is an indication that the domain owner has gone the extra mile to implement BIMI, which in turn implies they’ve already deployed DMARC at enforcement. If you’re interested in BIMI, ensure you meet all the prerequisites (DMARC at reject, a VMC certificate if required, etc.). DNS Tool helps verify the DNS piece of that puzzle.

## Domain Security Records: DNSSEC, DANE, MTA-STS, and CAA

**DNSSEC (Domain Name System Security Extensions):** DNSSEC adds a layer of cryptographic verification to DNS, enabling resolvers to detect if DNS records have been tampered with. When DNSSEC is enabled for a domain, every DNS answer is digitally signed.

* *What DNS Tool checks:* It doesn’t perform a full DNSSEC validation (which requires a chain of trust), but it does check if DNSSEC signatures (RRSIG records) are present in the DNS answers for your domain. In practice, the tool queries your domain’s A record with the DNSSEC flag and sees if a signature comes back. If yes, you get a ✅ “DNSSEC signatures present” message. If no, it will report ❌ “DNSSEC not detected” (meaning either DNSSEC is not enabled, or an error occurred).
* *Why it matters:* Without DNSSEC, DNS records can be spoofed by attackers (through cache poisoning attacks, for example). DNSSEC ensures that when someone looks up your domain, they can be confident the answer hasn’t been altered. Many security frameworks and government guidelines encourage DNSSEC for domains, especially those of high value or targets of attack. If DNS Tool shows DNSSEC as not present and you own the domain, consider enabling it at your domain registrar or DNS provider – it typically involves adding a DS record in the parent zone and signing your zone.

**DANE (DNS-based Authentication of Named Entities):** DANE uses DNS (and DNSSEC) to publish TLS certificates or fingerprints (via TLSA records), most commonly to secure SMTP (email server-to-server encryption) and sometimes HTTPS. DANE can indicate which TLS certificate a service is supposed to use, preventing tampering or mis-issuance.

* *What DNS Tool checks:* It looks for **TLSA records** on two services: the SMTP service (port 25) at your domain, and HTTPS (port 443) on your domain. Concretely, it queries for `_25._tcp.<domain>` and `_443._tcp.<domain>` with record type TLSA.

  * If a TLSA record is found for SMTP, it prints a ✅ and the TLSA record data (indicating DANE is configured for email). If none, it shows ❌ “No SMTP TLSA record (port 25)”.
  * Similarly for HTTPS, a TLSA at `_443._tcp` yields a ✅ “HTTPS TLSA found” plus the record, or ❌ “No HTTPS TLSA record” if not present.
* *Why it matters:* DANE for SMTP (often in conjunction with DNSSEC) is a way to enforce TLS encryption for incoming email to your domain, preventing downgraded connections. It’s not yet widely adopted because it requires DNSSEC, but it’s powerful where implemented. DNS Tool’s check lets you know if you have DANE records and can alert you if they’re missing (if you intended to have them). If you see ❌ for DANE but haven’t set it up, it’s just informational. If you *have* set it up but see a ❌, that could indicate a configuration issue (or maybe the TLSA records aren’t where expected).

**MTA-STS (Mail Transfer Agent – Strict Transport Security):** MTA-STS is a policy that helps enforce TLS encryption for emails in transit to your domain. Unlike DANE, it doesn’t use DNS for the certificate info, but it does use DNS to advertise a policy and HTTPS to retrieve the policy.

* *What DNS Tool checks:* It performs two steps:

  1. Looks for a TXT record at `_mta-sts.<domain>`. If found, and it’s formatted (e.g., `v=STSv1; id=...`), DNS Tool prints a ✅ line showing the record’s presence. If not found, it prints ❌ “No \_mta-sts.<domain> TXT record.”.
  2. Attempts to fetch the MTA-STS policy file by making an HTTPS request to `https://mta-sts.<domain>/.well-known/mta-sts.txt`. It will report the HTTP response: a ✅ if the policy is fetched successfully (HTTP 200), or an ❌ if not (e.g., 404 Not Found, or no response). The output might look like:

     ```
     ❌ No _mta-sts.example.com TXT record.
        Checking policy file: https://mta-sts.example.com/.well-known/mta-sts.txt  
        ❌ No policy file (HTTP 404).
     ```

     or if everything is in place:

     ```
     ✅ _mta-sts.example.com TXT => "v=STSv1; id=2022051800"  
        Checking policy file: https://mta-sts.example.com/.well-known/mta-sts.txt  
        ✅ Policy file found (HTTP 200).
     ```
* *Why it matters:* MTA-STS, when configured, ensures that senders like Gmail, etc., will only deliver mail to your domain’s servers if they can do so over a trusted TLS connection. It helps prevent downgrade attacks (where a Man-in-the-Middle could force email to be sent unencrypted). If DNS Tool flags that you have no MTA-STS record or policy, consider setting it up for improved email security. If it shows an error in retrieving the policy, you’ll want to fix the hosting of the policy file.

**CAA (Certification Authority Authorization):** CAA records allow a domain owner to specify which Certificate Authorities (CAs) are allowed to issue certificates for the domain. This is a security measure to prevent unauthorized or unexpected certificate issuance.

* *What DNS Tool checks:* It queries for **CAA records** at the root of your domain.

  * If at least one CAA record exists, DNS Tool will list them under a ✅ “Found CAA” heading. Typically, a CAA record might say something like `0 issue "letsencrypt.org"` or `0 issuewild "digicert.com"`.
  * If no CAA record is found, DNS Tool doesn’t mark it as a critical failure, but it will give a ⚠️ warning: “No CAA record found. (Optional but recommended to limit cert issuers.)”.
* *Why it matters:* Although CAA is not mandatory, it’s a good practice. It ensures that if someone (including you) tries to get an SSL/TLS certificate for your domain from an unauthorized CA, that CA should refuse issuance. This can reduce the risk of mis-issuance (a malicious actor socially engineering a less-known CA to issue a certificate for your domain). If DNS Tool shows no CAA, it’s a nudge that you can improve security by adding one (specifying your CA of choice, e.g., Let’s Encrypt, DigiCert, etc.). If it shows CAA records, review them to ensure they align with your intended CAs.

## Core DNS Records: A, MX, NS, SOA, PTR, etc.

Beyond the security-focused records above, DNS Tool also checks the fundamental DNS records that every domain relies on. These often tie into security and deliverability as well.

**NS Records (Name Servers):** NS records tell the world which servers are authoritative for your domain.

* *What DNS Tool checks:* It fetches the NS records for the domain. If found, it lists them with a ✅ “Found NS”. If none are found (which would be extremely unusual for a properly configured domain), it will show ❌ “No NS records found”.
* *Why it matters:* Without NS records, your domain won’t resolve at all. DNS Tool listing them is mostly informational – you can verify that the NS are correct (e.g., match what you expect from your registrar or DNS provider). It can help catch cases where maybe a domain’s NS aren’t correctly set due to an error.

**A/AAAA Records (IPv4/IPv6 Addresses):** A records map your domain to IPv4 addresses, and AAAA records map to IPv6 addresses.

* *What DNS Tool checks:* It will perform an A lookup and an AAAA lookup on your domain.

  * For **A records**, if at least one IPv4 address is found, it prints them under ✅ “Found A”. If none, you get ❌ “No A record found”.
  * For **AAAA records**, similarly, a ✅ with the list of IPv6 addresses if present, or ❌ “No AAAA record found” if none.
* *Why it matters:* These are your basic web or service endpoints. DNS Tool showing them helps verify you didn’t forget to set an A/AAAA (for instance, if you intend your domain to have a website). No A record could mean your website is down or only accessible via a subdomain. No AAAA record is not critical (many domains still don’t have IPv6), but if you have IPv6 services you’ll want to see them listed. The tool doesn’t flag the absence of AAAA as a warning since IPv6 adoption, while recommended, isn’t strictly required yet.

**MX Records (Mail Exchange):** MX records specify where email for your domain should be delivered.

* *What DNS Tool checks:* It queries for MX records. If none are found, it’s a ❌ error with a note “(Likely why email is failing—this is big trouble!)”. If MX records exist, it lists them with ✅ and shows each entry (e.g., `10 mail.example.com`). Additionally, DNS Tool has a built-in check for a specific issue: if it sees MX records referencing `aspmx2.googlemail.com` or `aspmx3.googlemail.com`, it will warn you that you have old Google Apps MX entries. This is because Google’s legacy MX included those, but modern Google Workspace uses different server names (and the `aspmx2/3.googlemail.com` servers are deprecated). The tool will output a ⚠️ noting the presence of those and suggest updating to the current recommended Google MX setup.
* *Why it matters:* If your domain is intended to receive email, MX records are essential. No MX means many mail systems assume there’s no mail server (though technically mail can fallback to A record, in practice missing MX is a configuration error). The Google MX warning is an example of how the tool doesn’t just check existence, but also sanity: keeping outdated records could lead to missing important updates or suboptimal routing.

**TXT Records:** TXT is a generic record type for free-form text. Many frameworks (SPF, DMARC, DKIM, Google site verification, etc.) use TXT records.

* *What DNS Tool checks:* It fetches all TXT records at the root of your domain and prints them. If none, it says ❌ “No TXT records found”. If there are, you’ll see each TXT string (wrapped in quotes) listed. This will naturally include things like your SPF record and any other verification codes. DNS Tool doesn’t specifically validate every TXT usage (except SPF/DMARC which it handles separately), but this gives a quick view of any miscellaneous TXT data present.
* *Why it matters:* Seeing the raw TXT records can be useful to ensure, for example, that your SPF string is as expected (especially if you have multiple TXT records and want to ensure the SPF one is correct), or to check that other services’ verification codes are in place. If DNS Tool says no TXT and you expected some (like an SPF or DMARC), that’s a red flag to investigate.

**SOA (Start of Authority):** The SOA record contains administrative information about the domain’s DNS zone (like the primary nameserver and a contact email, as well as serial number and timers for zone transfers).

* *What DNS Tool checks:* It retrieves the SOA record for the domain. If found, ✅ “Found SOA” and it will print the SOA record line. If not found (which would be unusual unless the domain is misconfigured), it prints ❌ “No SOA record found”.
* *Why it matters:* Every zone should have an SOA. The tool prints it mostly for completeness. You might glance at the SOA to see the serial number (to confirm if a recent change propagated, as the serial should increment when a change is made) or to verify the primary NS is correct. It’s not usually a security issue unless the SOA is missing entirely (which would suggest major DNS misconfiguration).

**PTR (Reverse DNS for IPs):** A PTR record maps an IP address back to a hostname. DNS Tool approaches PTR in the context of your domain’s A records.

* *What DNS Tool checks:* After getting your domain’s A record(s), DNS Tool will attempt a reverse lookup on each IP. If your domain’s IP has a PTR record, it will print it. If not, it will give a message. There is a nuanced logic:

  * If no PTR is found and DNS Tool detects that your domain’s email is handled by Google or Microsoft (it checks if your MX or SPF mentions common Google/Microsoft indicators), it will actually **not** flag it as an error. Instead, it prints a line saying no PTR found but “domain likely on shared Google/Microsoft IP => normal” (✅). This is because, for example, if you use Google Workspace for email, your domain’s outbound IP will be a Google server that has a generic PTR (not one with your domain name), and that’s expected.
  * If no PTR is found and you’re not using those major providers, it will print a ❌ “No PTR found for <IP>”. If PTR exists, it lists them (usually there will be one PTR pointing back to some hostname).
* *Why it matters:* PTR records are mainly important for mail server IPs – many receiving mail servers do a reverse lookup on the sending IP to see if it resolves to a reasonable hostname. If you manage your own mail server, you absolutely want a PTR set (often through your ISP) that matches your mail hostname. DNS Tool helps flag if your server’s IP is lacking a PTR. If you’re on a cloud email service (like GSuite or Office 365), you generally won’t have a custom PTR (and shouldn’t try to set one on their IPs), hence the tool’s leniency in those cases. A proper PTR can improve email deliverability and is a mark of a well-configured network service.

**Registrar and WHOIS Info:** (Not a DNS record, but included for completeness.) DNS Tool fetches the domain’s registrar information via RDAP and WHOIS.

* *What DNS Tool checks:* It contacts RDAP servers to get the registrar name for the domain. If RDAP fails or doesn’t provide it, it falls back to a WHOIS query. The output will show either:

  * ✅ Registrar (RDAP): SomeRegistrarName
  * ✅ Registrar (WHOIS fallback): SomeRegistrarName
  * or a warning/error if it couldn’t find it.
* *Why it matters:* This is informational so you know who the domain is registered with. For security professionals, it’s useful context – e.g., if a domain is registered at a less reputable registrar, that might be notable, or if you expected it to be at a different one, that could indicate an issue. It’s also handy when investigating someone else’s domain (to quickly see the registrar without doing a separate WHOIS lookup).

---

Armed with this understanding of each check, you can interpret DNS Tool’s output with confidence. The tool not only checks existence but also provides guidance (through messages and symbol cues) on whether something is configured in a secure, recommended way. Use this reference to double-check any item that the tool flags, and refer back when you need a refresher on what a particular DNS record does.
