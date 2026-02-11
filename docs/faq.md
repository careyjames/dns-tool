## docs/faq.md

# FAQ

> **Legacy CLI FAQ**
>
> This FAQ applies to the command-line release line.
>
> For the current primary DNS Tool platform, use: https://dnstool.it-help.tech/

Below are answers to some frequently asked questions about DNS Tool, covering usage, capabilities, and common scenarios.

**Q: Is this repository still the primary DNS Tool product?**
**A:** No. The web app at https://dnstool.it-help.tech/ is the primary and actively developed version. This repository remains available for CLI users who need local or script-based workflows.

**Q: What do the symbols ✅, ❌, and ⚠️ mean in the output?**
**A:** These symbols provide a quick assessment of each check’s result:

* **✅ (Green check)** – The check passed or the record is present as expected. Everything is good or within best practices for that item.
* **❌ (Red X)** – The check failed or found a critical issue. A required record might be missing, invalid, or misconfigured. This needs attention.
* **⚠️ (Yellow warning)** – The check didn’t fail outright, but something is suboptimal or worthy of caution. For example, a DMARC record with `p=none` will trigger a ⚠️ because it’s only monitoring, not protecting. Warnings often indicate an opportunity to improve security settings.
  These symbols, combined with the colored text, let you scan the output quickly. For instance, you might ignore all the ✅ entries and focus on any ❌ or ⚠️ lines first. In the example below, the SPF is missing (❌) and DMARC is present but not enforcing (⚠️):

```
✅ NS: OK – 2 name servers  
❌ SPF: Missing – No SPF record found  
⚠️ DMARC: Policy p=none – Not enforcing  
✅ DKIM: Found – default._domainkey has a key  
...
```

By addressing the ❌ and ⚠️ items (adding an SPF record, moving DMARC to an enforcement policy), you turn them into ✅ on the next run.

**Q: Can I check multiple domains at once with DNS Tool?**
**A:** Yes. There are two ways:

* **Command-line arguments:** You can list several domains after the command. For example: `dnstool domain1.com domain2.com domain3.com`. DNS Tool will process each in sequence. This is handy for quick checks of a few domains.
* **File input:** For larger lists, use the `-f` option with a file that contains one domain per line. For example, `dnstool -f mydomains.txt`. This lets you run through dozens or hundreds of domains without typing them all in one command.
  There isn’t an arbitrary limit built into the tool for number of domains, but practical constraints (time and output length) apply. The tool will print a separator and the domain name before each domain’s results so you can distinguish them in the output. If you have a very large list, consider running in batches or using multiple terminals to parallelize, and maybe redirect output to a file for review.

**Q: Does DNS Tool support using custom DNS servers (resolvers)?**
**A:** Absolutely. By default, DNS Tool uses a few public resolvers (Cloudflare, Google, Quad9) in rotation. If you want it to query a specific DNS server (for instance, your internal DNS or another preferred resolver), use the `--resolver <IP>` flag. You can even specify `--resolver` multiple times to give a list of servers. The tool will then use those instead of the defaults. For example:

```
dnstool --resolver 192.168.10.1 --resolver 192.168.10.2 example.com
```

would query the two listed servers for all DNS lookups. This is useful if, say, you have internal DNS zones not visible to public resolvers, or if you want to test how a particular DNS service (like a filtering DNS) is seeing your records. If you don’t specify `--resolver`, the built-in defaults are used. There’s currently no flag to directly use the system’s `/etc/resolv.conf` settings, so using `--resolver` is the way to point to any DNS server of your choice.

**Q: How does DNS Tool handle new or changed DNS records?**
**A:** If you’ve just added or changed a DNS record and run DNS Tool, you might wonder if it’s getting fresh data or cached results. By default, DNS Tool queries the public resolvers which may return cached data until the record’s TTL expires. If you want to ensure you’re seeing the *new* data immediately, run DNS Tool with the `--authoritative` flag. Authoritative mode bypasses caches and asks the domain’s own nameservers directly. This is the best way to check recent changes. Keep in mind propagation: if you changed a record but your registrar or DNS provider hasn’t fully pushed it out (or if you changed NS delegation), authoritative queries will show the truth at the source. For most typical record updates, using `--authoritative` will show you the latest state without waiting for TTL. Without `-a`, you might see the old value until the cache expires.

**Q: My domain’s email is hosted by Google/Microsoft. Why do I see a PTR warning?**
**A:** DNS Tool’s PTR check will warn if an IP has no reverse DNS (PTR) record *and* it appears to be a custom mail server. However, if it detects you’re using Google or Microsoft for email (through hints in your MX or SPF records), it understands that the sending IPs are shared infrastructure and might not have a PTR specific to your domain. In those cases, it will actually note that it’s “normal” to not have a PTR for those shared IPs. If you do see a PTR ❌ for a Google/Microsoft setup, double-check your SPF includes the right servers and that the warning isn’t about something else. If you run your own mail server and see a PTR error, that’s something to fix (by asking your ISP or cloud provider to set up reverse DNS for your IP). Reverse DNS matching your domain isn’t strictly required, but many mail systems treat its absence as a spam signal.

**Q: Will DNS Tool tell me if my DNS records are configured correctly for deliverability and security?**
**A:** Yes – that’s its core purpose. It won’t just list records; it evaluates them against best practices:

* It will warn you if SPF is missing or if you have multiple SPF records (which is invalid).
* It will alert if DMARC is missing or not at a strong policy.
* It highlights if your MX setup might be problematic (no MX, or deprecated Google MX entries).
* It notes optional improvements like DNSSEC not enabled, no CAA record, etc., as warnings.
  In other words, a “clean” output (all ✅ and no ❌/⚠️) means your domain’s DNS is in great shape by current standards. If there are warnings, consider them recommendations for hardening your domain (for example, moving DMARC from none to reject, adding DNSSEC, etc.). The tool incorporates guidance from industry best practices - for instance, [our DMARC/SPF/DKIM guide](https://www.it-help.tech/blog/dns-security-best-practices/) emphasizes an enforcement policy for DMARC; DNS Tool reflects that by warning on `p=none`. Always review the output messages in context; they often contain advice on why something is important.

**Q: Some of the checks aren’t applicable to my domain – can I ignore them?**
**A:** Yes. DNS Tool is somewhat opinionated toward security best practices. If your domain doesn’t send email at all, seeing ❌ “No SPF” or “No DMARC” is technically fine (though consider adding them to prevent others from spoofing your unused domain). If you don’t operate a web service, “No A record” might be fine. The tool’s output is meant to be a helpful audit, not a strict pass/fail in every scenario. Use your knowledge of your domain’s purpose: for example, if you know a domain is only used for web, and you intentionally have no MX (so it shouldn’t receive email), you can ignore the “No MX” error – but you might still want an SPF/DMARC of `v=spf1 -all` and `p=reject` to nullify email misuse. Ultimately, treat the tool as a knowledgeable advisor: most ❌ need fixing, most ⚠️ deserve improvement, but you’re the final judge of what’s relevant.

**Q: Is DNS Tool safe to run on any domain?**
**A:** Yes. It’s a read-only tool – it only performs DNS queries (the same kind your computer does when visiting a website or sending email) and RDAP/WHOIS lookups. It doesn’t make any changes to DNS. Checking someone else’s domain with DNS Tool is equivalent to querying their DNS records publicly, which is normal and allowed. All the data retrieved is public information by design of DNS. The tool’s queries are also unlikely to trigger any security alarms; at worst, RDAP queries might be rate-limited if you do them in huge volume. We designed DNS Tool to be non-intrusive and network-friendly.

**Q: Can I add or suggest new features?**
**A:** Definitely. DNS and email security evolve, and we welcome contributions. If you have an idea, feel free to open an issue or a pull request on this repository. Please note that major product evolution now happens in the web platform, so some feature requests may be implemented there first.

Hopefully this FAQ answers most questions you’ll have. If you need more help, check out the repository README or open a discussion with the community. Happy DNS exploring!
