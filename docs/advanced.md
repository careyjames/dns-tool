## docs/advanced.md

# Advanced Usage and Integration

> **Legacy CLI advanced guide**
>
> This page applies to the command-line release line.
>
> For the current primary DNS Tool platform, use the web app: https://dnstool.it-help.tech/

For power users and larger deployments, DNS Tool offers flexibility to integrate into scripts, CI pipelines, and other automation. It also provides flags to tweak its behavior for special scenarios. This section covers how to make the most of DNS Tool in advanced use cases, as well as performance considerations and troubleshooting tips.

## Integration & Automation

**Using in Scripts and CI/CD:** DNS Tool’s binary can be invoked in any environment where you might script DNS checks. For example, you could include a step in a CI pipeline (GitHub Actions, Jenkins, etc.) that runs `dnstool yourdomain.com` after DNS changes or before a deployment, to ensure critical records are in place (like ensuring a new subdomain has the correct DNS entries). The exit code of the `dnstool` command is `0` as long as the program runs to completion, even if it finds issues – so if you want to fail a build or alert based on findings, you should parse the output for “❌” or specific keywords. For instance, a simple grep for "❌" in the output can tell you if any critical misconfigurations were detected.

**Cron Jobs for Monitoring:** Many administrators set up cron jobs to run DNS Tool on a schedule (daily/weekly) for their domains. This produces a regular report that can be emailed out or stored. It’s a great way to catch unexpected DNS changes – e.g., if someone modified a DNS record incorrectly, the next run of DNS Tool would flag it. When running in cron, remember to specify any needed options (like `--authoritative` if you want fresh data, or `-r` if your environment requires a custom DNS server). Also, directing output to a timestamped file or email can help track changes over time.

**Scripting Tips:** Because DNS Tool outputs human-readable text with colors and symbols, you might want to disable color when capturing output to a file (to avoid ANSI codes in your logs). Currently, DNS Tool doesn’t have a built-in “no-color” switch, but you can achieve this by running it through a strip-colors utility or by piping through `sed`/`perl` to remove `\x1b[...m` sequences. Alternatively, consider requesting a feature for machine-readable output (JSON/XML) if you need to integrate it deeply; as of now, that’s not implemented.

## Advanced Flags & Options

DNS Tool provides several command-line options to adjust its behavior:

* **`-r, --resolver <IP>`** (Repeatable): Use a custom DNS resolver for lookups. By default, DNS Tool uses a set of public resolvers (Cloudflare, Google, Quad9). If you need to query through a specific DNS server (for instance, your organization’s internal DNS that knows internal zones, or a regional DNS for testing propagation), use this flag. You can specify it multiple times to provide a list of DNS server IPs – the tool will try them in order. Example: `--resolver 10.1.1.1 --resolver 10.2.2.2` to use two internal DNS servers. **Note:** This overrides the default servers entirely.

* **`-a, --authoritative`**: Enable authoritative mode. When this flag is set, DNS Tool will send queries directly to the domain’s *authoritative* nameservers instead of a recursive resolver cache. This is useful if you suspect caching might hide the current truth (for example, right after you update a record), or to double-check what the authoritative response is. Keep in mind that in authoritative mode, DNS Tool first has to discover the NS records for the domain (from the root servers) and then query those, which adds a bit of latency to each lookup. However, it guarantees the freshest data.

* **`-f, --file <filename>`**: Read domains from a file. This is the batch mode convenience option we discussed earlier. It can be combined with other options; e.g., you can use `-a` and `-f` together to do authoritative checks on a list of domains, or `-v` and `-f` for verbose checks on multiple domains.

* **`-v, --verbose`**: Verbose output. Prints debug information as the tool runs. Use this if you need to troubleshoot or to see the timing and sequence of operations (for instance, which RDAP servers are queried for registrar info, or the HTTP status of fetching an MTA-STS policy). In verbose mode, errors that are normally suppressed (for example, if a query times out and the tool moves on) will be shown, which can provide insight into network issues or unsupported record types.

* **(Implicit)** *Interactive mode trigger*: If you run `dnstool` with **no arguments**, it goes into interactive mode. If you provide one or more domains (via arguments or file), it goes into batch mode. There isn’t a separate flag for interactive mode – it’s automatically chosen when no domains are given.

At this time, DNS Tool does not require any configuration file – all options are provided via CLI flags. This makes it easy to use in ephemeral environments (just call it with the needed flags each time). If you have suggestions for additional options (for example, an output format or a specific check to toggle), feel free to contribute or open an issue.

## Performance Considerations

DNS Tool is designed to be efficient, but its performance naturally depends on external factors: network latency to DNS servers, the responsiveness of RDAP services, etc. Here are some notes on performance and how to optimize:

* **Parallelism:** Currently, DNS Tool checks the records sequentially for each domain (and domains one after the other in batch mode). This is deliberate to avoid confusing output ordering and to be gentle on servers. If you need to speed up checking a large list of domains, you could run multiple instances of DNS Tool in parallel (for example, splitting a list of 100 domains into 4 files and running 4 processes). Just be mindful of not overwhelming DNS or RDAP services.
* **Timeouts and Retries:** The tool uses a default DNS query timeout of a few seconds per query, with a couple of retry attempts. Most domains’ DNS will answer well within this, but if you’re on a very slow network or querying an unreliable server, the verbose mode will show if timeouts occur. For web fetches (like MTA-STS policy retrieval), a short timeout (\~5 seconds) is used. In most cases this is enough; if not, you might see an error in the output.
* **RDAP/WHOIS Rate Limits:** When DNS Tool performs an RDAP lookup for the domain’s registrar, it’s querying a public RDAP service (often run by the registry or a regional internet authority). These services can have rate limits. If you check hundreds of domains in one run, the RDAP step might get rate-limited or temporarily blocked for some lookups. The tool does try a WHOIS fallback if RDAP fails, but WHOIS servers can also be rate-limited. In a scenario of many domains, consider whether you need the registrar info every time; if not, you can ignore that part of the output or run in smaller batches to be safe.
* **Memory and CPU:** DNS Tool’s memory and CPU footprint is minimal. Even checking dozens of domains, it’s mostly waiting on network I/O. It’s perfectly fine to run on low-power systems (like a Raspberry Pi or a cloud VM) – just keep an eye on network connectivity.

## Troubleshooting Tips

* **No Output / Immediate Exit:** If you run `dnstool` and nothing happens or it exits immediately, make sure you’re actually running the binary (add `./` if it’s in the current directory). Running without any arguments should show the interactive prompt text. If not, add `-v` to see if an error is printed (e.g., a missing dependency or an import failing – which shouldn’t happen with the packaged binary, but could if running from source without installing requirements).
* **DNS Queries Failing:** If every DNS check is coming back with “not found” or timing out, it could be a network issue. Ensure your internet connection is working and that outbound DNS (UDP/TCP on port 53) isn’t being blocked by a firewall. If you suspect your network blocks external DNS, use the `--resolver` flag to point to your local DNS server (which might be allowed) or use a known port 53 alternative.
* **Incorrect Results / False Alarms:** DNS Tool tries to interpret records in a security context. For example, it warns if DMARC is `p=none` because that’s not enforcing protection, and it warns if no CAA record because having one is a good practice. These aren’t “errors” per se, but recommendations. Use your judgment: if a domain is intentionally configured a certain way (maybe you *want* an open DMARC policy during a testing phase), you can ignore the warning. Similarly, the absence of DNSSEC or DANE might be acceptable for your scenario, but the tool highlights it so you’re aware of potential improvements.
* **Arrow Keys Not Working (Windows):** On Windows, the bundled `prompt_toolkit` should enable arrow-key history in most terminals. If you find arrow keys don’t work (e.g., in the old cmd.exe), try using PowerShell or the newer Windows Terminal which have better support for modern input handling. In some cases, running the tool via `python dnstool.py` might not have history if `prompt_toolkit` isn’t installed separately – but with the packaged `.exe` you should have it working out-of-the-box.
* **Character Encoding Issues:** If you input an internationalized domain name (IDN) with non-ASCII characters, DNS Tool will attempt to convert it to punycode (ASCII) for lookup. If you see garbled output or an error for such domains, it may be an edge case in IDNA conversion. Please report it. Generally, the tool will print the ASCII form (prefixed with `xn--`) of the domain in the output in those cases.

Remember, you can always run `dnstool -v` for more verbose debugging info. And if you encounter a persistent issue, check the project’s GitHub Issues or open a new one with details. The community can likely help with specific cases, and it may lead to improved future versions of the tool.
