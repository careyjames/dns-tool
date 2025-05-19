# DNS Tool

**DNS Tool** is a command-line utility for comprehensive DNS and email security auditing. It provides a one-stop solution to verify critical DNS records (DMARC, SPF, DKIM, DNSSEC, etc.), offering real-time feedback on your domain’s configuration. Designed for network administrators, cybersecurity professionals, and IT engineers, DNS Tool helps prevent email spoofing (e.g., BEC attacks) and fortify your domain’s DNS infrastructure by giving an easy bird’s-eye view of all essential records.

## Why DNS Tool Exists

I built DNS Tool out of frustration with juggling multiple DNS lookup tools. As I often say:

> **“If your DMARC says `p=none`, your work’s not done—get to `p=reject`!”**

Too many domains stick with a DMARC policy of `p=none` (monitoring only), which merely reports spoofing rather than preventing it. Enforcing `p=reject` is crucial to actively block fraudulent emails. But achieving full email security means verifying SPF and DKIM alignment as well, and extending protection with DNSSEC, MTA-STS, DANE, and more.

Before DNS Tool, checking all these meant hopping between separate utilities: one for SPF, another for DMARC, another for DKIM, plus others for DNSSEC, TLSA, CAA, etc.. It was time-consuming and error-prone – especially when propagating DNS changes and needing “live” re-checks. I often found myself copy-pasting domains across half a dozen sites to validate each record type.

### One Tool to Check Them All

That’s why **DNS Tool** (originally called *DNS Scout*) was born. It consolidates all key DNS and email security checks into a single command:

* **Comprehensive Record Coverage:** In one run, DNS Tool checks **NS, A, AAAA, MX, TXT, SPF, DMARC, DKIM, MTA-STS, DANE, BIMI, DNSSEC, CAA, SOA,** and **PTR** records. It also performs an RDAP lookup (with WHOIS fallback) to identify the domain’s registrar.
* **Immediate, Color-Coded Feedback:** Results are printed in color with intuitive symbols – ✅ for passes, ❌ for problems, and ⚠️ for warnings – so you can spot misconfigurations at a glance. Missing records or unsafe settings are clearly highlighted with context and best-practice suggestions.
* **Interactive & Batch Modes:** Use DNS Tool in an interactive prompt (with command history and tab-completion via Prompt Toolkit) or run it in batch mode to scan multiple domains in one go. In both cases, you get instant insight into each domain’s DNS health.
* **Built for Real-Time Iteration:** Correct a DNS setting and re-run the tool immediately to see if the issue is resolved. No need to wait or use external web tools – DNS Tool lets you validate changes as soon as they propagate.
* **Portable, Single-Binary Utility:** DNS Tool is compiled into a single self-contained binary with all Python dependencies bundled. No Python installation is required on the target system, and it works across Linux, macOS, and Windows out-of-the-box.

In short, I was tired of switching between various DNS checkers, so I built one tool to do it all. Now, whether I’m ensuring a domain’s DMARC is set to `p=reject` or confirming that DNSSEC and MTA-STS are configured correctly, I can just run **`dnstool`** and get a complete report in seconds. This unified approach not only saves time but also reduces the chance of overlooking something critical.

### Example Output

Below are sample outputs from **DNS Tool**, illustrating how it highlights issues versus a clean bill of health:

* **Misconfigured Domain (example: `monstrico.com`):** The first screenshot shows a domain with multiple problems – DNS Tool flags missing SPF, a nonexistent DMARC record, outdated MX entries, etc., using ❌ and ⚠️ symbols for each issue.
  ![Example Output – issues detected](Screenshot-Output.png)
  ![Example Output – issues detected 2](Screenshot-Output2.png)

* **Properly Configured Domain:** The next screenshot shows a domain that has all the recommended records in place. Notice the ✅ symbols indicating pass status for each check.
  ![Example Output – all good](Screenshot-Output3.png)

In these outputs, you can see how DNS Tool provides clear indicators: for example, a ❌ “SPF: Missing” or ⚠️ “DMARC: p=none” warning stands out immediately. This makes it easy to identify what needs fixing to improve your domain’s security posture.

## Download and Installation

DNS Tool is available as pre-compiled binaries for major platforms (Linux, macOS, Windows). Download the appropriate release for your system from the [GitHub Releases](../../releases) page. The table below shows the available builds:

| Release Asset                     | Supported Systems                                                       |
| --------------------------------- | ----------------------------------------------------------------------- |
| `dnstool-linux-amd64-glibc-<ver>` | Linux x86\_64 (glibc-based distros: Ubuntu, Debian, Fedora, Kali, etc.) |
| `dnstool-linux-arm64-glibc-<ver>` | Linux ARM64 (Raspberry Pi OS 64-bit, Ubuntu ARM, etc.)                  |
| `dnstool-macos-intel-<ver>`       | macOS (Intel CPUs)                                                      |
| `dnstool-macos-silicon-<ver>`     | macOS (Apple Silicon M1/M2)                                             |
| `dnstool-windows-amd64-<ver>.exe` | Windows 10/11 (x86\_64)                                                 |

### Linux

1. **Download** the Linux binary (`dnstool-linux-amd64-glibc` for Intel/AMD, or `dnstool-linux-arm64-glibc` for ARM) from the Releases page.
2. **Make it executable**:

   ```bash
   chmod +x dnstool-linux-amd64-glibc-<version>
   ```

   (Replace `<version>` with the actual version number of the downloaded file.)
3. **Run the tool**:

   ```bash
   ./dnstool-linux-amd64-glibc-<version> --help
   ```

   *(Optionally, rename the file to just `dnstool` for convenience.)*
4. **(Optional)** Move the binary into your `$PATH` for system-wide use:

   ```bash
   sudo mv dnstool-linux-amd64-glibc-<version> /usr/local/bin/dnstool
   ```

**Note:** The provided Linux binaries require a fairly recent glibc. On older distributions, if you encounter errors about GLIBC version mismatches, you may need to build the tool from source on that system (see **Building from Source** below).

### macOS

1. **Download** the appropriate macOS binary (`dnstool-macos-intel` for Intel Macs, or `dnstool-macos-silicon` for M1/M2 Macs).
2. **Allow it to run**: macOS Gatekeeper might block the app since it isn’t notarized. To bypass this, either:

   * **Via Finder:** Right-click the downloaded file and select “Open”. Confirm by clicking “Open” in the prompt. You may also need to go to **System Preferences → Security & Privacy → General** and click “Allow Anyway” for the app.
   * **Via Terminal:** Make the file executable and remove the quarantine attribute:

     ```bash
     chmod +x dnstool-macos-*
     xattr -d com.apple.quarantine dnstool-macos-*
     ```

     Then run it with `./dnstool-macos-*`.
3. **Run the tool:**
   If prompted about an unverified developer, confirm that you want to run the program. Once launched, DNS Tool’s interactive prompt and color output should work on macOS just as on Linux.

### Windows

1. **Download** the Windows executable (`dnstool-windows-amd64-<version>.exe`) from Releases.
2. **Run** the program by double-clicking it or launching from Command Prompt/PowerShell:

   ```powershell
   .\dnstool-windows-amd64-<version>.exe
   ```
3. If Windows SmartScreen warns that the publisher is unknown, click “More info” then “Run anyway” to start the tool. (The binary is not code-signed at this time.)

After installation, you’re ready to use DNS Tool. You can run `dnstool` without arguments to enter interactive mode, or supply a domain (or list of domains) to run checks immediately. See the **Usage** section below for details.

## Usage

DNS Tool can be used in two primary ways: an **Interactive Mode** for on-the-fly queries, and a **Batch Mode** for scanning multiple domains. It also supports a few options for advanced usage.

### Interactive Mode

Simply run the `dnstool` binary with no arguments to start an interactive session:

```bash
$ ./dnstool
```

You will see a prompt (usually **`Domain:`** in bold text) indicating that the tool is ready for input. At the prompt, type a domain name (e.g., `example.com`) and press **Enter**. DNS Tool will immediately run all checks for that domain and display the results in a formatted, color-coded list.

* **Arrow-Key History:** You can press the Up/Down arrow keys to navigate through previously entered domains (this history is persisted between sessions, stored in `~/.domain_history_rdap_interactive`). This makes it easy to re-check a domain you queried earlier.
* **Exit:** To quit interactive mode, type `exit` or simply press Enter on an empty prompt line.

**Example:**

```
Domain: example.com
✅ NS: OK – Found 4 name servers  
❌ SPF: Missing – No SPF record found  
⚠️ DMARC: p=none – Policy not enforcing (monitor only)
… (additional checks) …
```

In the above hypothetical output, **✅** indicates the NS records exist and look correct, **❌** indicates a critical issue (no SPF record was found for the domain), and **⚠️** is a warning (DMARC policy is set to none, meaning no enforcement). These symbols provide a quick visual summary of each check’s outcome.

### Batch Mode

Batch mode allows you to check multiple domains in one run, which is useful for auditing many domains or automating reports.

* **Multiple Domains as Arguments:** You can list one or more domains after the command to check them sequentially. For example:

  ```bash
  $ ./dnstool example.com example.org test.co
  ```

  DNS Tool will run through all checks for `example.com`, then proceed to `example.org`, then `test.co`, in one execution. Each domain’s results are separated by a header line for clarity.

* **Domain List from File:** Alternatively, use the `-f <filename>` option to read domains from a text file (one domain per line). For example:

  ```bash
  $ ./dnstool -f domains.txt
  ```

  This will run the tool on every domain listed in *domains.txt*. This method is handy for scheduled bulk audits or integrating with scripts.

**Note:** In batch mode, output for each domain is printed one after another. Scroll up to make sure you identify which domain a set of results belongs to. DNS Tool prints a separator and the domain name being checked, to help delineate outputs.

### Custom DNS Resolvers

By default, DNS Tool uses a preset list of public DNS resolvers – **1.1.1.1 (Cloudflare)**, **8.8.8.8 (Google)**, and **9.9.9.9 (Quad9)** – to perform queries. These are hardcoded to ensure consistent results and avoid local DNS caching issues. If you prefer to use specific DNS servers (for instance, your own resolver or an internal DNS server), you can specify one or more via the `--resolver` (or `-r`) option:

```bash
$ ./dnstool --resolver 1.1.1.1 --resolver 8.8.8.8 example.com
```

You can repeat `--resolver` to list multiple DNS server IPs (the order will be used for queries). If you use this option, the default resolvers are overridden. For example, to use only Cloudflare DNS, just supply `--resolver 1.1.1.1`. To use your system’s default resolver, you could specify its IP (e.g., `--resolver 192.168.1.1` for a router-based DNS, etc.).

### Authoritative Lookups

Normally, DNS Tool performs *recursive* DNS queries (respecting caches). If you want to bypass caches and query a domain’s authoritative nameservers directly, use the **`-a` / `--authoritative`** flag. This forces each DNS lookup to go straight to the source (the NS records for the target domain), which is useful for checking unpropagated changes or getting fresher data:

```bash
$ ./dnstool --authoritative example.com
```

Authoritative mode may be slightly slower (it has to fetch NS and then query each directly) but ensures you’re seeing the records as delivered by the domain’s own DNS servers.

### Verbose / Debug Mode

For more insight into what the tool is doing under the hood, use the **`-v` / `--verbose`** flag. Verbose mode will print debug messages to stderr as the tool runs, such as DNS query timings, which RDAP servers are being queried, and other diagnostic info. This is useful for troubleshooting when a check is failing unexpectedly or to see details like fallback to WHOIS.

```bash
$ ./dnstool -v example.com
```

In verbose output, lines prefixed with `[DEBUG]` (or logged as errors) may appear, which can help identify network issues (e.g., timeouts contacting a DNS server or web endpoint for MTA-STS) or clarify the decision behind a ❌/⚠️ result.

### Getting Help

Run `dnstool -h` (or `--help`) to display a brief usage summary at any time:

```text
$ ./dnstool -h
usage: dnstool.py [-v] [-f FILE] [-r RESOLVER] [-a] [domain1 domain2 ...]
```

This usage message outlines the available command-line options and arguments. For detailed documentation on each feature, continue reading this document or see the **DNS Checks Explained** section.

## Building from Source

DNS Tool is written in Python (requires Python 3.7+). If you prefer to build the binary yourself or need to run from source (e.g., on an unsupported platform), follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/careyjames/dns-tool.git
   cd dns-tool
   ```
2. **Install dependencies:** It’s recommended to use a virtual environment. Required libraries (with versions) are listed in `requirements.txt`. For example:

   ```bash
   python3 -m venv buildenv
   source buildenv/bin/activate
   pip install -r requirements.txt
   ```

   *(This installs `dnspython`, `requests`, `idna`, `prompt_toolkit`, etc.)*
3. **Compile the binary:**

   ```bash
   pyinstaller --onefile dnstool.py
   ```

   After a successful build, you’ll find the standalone binary in the `dist/` directory (e.g., `dist/dnstool` or `dist/dnstool.exe` on Windows). You can now use this binary just like the release versions.

Of course, you can also simply run `dnstool.py` directly with Python if you have the dependencies installed, but using PyInstaller as above creates a convenient portable binary.

## Running Tests

This project includes a test suite to verify functionality. Tests are written with `pytest`. To run the tests, install `pytest` in your environment, then execute:

```bash
pytest
```

from the project root. The tests cover domain validation, unicode handling, and various helper functions. Running them can give you confidence that everything is working as expected on your system.

## FAQ

**Q: Why is Windows complaining about an “unknown publisher” when I run DNS Tool?**
**A:** Because the Windows executable is not code-signed at the moment. This means Windows SmartScreen may warn that the publisher is unverified. The tool is safe to run – to proceed, click “More info” then “Run anyway.” In enterprise environments, you might need to adjust SmartScreen or antivirus settings to allow unsigned binaries.

**Q: How do I run the macOS binary if it’s blocked by Gatekeeper?**
**A:** macOS may prevent the app from running since it’s not notarized by Apple. You can right-click the binary and select “Open”, then confirm you want to run it. Or, open **System Preferences → Security & Privacy** and click “Open Anyway” after trying to run the app. As a third option, run `chmod +x` on the file and use `xattr -d com.apple.quarantine` to remove the quarantine attribute, then execute it from Terminal. After the first run, it shouldn’t prompt again.

**Q: Does the Linux binary work on all distributions?**
**A:** The pre-built binary should run on most modern Linux systems that have a glibc version comparable to the build environment. It’s been tested on Ubuntu, Debian, Fedora, Kali, etc. If you get errors about “GLIBC\_XX not found” on an older distro, that means the binary is incompatible with your system’s C library – in that case, you can compile DNS Tool from source on that machine, or upgrade to a newer OS.

**Q: Do I need to install anything for the arrow-key history and colored output to work?**
**A:** No. DNS Tool bundles the needed libraries (like `prompt_toolkit` for interactive history) into the single binary. The arrow-key command recall works out-of-the-box, saving history to `~/.domain_history_rdap_interactive`. Colored output should work in any modern terminal; if you’re using Windows CMD and don’t see colors, try PowerShell or Windows Terminal which have ANSI color support.

**Q: Can I check dozens or hundreds of domains at once?**
**A:** Yes, using the batch modes described above. There isn’t a hard-coded domain limit. For very large lists, the main consideration is time and output volume – each domain’s check involves multiple DNS queries (and some HTTPS queries for things like MTA-STS), so scanning hundreds of domains will take longer. It may be wise to break extremely large sets into chunks or run multiple instances in parallel (keeping an eye on not exceeding your network’s query rate limits). In most cases, checking a few dozen domains serially is quite feasible.

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for the full text.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an Issue on GitHub. Pull requests are encouraged for any improvements or fixes. When contributing code, please test your changes on Linux, macOS, and Windows if possible to ensure cross-platform compatibility. Together we can make DNS Tool even better for the community.

---

---

## docs/installation-and-setup.md

# Installation and Setup

Welcome to the **DNS Tool** installation guide. Follow the steps below to get DNS Tool up and running on your platform. Precompiled binaries are available for Linux, macOS, and Windows – no additional dependencies required.

## Linux

1. **Download** the latest Linux binary from the [GitHub Releases](https://github.com/careyjames/dns-tool/releases) page. Choose **AMD64** for 64-bit x86 systems, or **ARM64** if you’re on an ARM-based device. The file will be named similar to `dnstool-linux-amd64-glibc-<version>`.
2. **Make it executable** by running:

   ```bash
   chmod +x dnstool-linux-*.glibc-<version>
   ```

   This ensures you have permission to run the file.
3. **Run the tool**:

   ```bash
   ./dnstool-linux-amd64-glibc-<version>
   ```

   You should see the interactive prompt or usage info (if running without arguments). For convenience, you can rename the file to just `dnstool` and move it into a directory in your PATH (e.g., `/usr/local/bin`), so you can invoke it from anywhere.
4. *(Optional)* **Install system-wide**:

   ```bash
   sudo mv dnstool-linux-amd64-glibc-<version> /usr/local/bin/dnstool
   ```

   Now you can simply use `dnstool` as a command.

**Troubleshooting:** If you get an error about an incompatible GLIBC version when you run the binary, your Linux distribution may be too old for the pre-built binary. In that case, consider building DNS Tool from source on your system (see the repository README for instructions) or upgrading your OS.

## macOS

1. **Download** the macOS binary from [Releases](https://github.com/careyjames/dns-tool/releases). There are two macOS builds – one for Intel-based Macs and one for Apple Silicon (M1/M2). Grab the one that matches your hardware.
2. **Allow it to run:** After downloading, the binary might be blocked by macOS security since it isn’t from the App Store. To launch it:

   * Locate the file in Finder, right-click (or Ctrl-click) and choose “Open”. In the dialog that appears, confirm you want to open it. *(You only need to do this the first time.)*
   * If that doesn’t work, open **System Preferences → Security & Privacy → General**. You might see a message about `dnstool` being blocked; click “Allow Anyway”, then try opening the app again.
   * **Advanced:** As an alternative, you can remove the quarantine attribute via Terminal:

     ```bash
     chmod +x dnstool-macos-*            # give execute permission
     xattr -d com.apple.quarantine dnstool-macos-*
     ```

     Then run the binary with `./dnstool-macos-<...>`.
3. **Run the tool:** Double-click the app or execute it from Terminal. A Terminal window will open with the DNS Tool prompt (if you double-clicked). You should see colorized output and be able to use arrow keys in interactive mode just like on Linux.

## Windows

1. **Download** the Windows executable (`dnstool-windows-amd64-<version>.exe`) from the [Releases](https://github.com/careyjames/dns-tool/releases) page.
2. **Run** the downloaded `.exe` file. You can double-click it or run it from a Command Prompt / PowerShell:

   ```powershell
   C:\> dnstool-windows-amd64-<version>.exe
   ```
3. The first time you run it, Windows might show a **SmartScreen** warning (because the app isn’t signed by a publisher). Click on “More info” and then “Run anyway” to proceed. This will launch DNS Tool in a console window.

After these steps, DNS Tool should be up and running on your system. You can now move on to the [Usage and Examples](usage-and-examples.md) section to learn how to use the tool effectively.

---

## docs/usage-and-examples.md

# Usage and Examples

This guide will walk you through using DNS Tool in practice, with examples for both interactive and batch modes, plus explanations of the output. By the end, you’ll know how to quickly check a single domain or automate scans of many domains.

## Interactive Mode 🌐

In interactive mode, you launch DNS Tool and then enter domain names one at a time, getting instant results for each.

To start interactive mode, run the `dnstool` command with no arguments:

```bash
$ ./dnstool
```

You’ll be presented with a prompt (it will say **Domain:**). At this prompt, type a domain name (for example, `example.com`) and press **Enter**. DNS Tool will immediately perform all its checks on the domain.

* The output is **color-coded** and annotated with symbols: **✅** indicates a check passed or a recommended record is present, **❌** means a critical problem or missing record, and **⚠️** denotes a warning or advisory. For instance, you might see something like:

  ```
  ✅ NS: OK – 4 name servers found
  ❌ SPF: Missing – No SPF record
  ⚠️ DMARC: Policy p=none – Not enforcing
  ```

  This tells us the domain has NS records (✅), is missing an SPF record (❌), and has a DMARC policy set to “none” which is a warning state (⚠️).
* You can use the **Up/Down arrow keys** to scroll through previously entered domains during this session. This history is preserved across runs as well (stored in a hidden file in your home directory), so you can easily re-check domains you’ve queried before.
* To **exit** interactive mode, type `exit` or just press Enter on an empty prompt. The program will terminate.

Interactive mode is great for on-the-fly investigations or when you want to iteratively fix issues: update your DNS, run the tool, see the ✅ replace a ❌ in real time.

## Batch Mode 🗂️

Batch mode allows you to run DNS Tool for multiple domains in one go, which is useful for periodic audits or if you manage a portfolio of domains.

There are two ways to use batch mode:

### 1. Multiple Domains as Arguments

You can provide multiple domain names separated by space on the command line. For example:

```bash
$ ./dnstool example.com example.org test.io
```

DNS Tool will sequentially check each domain and print the results one after another. Each domain’s section of output begins with a header line (a row of `========================================` and the domain name) to clearly delineate where one domain’s results end and the next begins. This makes it easier to scroll through the output and find the domain you’re interested in.

There’s no strict limit to how many domains you can list, but for a large number, the output will be long. It might be convenient to redirect output to a file for later analysis if you are checking dozens of domains at once.

### 2. Reading Domains from a File

If you have a long list of domains, you can use the `-f` (file) option to have DNS Tool read domain names from a file. In the file, list one domain per line. For example, create a `domains.txt` containing:

```
example.com
example.net
example.org
```

Then run:

```bash
$ ./dnstool -f domains.txt
```

DNS Tool will open the file, queue up all the domains, and perform checks on each in turn. This is particularly handy for scheduled jobs or integrating with other scripts – you can maintain a text file of domains and let the tool iterate through them.

**Tip:** If you’re using batch mode in an automated script, you might also consider using the `--resolver` or `--authoritative` flags if you need custom DNS resolution behavior (see the Advanced section).

## Verbose Mode 🛠️

In both interactive and batch use, you can enable verbose output to get debug information. This is done with the `-v` flag:

```bash
$ ./dnstool -v example.com
```

With verbose mode on, DNS Tool will print additional details to the console (stdout or stderr). You might see which DNS server it’s querying, how long each query took, or messages like “\[DEBUG] Trying next RDAP endpoint…” and so on. This information is useful for troubleshooting – for example, if a check is failing due to a timeout or network issue, verbose mode will surface that underlying cause.

Verbose mode can also be combined with batch mode or any other options.

## Examples

Let’s go through a full example to illustrate how you might use DNS Tool:

* **Single Domain Audit:** Imagine you want to verify the configuration of `yourdomain.com` after making some DNS changes. You run `dnstool yourdomain.com`. The tool prints out a report: you see ✅ on NS, A, and MX, but ❌ on SPF and ⚠️ on DMARC. Reading the lines, it says “No SPF record found” and “DMARC policy p=none”. Armed with this, you know you need to add an SPF record and change your DMARC policy to a stricter setting. You add an SPF TXT record and a DMARC TXT record with policy `quarantine` or `reject`. A few minutes later, you run `dnstool yourdomain.com` again and now see a ✅ for SPF and the DMARC line shows p=reject with a ✅ – all clear!

* **Batch Report:** Suppose you manage 5 domains and want to do a routine check each week. You list them all in `domains.txt` and run `dnstool -f domains.txt > report.txt`. When you open *report.txt*, you see each domain’s results separated clearly. Domain1 might have a warning about an outdated MX record, Domain3 might show that DNSSEC is not enabled, etc. You can then address each issue domain-by-domain. This report can also be shared with your team or included in documentation to show progress on tightening DNS security.

These examples show how DNS Tool can fit into your workflow, whether it’s one-off troubleshooting or regular security audits. In the next sections, we’ll dive deeper into what each check means and how to interpret the results in detail – see **DNS Checks Explained** for an in-depth look at each record type and **Advanced** for integration tips and advanced usage.

*(Continue to the next sections for Advanced usage and detailed explanation of each DNS check.)*

---

## docs/advanced.md

# Advanced Usage and Integration

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

---

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

## docs/faq.md

# FAQ

Below are answers to some frequently asked questions about DNS Tool, covering usage, capabilities, and common scenarios.

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
  In other words, a “clean” output (all ✅ and no ❌/⚠️) means your domain’s DNS is in great shape by current standards. If there are warnings, consider them recommendations for hardening your domain (for example, moving DMARC from none to reject, adding DNSSEC, etc.). The tool incorporates guidance from industry best practices – for instance, [our blog post on mastering DMARC/SPF/DKIM](https://www.it-help.tech/blog/defend-your-domain-master-dns-security-with-dmarc-spf-and-dkim) emphasizes an enforcement policy for DMARC; DNS Tool reflects that by warning on `p=none`. Always review the output messages in context; they often contain advice on why something is important.

**Q: Some of the checks aren’t applicable to my domain – can I ignore them?**
**A:** Yes. DNS Tool is somewhat opinionated toward security best practices. If your domain doesn’t send email at all, seeing ❌ “No SPF” or “No DMARC” is technically fine (though consider adding them to prevent others from spoofing your unused domain). If you don’t operate a web service, “No A record” might be fine. The tool’s output is meant to be a helpful audit, not a strict pass/fail in every scenario. Use your knowledge of your domain’s purpose: for example, if you know a domain is only used for web, and you intentionally have no MX (so it shouldn’t receive email), you can ignore the “No MX” error – but you might still want an SPF/DMARC of `v=spf1 -all` and `p=reject` to nullify email misuse. Ultimately, treat the tool as a knowledgeable advisor: most ❌ need fixing, most ⚠️ deserve improvement, but you’re the final judge of what’s relevant.

**Q: Is DNS Tool safe to run on any domain?**
**A:** Yes. It’s a read-only tool – it only performs DNS queries (the same kind your computer does when visiting a website or sending email) and RDAP/WHOIS lookups. It doesn’t make any changes to DNS. Checking someone else’s domain with DNS Tool is equivalent to querying their DNS records publicly, which is normal and allowed. All the data retrieved is public information by design of DNS. The tool’s queries are also unlikely to trigger any security alarms; at worst, RDAP queries might be rate-limited if you do them in huge volume. We designed DNS Tool to be non-intrusive and network-friendly.

**Q: Can I add or suggest new features?**
**A:** Definitely. DNS and email security evolve, and we welcome contributions. If you have an idea (for example, checking for a new record type, or supporting JSON output, or an interactive GUI), feel free to open an issue or a pull request on the GitHub repository. This project is open source (Apache 2.0 licensed) and thrives on community feedback. Whether it’s a bug report, a feature request, or a code contribution, we’d love to hear from you.

Hopefully this FAQ answers most questions you’ll have. If you need more help, check out the repository README or open a discussion with the community. Happy DNS exploring!

---

## docs/changelog.md

# Changelog

All notable changes to DNS Tool are documented here. This project adheres to semantic versioning.

* **v1.2.3** – *Released 2025-05-17*
  **New Features:** Added support for BIMI and MTA-STS checks in the output (the tool now identifies BIMI records and validates MTA-STS policies). Improved DMARC feedback messages – the tool now explicitly warns when `p=none` and praises `p=reject` configurations.
  **Improvements:** Optimized interactive mode for faster start-up. Updated embedded dependencies to latest versions for security patches. Minor tweaks to color output for better readability on Windows.
  **Fixes:** Resolved a bug where multiple SPF records were not all detected in certain cases. Fixed an issue with DNSSEC detection on domains that have A records but no RRSIG (now correctly flags as not signed).

* **v1.2.2** – *Released 2025-04-10*
  **New Features:** Introduced DANE (TLSA) record checks for SMTP and HTTPS services. DNS Tool will now alert if your domain has no TLSA for SMTP (which is optional) and show any existing TLSA records. Added CAA record checking with a recommendation if none present.
  **Improvements:** Batch mode output formatting enhanced – each domain’s section is clearly separated with a header for easier parsing. Verbose mode now logs HTTP status codes for MTA-STS policy fetch attempts, helping debug MTA-STS deployment issues.
  **Fixes:** Fixed detection of deprecated Google MX records (aspmx2/3.googlemail.com) – now properly warns if those are present. Corrected some typos in output messages for clarity.

* **v1.2.1** – *Released 2025-03-01*
  Initial release of **DNS Tool (Python Edition)**. This version introduced the core functionality of the tool: interactive and batch modes, comprehensive DNS checks for NS, A, AAAA, MX, TXT, SPF, DKIM, DMARC, DNSSEC, PTR, etc., and integrated RDAP lookups for registrar info. The focus was on providing a unified output with clear indicators (✅/❌/⚠️) for each check. Packaged as a single-file executable via PyInstaller for easy distribution on Linux, macOS, and Windows.

*(For a detailed history and commit-by-commit information, see the Git repository logs. Future release notes will continue to document new features, improvements, and fixes.)*
