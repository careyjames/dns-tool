# DNS Tool

**DNS Tool** is a command-line utility for comprehensive DNS and email security auditing. It provides a one-stop solution to verify critical DNS records (DMARC, SPF, DKIM, DNSSEC, etc.) and offers real-time feedback on your domain’s configuration. Designed for network administrators, cybersecurity professionals, and IT engineers, DNS Tool helps prevent email spoofing (e.g., BEC attacks) and fortify your domain’s DNS infrastructure by giving an easy bird’s-eye view of all essential records.

## Why DNS Tool Exists

I built DNS Tool out of frustration with juggling multiple DNS lookup tools. As I often say:

> **“If your DMARC says `p=none`, your work’s not done—get to `p=reject`!”**

Too many domains have a DMARC policy of `p=none` (monitoring only), which merely reports spoofing rather than preventing it. Enforcing `p=reject` is crucial to actively blocking fraudulent emails. However, achieving full email security means verifying SPF and DKIM alignment and extending protection with DNSSEC, MTA-STS, DANE, and more.

Before creating the DNS Tool, checking all these meant hopping between separate utilities: one for SPF, another for DMARC, another for DKIM, plus others for DNSSEC, TLSA, CAA, etc. It was time-consuming and error-prone, especially when propagating DNS changes and needing “live” re-checks. I often copy-pasted domains across half a dozen sites to validate each record type.

### One Tool to Check Them All

That’s why **DNS Tool** (originally called *DNS Scout*) was born. It consolidates all key DNS and email security checks into a single command:

* **Comprehensive Record Coverage:** In one run, DNS Tool checks **NS, A, AAAA, MX, TXT, SPF, DMARC, DKIM, MTA-STS, DANE, BIMI, DNSSEC, CAA, SOA,** and **PTR** records. It also performs an RDAP lookup (with WHOIS fallback) to identify the domain’s registrar.
* **Immediate, Color-Coded Feedback:** Results are printed in color with intuitive symbols – ✅ for passes, ❌ for problems, and ⚠️ for warnings – so you can spot misconfigurations at a glance. Missing records or unsafe settings are highlighted with context and best-practice suggestions.
* **Interactive & Batch Modes:** You can use the DNS Tool in an interactive prompt (with command history and tab completion via Prompt Toolkit) or run it in batch mode to scan multiple domains in one go.
You get instant insight into each domain’s DNS health in both cases.
* **Built for Real-Time Iteration:** Correct a DNS setting and re-run the tool immediately to see if the issue is resolved. There is no need to wait or use external web tools—the DNS Tool lets you validate changes as soon as they propagate.
* **Portable, Single-Binary Utility:** DNS Tool is compiled into a single self-contained binary with all Python dependencies bundled. No Python installation is required on the target system, and it works out of the box across Linux, macOS, and Windows.

In short, I was tired of switching between various DNS checkers, so I built one tool to do it all. Now, whether I’m ensuring a domain’s DMARC is set to `p=reject` or confirming that DNSSEC and MTA-STS are configured correctly, I can run **`dnstool`** and get a complete report in seconds. This unified approach saves time and reduces the chance of overlooking something critical.

### Example Output

Below are sample outputs from **DNS Tool**, illustrating how it highlights issues versus a clean bill of health:

* **Misconfigured Domain (example: `monstrico.com`):** The first screenshot shows a domain with multiple problems—the DNS Tool flags a malformed SPF and DMARC record, nonexistent MX entries, etc., using ❌ ⚠️ symbols for each issue.  
Note: In the misconfigured domain example, it shows a ✅ by the TXT Records found because it did find TXT records, below in the SPF section, it clarifies that the records are malformed.
  ![Example Output – issues detected](Screenshot-Output.png)
  ![Example Output – issues detected 2](Screenshot-Output2.png)

* **Properly Configured Domain:** The following screenshot shows a domain with all the recommended records. Notice the ✅ symbols indicating pass status for each check.
  ![Example Output – all good](Screenshot-Output3.png)

These outputs show how the DNS Tool provides clear indicators. For example, an ❌ “SPF: Missing” or ⚠️ “DMARC: p=none” warning stands out immediately.  
This makes it easy to identify what needs fixing to improve your domain’s security posture.

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

**Note:** The provided Linux binaries require a relatively recent glibc. If you encounter errors about GLIBC version mismatches on older distributions, you may need to build the tool from source on that system (see **Building from Source** below).

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
   If prompted about an unverified developer, confirm that you want to run the program. Once launched, DNS Tool’s interactive prompt and color output should work on macOS as well as on Linux.

### Windows

1. **Download** the Windows executable (`dnstool-windows-amd64-<version>.exe`) from Releases.
2. **Run** the program by double-clicking it or launching from Command Prompt/PowerShell:

   ```powershell
   .\dnstool-windows-amd64-<version>.exe
   ```
3. If Windows SmartScreen warns that the publisher is unknown, click “More info” then “Run anyway” to start the tool. (The binary is not code-signed at this time.)

After installation, you’re ready to use DNS Tool. You can run `dnstool` without arguments to enter interactive mode, or supply a domain (or list of domains) to run checks immediately. See the **Usage** section below for details.

## Usage

DNS Tool can be used in two primary ways: an **Interactive Mode** for on-the-fly queries and a **Batch Mode** for scanning multiple domains. It also supports a few advanced usage options.

### Interactive Mode

Run the `dnstool` binary with no arguments to start an interactive session:

```bash
$ ./dnstool
```

You will see a prompt (usually **`Domain:`** in bold text) indicating that the tool is ready for input. Type a domain name (e.g., `example.com`) at the prompt and press **Enter**. DNS Tool will immediately run all checks for that domain and display the results in a formatted, color-coded list.

* **Arrow-Key History:** You can press the Up/Down arrow keys to navigate through previously entered domains (this history is persisted between sessions, stored in `~/.domain_history_rdap_interactive`). This makes it easy to re-check a domain you queried earlier.
* **Exit:** To quit interactive mode, type `exit` or press Enter on an empty prompt line.

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

Batch mode allows you to check multiple domains in one run, which helps audit many domains or automate reports.

* **Multiple Domains as Arguments:** You can list one or more domains after the command to check them sequentially. For example:

  ```bash
  $ ./dnstool example.com example.org test.co
  ```

  The DNS Tool will run through all checks for `example.com`, then proceed to `example.org`, and finally, `test.co`, in one execution. For clarity, each domain’s results are separated by a header line.

* **Domain List from File:** Alternatively, use the `-f <filename>` option to read domains from a text file (one domain per line). For example:

  ```bash
  $ ./dnstool -f domains.txt
  ```

  This will run the tool on every domain listed in *domains.txt*. This method is handy for scheduled bulk audits or integrating with scripts.

**Note:** In batch mode, output for each domain is printed one after another. You can scroll up to make sure you identify which domain a set of results belongs to. DNS Tool prints a separator and the domain name being checked, to help delineate outputs.

### Custom DNS Resolvers

By default, DNS Tool uses a preset list of public DNS resolvers – **1.1.1.1 (Cloudflare)**, **8.8.8.8 (Google)**, and **9.9.9.9 (Quad9)** – to perform queries. These are hardcoded to ensure consistent results and avoid local DNS caching issues. If you prefer to use specific DNS servers (for instance, your resolver or an internal DNS server), you can specify one or more via the `--resolver` (or `-r`) option:

```bash
$ ./dnstool --resolver 1.1.1.1 --resolver 8.8.8.8 example.com
```

You can repeat `--resolver` to list multiple DNS server IPs (the order will be used for queries). If you use this option, the default resolvers are overridden. For example, to use only Cloudflare DNS, just supply `--resolver 1.1.1.1`. To use your system’s default resolver, specify its IP (e.g., `--resolver 192.168.1.1` for a router-based DNS, etc.).

### Authoritative Lookups

Usually, DNS Tool performs *recursive* DNS queries (respecting caches). If you want to bypass caches and query a domain’s authoritative nameservers directly, use the **`-a` / `--authoritative`** flag. This forces each DNS lookup to go straight to the source (the NS records for the target domain), which helps check unpropagated changes or get fresher data:

```bash
$ ./dnstool --authoritative example.com
```

Authoritative mode may be slightly slower (it has to fetch NS and then query each directly), but ensures you see the records as delivered by the domain’s own DNS servers. SO, to check propagation, use interactive mode.

### Verbose / Debug Mode

Use the **`-v` / `--verbose`** flag for more insight into what the tool is doing under the hood. Verbose mode will print debug messages to stderr as the tool runs, such as DNS query timings, which RDAP servers are being queried, and other diagnostic info. This is useful for troubleshooting when a check fails unexpectedly or to see details like fallback to WHOIS.

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
**A:** Because the Windows executable is not currently code-signed. This means Windows SmartScreen may warn that the publisher is unverified. The tool is safe to run – to proceed, click “More info” then “Run anyway.” In enterprise environments, you might need to adjust SmartScreen or antivirus settings to allow unsigned binaries.

**Q: How do I run the macOS binary if Gatekeeper blocks it?**
**A:** macOS may prevent the app from running since Apple has not notarized it. You can right-click the binary, select “Open,” then confirm you want to run it. Or, open **System Preferences → Security & Privacy** and click “Open Anyway” after trying to run the app. As a third option, run `chmod +x` on the file and use `xattr -d com.apple.quarantine` to remove the quarantine attribute, then execute it from Terminal. After the first run, it shouldn’t prompt again.

**Q: Does the Linux binary work on all distributions?**
**A:** The pre-built binary should run on most modern Linux systems with a glibc version comparable to the build environment. It’s been tested on Ubuntu, Debian, Fedora, Kali, etc. If you get errors about “GLIBC\_XX not found” on an older distro, the binary is incompatible with your system’s C library – in that case, you can compile DNS Tool from source on that machine, or upgrade to a newer OS.

**Q: Do I need to install anything to make the arrow-key history and colored output work?**
**A:** No. DNS Tool bundles the needed libraries (like `prompt_toolkit` for interactive history) into a single binary. The arrow-key command recall works out-of-the-box, saving history to `~/.domain_history_rdap_interactive`. Colored output should work in any modern terminal; if you’re using Windows CMD and don’t see colors, try PowerShell or Windows Terminal with ANSI color support.

**Q: Can I check dozens or hundreds of domains at once?**
**A:** Yes, using the batch modes described above. There isn’t a hard-coded domain limit. For huge lists, the main consideration is time and output volume – each domain’s check involves multiple DNS queries (and some HTTPS queries for things like MTA-STS), so scanning hundreds of domains will take longer. It may be wise to break extensive sets into chunks or run multiple instances in parallel (keeping an eye on not exceeding your network’s query rate limits). In most cases, checking a few dozen domains serially is quite feasible.

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for the full text.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an Issue on GitHub. Pull requests are encouraged for any improvements or fixes. When contributing code, please test your changes on Linux, macOS, and Windows if possible to ensure cross-platform compatibility.  
Together, we can make DNS Tool even better for the community.
