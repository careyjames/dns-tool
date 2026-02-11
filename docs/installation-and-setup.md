## docs/installation-and-setup.md

# Installation and Setup

> **Legacy CLI install guide**
>
> This page is for the command-line release line.
>
> For the current primary experience, use the web app (no install): https://dnstool.it-help.tech/

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
