# DNS Tool

DNS Tool is an all-in-one, command-line DNS and email security checker, built to simplify the process of verifying critical DNS records like DMARC, SPF, DKIM, DNSSEC, and more. Designed for network administrators, security researchers, and IT professionals, this tool provides real-time feedback on DNS configurations and offers in-depth analysis to strengthen email security and prevent spoofing. Perfect for securing your domain’s DNS infrastructure and achieving best practices in email authentication.

## Why DNS Tool Exists

I’ve always said:

> **“If your DMARC says p=none, your work’s not done—get to p=reject!”**

That succinctly captures why email security is so critical. It’s one thing to see a DMARC record, but it’s another to ensure it enforces protection. Too many domains sit with `p=none`, which doesn’t actually stop spoofing—it only reports it. Meanwhile, `p=reject` actively blocks spoofed emails.

While participating with CISA’s cyber hygiene program and learning best practices, I discovered the tremendous importance of DMARC—especially for American infrastructure. But that was just one piece of the DNS puzzle. I needed to verify SPF was correct, DKIM selectors existed, DNSSEC was enabled, MTA-STS was present, and so on.

Back then, I had to hop between several separate DNS tools:

- One for SPF lookups.
- Another for DMARC checks.
- A third for DKIM record validation.
- Another for DNSSEC, TLSA, CAA, and so forth.

It was time-consuming and error-prone—especially if I needed to see DNS changes “live” as they propagated. Checking each record across multiple tools became a daily routine of copying and pasting domain names.

## One Tool to Check Them All

That’s why **DNS Tool** (originally called **DNS Scout**) was born:

- A single script to see all key DNS records at once: **NS, A/AAAA, MX, TXT, SPF, DMARC, DKIM, DANE, BIMI, DNSSEC, CAA, SOA, PTR**—plus RDAP and a WHOIS fallback for registrar info.
- Colorful output to highlight missing records or outdated policies.
- Immediate feedback when you correct your DNS settings and re-run checks.

Now, whether I’m verifying a domain has `p=reject` for DMARC or ensuring MTA-STS is properly configured, I can run one command (or open one interactive prompt) and see everything. That’s the power of **DNS Tool**—born out of necessity, to unify the multiple DNS checks I performed every day.

In short: I was tired of flipping between a half-dozen DNS utilities, so I built one that does it all, with just a single command.
### Example Output

This is an example of the output you can expect when running `dnstool`:
A  purposefully horrible domain dns record monstrico.com
![Example Output](Screenshot-Output.png)
![Example Output](Screenshot-Output2.png)

A Correct domain:

![Example Output](Screenshot-Output3.png)

The output highlights key DNS and email security checks, such as missing SPF records and invalid DMARC policies.

#### DNS Tool (Python Edition)

A powerful, all-in-one DNS diagnostic and RDAP lookup utility, with:

- **Interactive Mode** (arrow-key history built-in via prompt_toolkit).
- **Batch Mode** (pass domains as arguments or via a file).
- Checks for:
  - NS, A/AAAA, MX, TXT, SPF, DMARC, DKIM, MTA-STS, DANE, BIMI, DNSSEC, CAA, SOA, PTR.
  - RDAP + WHOIS fallback for registrar info.
- Colorful output with ✅, ❌, ⚠️ to highlight issues and best-practice suggestions.

This tool bundles Python dependencies (dnspython, requests, etc.) into a **single binary** via PyInstaller—no separate Python install needed.

---

##### Download & Run

###### Linux

1. **Download** the `dnstool` binary from the [GitHub Releases](../../releases).
2. **Make the binary executable**:
   ```bash
   chmod +x dnstool
   ```
   Run the tool:
   ```bash
   ./dnstool
   ```
   Optional: Move the binary to a directory in your `PATH` (e.g., `/usr/local/bin`) to run it from anywhere:
   ```bash
   sudo mv dnstool /usr/local/bin
   ```
   Now, you should be able to run `dnstool` directly from any directory without having to prefix it with `./`.

####### macOS
Download the dnstool_macos (or similarly named) file from Releases.
By default, macOS Gatekeeper may block it (since it’s unsigned). Two ways to allow it:

GUI method:

In Finder, Right-click the file → Open.
You’ll see a warning: “cannot be opened because the developer cannot be verified.”
Click Open Anyway.
Alternatively, go to System Preferences → Security & Privacy → General and click Allow Anyway for dnstool_macos.
Terminal method:
```bash
chmod +x dnstool_macos
xattr -r -d com.apple.quarantine ./dnstool_macos
./dnstool_macos
```
That's it! Arrow-key history and color output should work just like Linux.

######## Windows
Download the dnstool.exe from Releases.
Run the .exe binary in Command Prompt / PowerShell:
```powershell
.\dnstool.exe
```
Because it’s not code-signed, Windows SmartScreen may show “Publisher cannot be verified.” Click More info → Run anyway.

######### Usage
Interactive Mode
Just run dnstool (or the .exe/macOS binary with no arguments):
```bash
./dnstool
```
You’ll see:
```text
Interactive Mode. Type a domain and press Enter to run checks immediately.
Type 'exit' or press Enter on a blank line to quit.
```

Domain:
Type any domain (e.g., example.com), press Enter, and DNS Tool will run a comprehensive set of checks (NS, MX, SPF, DMARC, etc.) and show color-coded results.

Arrow keys work for recalling previously typed domains (thanks to prompt_toolkit). On macOS Terminal or Linux, you should see a bold “Domain:” prompt with ANSI colors.

Batch Mode (Command-line arguments)
You can pass one or more domain names on the command line:

```bash
./dnstool example.com example.org
```
DNS Tool will run checks for each domain in turn.

File Input
Use -f <file> to read domains from a file (one domain per line):

```bash
./dnstool -f domains.txt
```
DNS Tool reads those domains and runs checks in sequence.

Verbose/Debug
Add -v to see debug messages:

```bash
./dnstool -v example.com
```
You’ll get extra [DEBUG] lines (like which RDAP endpoints it tries, DNS query timeouts, etc.).

######### Help/Usage
```bash
./dnstool -h
```
Prints a short usage message:
```text
usage: dnstool.py [-v] [-f file] [domain1 domain2 ...]
```
Building From Source
If you don’t want to download the precompiled binaries, you can build it yourself:

Install Python 3.7+ (system-wide).
Clone this repo:
```bash
git clone https://github.com/<your-username>/dns-tool.git
cd dns-tool
```
Install dependencies in a virtual environment (versions pinned in `requirements.txt`):
```bash
python3 -m venv buildenv
source buildenv/bin/activate
 pip install pyinstaller \
   dnspython>=2.4,<3.0 \
   requests>=2.31,<3.0 \
   idna>=3.3,<4.0 \
   prompt_toolkit>=3.0,<4.0
```
Compile:
```bash
pyinstaller --onefile dnstool.py
```
The final binary is in dist/dnstool (or dnstool.exe on Windows).

### Running Tests

Unit tests are written with `pytest`. After installing the dependencies and
`pytest`, execute the test suite from the project root:

```bash
pytest
```

FAQ
1. Why is Windows complaining about an unknown publisher?

Because we’re not code-signing the .exe. We’re currently not able to afford a code-signing certificate. You can still run it by clicking “More info → Run anyway.”

2. macOS says “cannot be opened because developer cannot be verified.”

Yes, same reason—no code signing or notarization. Use “System Preferences → Security & Privacy → General → Open Anyway” or xattr -d com.apple.quarantine ./dnstool_macos.

3. Does the Linux binary work on all distros?

It should work on most recent distros with glibc >= the version in our build environment. On older systems, you may see “GLIBC_2.X not found.” In that case, build from source on your own system.

4. Does arrow-key history require anything special?

No, we’ve embedded prompt_toolkit inside the compiled binary. It “just works.” Commands typed are saved to ~/.domain_history_rdap_interactive.

License
Apache License 2.0

Copyright 2025 Carey James Balboa

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Contributing
Bug reports: Please open an Issue if you spot any problems or have feature requests.
Pull requests: Always welcome. Test on your OS (Linux, macOS, Windows) if possible.
