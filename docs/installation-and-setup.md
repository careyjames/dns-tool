# Installation and Setup

Welcome to the **Installation and Setup** guide for the DNS Tool, a command-line utility for DNS and email security validation. Follow these steps to get DNS Tool running on your Linux, macOS, or Windows machine.

## Linux 

1. **Download** the `dnstool` binary from the [GitHub Releases](https://github.com/careyjames/dns-tool/releases).
2. **Make the binary executable**:  
   ```bash
   chmod +x dnstool
   ```
3. **Run the tool**:  
   ```bash
   ./dnstool
   ```
4. Optional: Move the binary to a directory in your PATH:  
   ```bash
   sudo mv dnstool /usr/local/bin
   ```

## macOS

1. **Download** `dnstool_macos` from the [Releases](https://github.com/careyjames/dns-tool/releases).
2. **Allow execution** via Terminal:  
   ```bash
   chmod +x dnstool_macos
   xattr -r -d com.apple.quarantine ./dnstool_macos
   ```
3. **Run**:  
   ```bash
   ./dnstool_macos
   ```

Alternatively, right-click in Finder → Open → Click Open Anyway via Security & Privacy settings.

## Windows

1. **Download** `dnstool.exe` from the [Releases](https://github.com/careyjames/dns-tool/releases).
2. **Execute** in Command Prompt / PowerShell:  
   ```powershell
   .\dnstool.exe
   ```
3. If warned by SmartScreen, click "More info → Run anyway."

You are now ready to use DNS Tool, see the [Getting Started guide](/dns-tool/usage-and-examples.html) for next steps.
