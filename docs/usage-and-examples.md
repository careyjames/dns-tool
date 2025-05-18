# Usage and Examples

This guide will show you how to get started with DNS Tool. It will showcase how to use the tool in both interactive and batch modes, with example commands and output descriptions.

## Interactive Mode 🌟

Interactive mode is straightforward to use. To enter this mode, run the following command:

```bash
./dnstool
```

You’ll see a prompt where you can enter a domain, press Enter, and DNS Tool will perform a DNS check. 

The output is color-coded: ✅ for success, ❌ for failure, and ⚠️ for warnings.

### Example Command
Run `./dnstool` to start the interactive mode:
```bash
./dnstool
```

Then just enter a domain:

```
Domain:
example.com
```

You will then get color-coded output, such as:
```
✅ NS: OK
❌ SPF: Missing
⚠️ DMARC: p=none
```

This design can help to quickly spot configuration issues.

## Batch Mode 🚀

Batch mode allows you to check multiple domains simultaneously. Provide domain names as command-line arguments or via a file.

### Direct Command-line Arguments

```bash
./dnstool example.com example.org
```

### File Input

```bash
./dnstool -f domains.txt
```

This mode is ideal for managing multiple domains or integrating checks into workflows.

## Verbose Output 🛠️

For detailed insights, use the `-v` flag for verbose output.

```bash
./dnstool -v example.com
```

This provides detailed debug information, useful for troubleshooting or understanding the tool’s processes.

For full details and features, refer to the main documentation [here](https://github.com/careyjames/dns-tool).
