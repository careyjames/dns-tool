# Building DNS Tool from Source

## Prerequisites

- **Go 1.25+** — [https://go.dev/dl/](https://go.dev/dl/)
- **Git** — to clone the repository

## Quick Start

```bash
git clone https://github.com/IT-Help-San-Diego/dns-tool.git
cd dns-tool
go build ./go-server/cmd/server
```

The resulting `server` binary is the DNS Tool web server.

## Build Variants

DNS Tool uses Go build tags to control feature tiers:

- **Default build**: `go build ./go-server/cmd/server`
  - Uses `_oss.go` stub files that provide safe default implementations
  - All core DNS analysis functionality works
  - Confidence scoring, report generation, and web UI are fully functional

- **Intel build** (extended intelligence): `go build -tags intel ./go-server/cmd/server`
  - Activates `_intel.go` files with additional intelligence modules
  - Adds provider detection databases, infrastructure classification, and AI surface scanning
  - Not required for core functionality

## Running

```bash
# Set required environment variables
export PORT=5000

# Start the server
./server
```

The server will be available at `http://localhost:5000`.

## Verifying Your Build

After building, verify the binary works:

```bash
./server --version
```

## Reproducibility

Each tagged release on GitHub corresponds to a Zenodo archive
(DOI: [10.5281/zenodo.18854899](https://doi.org/10.5281/zenodo.18854899)).

The Zenodo archive contains the complete OSS source code including
all `_oss.go` build-tag stubs required for compilation. Scientists
can reproduce builds from any archived version.
