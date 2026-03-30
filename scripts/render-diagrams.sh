#!/usr/bin/env bash
set -euo pipefail

DIAGRAMS_DIR="docs/diagrams"
OUTPUT_DIR="static/images/diagrams"
CONFIG_FILE="docs/diagrams/mermaid-config.json"

mkdir -p "$OUTPUT_DIR"

if ! command -v mmdc &> /dev/null; then
    echo "mermaid-cli (mmdc) not found. Install with: npm install -g @mermaid-js/mermaid-cli"
    echo "Alternatively, run on a machine with puppeteer support."
    exit 1
fi

for mmd_file in "$DIAGRAMS_DIR"/*.mmd; do
    name=$(basename "$mmd_file" .mmd)
    svg_file="$OUTPUT_DIR/$name.svg"
    echo "Rendering $name..."
    mmdc -i "$mmd_file" -o "$svg_file" -t dark -b "#0c1018" -c "$CONFIG_FILE" 2>/dev/null
    echo "  -> $svg_file"
done

echo "Done. Rendered $(ls "$OUTPUT_DIR"/*.svg 2>/dev/null | wc -l) diagrams."
