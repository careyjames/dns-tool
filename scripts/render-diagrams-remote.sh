#!/usr/bin/env bash
set -euo pipefail

DIAGRAMS_DIR="docs/diagrams"
OUTPUT_DIR="static/images/diagrams"
THEME="dark"
BG_COLOR="0c1018"

mkdir -p "$OUTPUT_DIR"

rendered=0
failed=0

for mmd_file in "$DIAGRAMS_DIR"/*.mmd; do
    [ -f "$mmd_file" ] || continue
    name=$(basename "$mmd_file" .mmd)
    svg_file="$OUTPUT_DIR/$name.svg"

    encoded=$(cat "$mmd_file" | base64 -w0)
    url="https://mermaid.ink/svg/${encoded}?bgColor=!${BG_COLOR}&theme=${THEME}"

    echo -n "Rendering $name..."
    http_code=$(curl -s -o "$svg_file" -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [ "$http_code" = "200" ] && grep -q '<svg' "$svg_file" 2>/dev/null; then
        echo " OK ($svg_file)"
        rendered=$((rendered + 1))
    else
        echo " FAILED (HTTP $http_code)"
        rm -f "$svg_file"
        failed=$((failed + 1))
    fi
done

echo ""
echo "Done. Rendered: $rendered, Failed: $failed"
[ "$failed" -eq 0 ] || exit 1
