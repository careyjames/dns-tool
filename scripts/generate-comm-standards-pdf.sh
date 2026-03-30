#!/bin/bash
# Generate the Communication Standards PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-comm-standards-pdf.sh [VERSION]
#
# If VERSION is provided, updates the version in the HTML before
# generating the PDF. If omitted, generates from current content.
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-signature.png (Owl of Athena)
#
# This MUST be run after every edit to docs/communication-standards.html

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"

if [ -n "$VERSION" ]; then
  echo "Updating communication standards version to ${VERSION}..."

  sed -i -E "s/Version<\/span>\&ensp;[0-9]+\.[0-9]+\.[0-9]+/Version<\/span>\&ensp;${VERSION}/" docs/communication-standards.html
  sed -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version ${VERSION}/" docs/COMMUNICATION_STANDARDS.md

  echo "Version updated in .html and .md"
fi

echo "Generating Communication Standards PDF..."
python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/communication-standards.html', base_url='docs/')
html.write_pdf('docs/communication-standards.pdf')
"

cp docs/communication-standards.pdf static/docs/communication-standards.pdf
cp docs/communication-standards.pdf go-server/static/docs/communication-standards.pdf

SIZE=$(stat -f%z docs/communication-standards.pdf 2>/dev/null || stat -c%s docs/communication-standards.pdf 2>/dev/null)
echo "PDF generated: docs/communication-standards.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/communication-standards.pdf"
echo "Copied to:     go-server/static/docs/communication-standards.pdf"

if [ ! -s docs/communication-standards.pdf ]; then
  echo "ERROR: docs/communication-standards.pdf is empty or missing"
  exit 1
fi
if [ ! -s static/docs/communication-standards.pdf ]; then
  echo "ERROR: static/docs/communication-standards.pdf is empty or missing"
  exit 1
fi
if [ ! -s go-server/static/docs/communication-standards.pdf ]; then
  echo "ERROR: go-server/static/docs/communication-standards.pdf is empty or missing"
  exit 1
fi

echo "Done."
