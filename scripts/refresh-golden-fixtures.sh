#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/golden_fixtures"
MANIFEST="$FIXTURES_DIR/manifest.json"
SERVER_URL="${DNS_TOOL_URL:-http://localhost:5000}"
DB_URL="${DATABASE_URL:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[refresh]${NC} $*"; }
ok()   { echo -e "${GREEN}[  ok  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ warn ]${NC} $*"; }
err()  { echo -e "${RED}[error ]${NC} $*"; }

if [ ! -f "$MANIFEST" ]; then
    err "Manifest not found: $MANIFEST"
    exit 1
fi

DOMAINS=$(python3 -c "import json,sys; m=json.load(open('$MANIFEST')); print('\n'.join(m['domains']))")
OLD_CAPTURED_AT=$(python3 -c "import json; m=json.load(open('$MANIFEST')); print(m.get('captured_at','unknown'))")
DOMAIN_COUNT=$(echo "$DOMAINS" | wc -l | tr -d ' ')

log "Golden Fixture Refresh"
log "Manifest: $MANIFEST"
log "Domains:  $DOMAIN_COUNT"
log "Old captured_at: $OLD_CAPTURED_AT"
log "Server: $SERVER_URL"
echo ""

refresh_via_api() {
    local domain="$1"
    local fixture_file="$2"

    log "Triggering fresh analysis for $domain ..."
    local analyze_response
    analyze_response=$(curl -s -w "\n%{redirect_url}\n%{http_code}" \
        -L -o /dev/null \
        --max-time 120 \
        "${SERVER_URL}/analyze?domain=${domain}" 2>/dev/null) || true

    local analysis_id
    analysis_id=$(curl -s -o /dev/null -w "%{redirect_url}" \
        --max-time 120 \
        "${SERVER_URL}/analyze?domain=${domain}" 2>/dev/null \
        | grep -oE '/analysis/([0-9]+)' \
        | grep -oE '[0-9]+' | head -1) || true

    if [ -z "$analysis_id" ]; then
        warn "Could not extract analysis ID for $domain from redirect"
        return 1
    fi

    log "Got analysis ID: $analysis_id for $domain"

    local api_response
    api_response=$(curl -s --max-time 30 \
        "${SERVER_URL}/api/analysis/${analysis_id}" 2>/dev/null) || true

    if [ -z "$api_response" ]; then
        warn "Empty API response for $domain (ID: $analysis_id)"
        return 1
    fi

    local full_results
    full_results=$(echo "$api_response" | python3 -c "
import json, sys
data = json.load(sys.stdin)
fr = data.get('full_results')
if fr:
    print(json.dumps(fr, indent=2, sort_keys=False))
else:
    print(json.dumps(data, indent=2, sort_keys=False))
" 2>/dev/null) || true

    if [ -z "$full_results" ] || [ "$full_results" = "null" ]; then
        warn "No full_results in API response for $domain"
        return 1
    fi

    echo "$full_results" > "$fixture_file"
    return 0
}

refresh_via_db() {
    local domain="$1"
    local fixture_file="$2"

    if [ -z "$DB_URL" ]; then
        warn "DATABASE_URL not set — cannot query database directly"
        return 1
    fi

    log "Querying database for latest analysis of $domain ..."

    local full_results
    full_results=$(psql "$DB_URL" -t -A -c "
        SELECT full_results FROM domain_analyses
        WHERE ascii_domain = '${domain}'
          AND analysis_success = TRUE
          AND full_results IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1;
    " 2>/dev/null) || true

    if [ -z "$full_results" ] || [ "$full_results" = "null" ]; then
        warn "No results in database for $domain"
        return 1
    fi

    echo "$full_results" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(json.dumps(data, indent=2, sort_keys=False))
" > "$fixture_file"

    return 0
}

domain_to_filename() {
    local domain="$1"
    echo "${domain//./_}.json"
}

count_keys() {
    local file="$1"
    if [ -f "$file" ]; then
        python3 -c "import json; print(len(json.load(open('$file')).keys()))" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

SUMMARY=()
SUCCESS_COUNT=0
FAIL_COUNT=0
NEW_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

for domain in $DOMAINS; do
    fixture_filename=$(domain_to_filename "$domain")
    fixture_path="$FIXTURES_DIR/$fixture_filename"

    old_key_count=$(count_keys "$fixture_path")

    log "--- $domain ---"

    refreshed=false

    if [ -n "$DB_URL" ]; then
        if refresh_via_db "$domain" "$fixture_path"; then
            refreshed=true
        fi
    fi

    if [ "$refreshed" = false ]; then
        if refresh_via_api "$domain" "$fixture_path"; then
            refreshed=true
        fi
    fi

    new_key_count=$(count_keys "$fixture_path")

    if [ "$refreshed" = true ]; then
        diff_count=$((new_key_count - old_key_count))
        if [ $diff_count -ge 0 ]; then
            diff_display="+${diff_count}"
        else
            diff_display="${diff_count}"
        fi
        ok "$domain: refreshed (keys: $old_key_count -> $new_key_count, diff: $diff_display)"
        SUMMARY+=("$domain | $OLD_CAPTURED_AT | $NEW_TIMESTAMP | $diff_display keys")
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        err "$domain: FAILED to refresh"
        SUMMARY+=("$domain | $OLD_CAPTURED_AT | FAILED | -")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    echo ""
done

python3 -c "
import json, sys

manifest_path = '$MANIFEST'
new_timestamp = '$NEW_TIMESTAMP'

with open(manifest_path, 'r') as f:
    manifest = json.load(f)

manifest['captured_at'] = new_timestamp

with open(manifest_path, 'w') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
"

echo ""
log "========================================="
log "  Golden Fixture Refresh Summary"
log "========================================="
printf "%-30s | %-24s | %-24s | %s\n" "Domain" "Old Capture" "New Capture" "Diff"
printf "%-30s-+-%-24s-+-%-24s-+-%s\n" "------------------------------" "------------------------" "------------------------" "----------"
for line in "${SUMMARY[@]}"; do
    IFS='|' read -ra parts <<< "$line"
    printf "%-30s | %-24s | %-24s | %s\n" "${parts[0]}" "${parts[1]}" "${parts[2]}" "${parts[3]}"
done
echo ""
ok "Success: $SUCCESS_COUNT / $DOMAIN_COUNT"
if [ $FAIL_COUNT -gt 0 ]; then
    warn "Failed:  $FAIL_COUNT / $DOMAIN_COUNT"
fi
log "Manifest updated: $MANIFEST"
log "New captured_at: $NEW_TIMESTAMP"
