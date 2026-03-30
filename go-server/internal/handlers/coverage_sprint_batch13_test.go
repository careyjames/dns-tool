package handlers

import (
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/icuae"

        "github.com/jackc/pgx/v5/pgtype"
)

func TestRiskColorToHex_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"success", hexGreen},
                {"warning", hexYellow},
                {"danger", colorDanger},
                {"unknown", colorGrey},
                {"", colorGrey},
        }
        for _, tc := range cases {
                if got := riskColorToHex(tc.in); got != tc.want {
                        t.Errorf("riskColorToHex(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestNormalizeRiskColor_B13(t *testing.T) {
        cases := []struct{ label, color, want string }{
                {"Low Risk", "success", "success"},
                {"Medium Risk", "warning", "warning"},
                {"High Risk", "danger", "danger"},
                {"Low Risk", "", "success"},
                {"Medium Risk", "", "warning"},
                {"High Risk", "", "danger"},
                {"Critical Risk", "", "danger"},
                {"Unknown", "", ""},
                {"Unknown", "custom", "custom"},
        }
        for _, tc := range cases {
                if got := normalizeRiskColor(tc.label, tc.color); got != tc.want {
                        t.Errorf("normalizeRiskColor(%q,%q)=%q want %q", tc.label, tc.color, got, tc.want)
                }
        }
}

func TestReportRiskColor_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"success", "#198754"},
                {"warning", "#ffc107"},
                {"danger", "#dc3545"},
                {"other", colorGrey},
        }
        for _, tc := range cases {
                if got := reportRiskColor(tc.in); got != tc.want {
                        t.Errorf("reportRiskColor(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestScotopicRiskColor_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"success", hexScGreen},
                {"warning", hexScYellow},
                {"danger", hexScRed},
                {"other", "#9C7645"},
        }
        for _, tc := range cases {
                if got := scotopicRiskColor(tc.in); got != tc.want {
                        t.Errorf("scotopicRiskColor(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestRiskColorToShields_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"success", "brightgreen"},
                {"warning", "yellow"},
                {"danger", "red"},
                {"other", mapKeyLightgrey},
        }
        for _, tc := range cases {
                if got := riskColorToShields(tc.in); got != tc.want {
                        t.Errorf("riskColorToShields(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestCovertRiskLabel_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"Low Risk", "Hardened"},
                {"Medium Risk", "Partial"},
                {"High Risk", "Exposed"},
                {"Critical Risk", "Wide Open"},
                {"Unknown", "Unknown"},
        }
        for _, tc := range cases {
                if got := covertRiskLabel(tc.in); got != tc.want {
                        t.Errorf("covertRiskLabel(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestCovertTagline_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"Low Risk", "Good luck with that."},
                {"Medium Risk", "Gaps in the armor."},
                {"High Risk", "Door's open."},
                {"Critical Risk", "Free real estate."},
                {"Unknown", ""},
        }
        for _, tc := range cases {
                if got := covertTagline(tc.in); got != tc.want {
                        t.Errorf("covertTagline(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestRiskBorderColor_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"success", "#238636"},
                {"warning", "#9e6a03"},
                {"danger", "#da3633"},
                {"other", hexDimGrey},
        }
        for _, tc := range cases {
                if got := riskBorderColor(tc.in); got != tc.want {
                        t.Errorf("riskBorderColor(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestCountMissing_B13(t *testing.T) {
        nodes := []protocolNode{
                {status: "success"},
                {status: "missing"},
                {status: "error"},
                {status: "warning"},
        }
        if got := countMissing(nodes); got != 2 {
                t.Errorf("countMissing got %d want 2", got)
        }
        if got := countMissing(nil); got != 0 {
                t.Errorf("countMissing(nil) got %d want 0", got)
        }
}

func TestCountVulnerable_B13(t *testing.T) {
        nodes := []protocolNode{
                {status: "success"},
                {status: "warning"},
                {status: "missing"},
                {status: "error"},
        }
        if got := countVulnerable(nodes); got != 2 {
                t.Errorf("countVulnerable got %d want 2", got)
        }
}

func TestCovertStatusPrefix_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"success", "[+]"},
                {"warning", "[~]"},
                {"error", "[-]"},
                {"missing", "[-]"},
                {"", "[-]"},
        }
        for _, tc := range cases {
                if got := covertStatusPrefix(tc.in); got != tc.want {
                        t.Errorf("covertStatusPrefix(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestCovertSeverityTag_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"critical", " [CRITICAL]"},
                {"high", " [HIGH]"},
                {"medium", ""},
                {"", ""},
        }
        for _, tc := range cases {
                if got := covertSeverityTag(tc.in); got != tc.want {
                        t.Errorf("covertSeverityTag(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestCovertPrefixColor_B13(t *testing.T) {
        dim := "#111"
        sRed := "#222"
        alt := "#333"
        cases := []struct{ prefix, want string }{
                {"[+]", dim},
                {"[~]", "#8a8a00"},
                {"[-]", "#7a2419"},
                {"[!!]", sRed},
                {"[!]", sRed},
                {"", alt},
        }
        for _, tc := range cases {
                if got := covertPrefixColor(tc.prefix, dim, sRed, alt); got != tc.want {
                        t.Errorf("covertPrefixColor(%q)=%q want %q", tc.prefix, got, tc.want)
                }
        }
}

func TestCovertProtocolLine_B13(t *testing.T) {
        line := covertProtocolLine("SPF", "success")
        if line.prefix != "[+]" {
                t.Errorf("expected [+] prefix, got %q", line.prefix)
        }
        if line.desc != "can't forge sender envelope" {
                t.Errorf("unexpected desc: %q", line.desc)
        }

        line = covertProtocolLine("DKIM", "warning")
        if line.prefix != "[~]" {
                t.Errorf("expected [~] prefix, got %q", line.prefix)
        }
        if line.desc != "weak key — forgery harder" {
                t.Errorf("unexpected desc: %q", line.desc)
        }

        line = covertProtocolLine("UNKNOWN_PROTO", "error")
        if line.prefix != "[?]" {
                t.Errorf("expected [?] for unknown proto, got %q", line.prefix)
        }
}

func TestCovertExposureLines_Nil_B13(t *testing.T) {
        e := exposureData{status: "clear", findingCount: 0}
        if lines := covertExposureLines(e, "", "", "", 0); lines != nil {
                t.Errorf("expected nil for clear exposure, got %d lines", len(lines))
        }
}

func TestCovertExposureLines_Exposed_B13(t *testing.T) {
        e := exposureData{
                status:       "exposed",
                findingCount: 2,
                findings: []exposureFinding{
                        {findingType: "AWS Key", severity: "critical", redacted: "AKIA...1234"},
                        {findingType: "Token", severity: "high", redacted: "ghp_abcdef0123456789abcdef0"},
                },
        }
        lines := covertExposureLines(e, "#f00", "#aaa", "https://dns.example.com", 42)
        if len(lines) < 5 {
                t.Fatalf("expected >= 5 lines, got %d", len(lines))
        }
        found := false
        for _, l := range lines {
                if strings.Contains(l.text, "2 credentials found") {
                        found = true
                }
        }
        if !found {
                t.Error("expected exposure count in lines")
        }
}

func TestCovertSummaryLines_AllHardened_B13(t *testing.T) {
        lines := covertSummaryLines(covertSummaryParams{vulnerable: 0, findingCount: 0, tagline: "Good luck.", locked: "#aaa", dimLocked: "#bbb", sRed: "#ccc", alt: "#ddd"})
        if len(lines) != 2 {
                t.Fatalf("expected 2 lines, got %d", len(lines))
        }
        if !strings.Contains(lines[0].text, "hardened") {
                t.Errorf("expected hardened, got %q", lines[0].text)
        }
}

func TestCovertSummaryLines_SecretsLeaking_B13(t *testing.T) {
        lines := covertSummaryLines(covertSummaryParams{vulnerable: 0, findingCount: 3, tagline: "", locked: "#aaa", dimLocked: "#bbb", sRed: "#ccc", alt: "#ddd"})
        if len(lines) != 2 {
                t.Fatalf("expected 2 lines, got %d", len(lines))
        }
        if !strings.Contains(lines[0].text, "secrets") {
                t.Errorf("expected secrets reference, got %q", lines[0].text)
        }
}

func TestCovertSummaryLines_Vulnerable_B13(t *testing.T) {
        lines := covertSummaryLines(covertSummaryParams{vulnerable: 5, findingCount: 0, tagline: "Door's open.", locked: "#aaa", dimLocked: "#bbb", sRed: "#ccc", alt: "#ddd"})
        if len(lines) < 1 {
                t.Fatal("expected at least 1 line")
        }
        if !strings.Contains(lines[0].text, "5 of 10") {
                t.Errorf("expected 5 of 10, got %q", lines[0].text)
        }
}

func TestCovertSummaryLines_FewVectors_B13(t *testing.T) {
        lines := covertSummaryLines(covertSummaryParams{vulnerable: 1, findingCount: 1, tagline: "", locked: "#aaa", dimLocked: "#bbb", sRed: "#ccc", alt: "#ddd"})
        if len(lines) < 1 {
                t.Fatal("expected at least 1 line")
        }
        if !strings.Contains(lines[0].text, "2 attack vectors") {
                t.Errorf("expected 2 attack vectors, got %q", lines[0].text)
        }
}

func TestExtractPostureRisk_B13(t *testing.T) {
        label, color := extractPostureRisk(nil)
        if label != "Unknown" || color != "" {
                t.Errorf("nil: got %q,%q", label, color)
        }

        label, color = extractPostureRisk(map[string]any{})
        if label != "Unknown" {
                t.Errorf("empty: got %q", label)
        }

        label, color = extractPostureRisk(map[string]any{
                "posture": map[string]any{"label": "Low Risk", "color": "success"},
        })
        if label != "Low Risk" || color != "success" {
                t.Errorf("posture: got %q,%q", label, color)
        }

        label, _ = extractPostureRisk(map[string]any{
                "posture": map[string]any{"grade": "A+"},
        })
        if label != "A+" {
                t.Errorf("grade fallback: got %q", label)
        }
}

func TestUnmarshalResults_B13(t *testing.T) {
        if got := unmarshalResults(nil, "test"); got != nil {
                t.Error("expected nil for empty input")
        }
        if got := unmarshalResults([]byte("not json"), "test"); got != nil {
                t.Error("expected nil for invalid json")
        }
        got := unmarshalResults([]byte(`{"key":"val"}`), "test")
        if got == nil || got["key"] != "val" {
                t.Error("expected parsed result")
        }
}

func TestBadgeSVG_B13(t *testing.T) {
        svg := badgeSVG("DNS Tool", "Low Risk", "#4c1")
        s := string(svg)
        if !strings.Contains(s, "<svg") {
                t.Error("expected SVG output")
        }
        if !strings.Contains(s, "DNS Tool") {
                t.Error("expected label in SVG")
        }
        if !strings.Contains(s, "Low Risk") {
                t.Error("expected value in SVG")
        }
}

func TestProtocolGroupColor_B13(t *testing.T) {
        cases := []struct{ abbrev, want string }{
                {"SPF", "#4fc3f7"},
                {"DKIM", "#4fc3f7"},
                {protoDMARC, "#4fc3f7"},
                {protoDNSSEC, "#ffb74d"},
                {"CAA", "#ffb74d"},
                {"DANE", "#81c784"},
                {protoMTASTS, "#81c784"},
                {protoTLSRPT, "#81c784"},
                {"BIMI", "#ce93d8"},
                {"OTHER", "#484f58"},
        }
        for _, tc := range cases {
                if got := protocolGroupColor(tc.abbrev); got != tc.want {
                        t.Errorf("protocolGroupColor(%q)=%q want %q", tc.abbrev, got, tc.want)
                }
        }
}

func TestProtocolStatusToNodeColor_B13(t *testing.T) {
        gc := "#4fc3f7"
        if got := protocolStatusToNodeColor("success", gc); got != gc {
                t.Errorf("success: got %q want %q", got, gc)
        }
        if got := protocolStatusToNodeColor("warning", gc); got != hexYellow {
                t.Errorf("warning: got %q want %q", got, hexYellow)
        }
        if got := protocolStatusToNodeColor("error", gc); got != hexRed {
                t.Errorf("error: got %q want %q", got, hexRed)
        }
        if got := protocolStatusToNodeColor("missing", gc); got != hexDimGrey {
                t.Errorf("missing: got %q want %q", got, hexDimGrey)
        }
}

func TestExtractProtocolIndicators_B13(t *testing.T) {
        results := map[string]any{
                "spf_analysis":  map[string]any{"status": "success"},
                "dkim_analysis": map[string]any{"status": "warning"},
        }
        nodes := extractProtocolIndicators(results)
        if len(nodes) != 10 {
                t.Fatalf("expected 10 nodes, got %d", len(nodes))
        }
        if nodes[0].status != "success" {
                t.Errorf("SPF status: got %q", nodes[0].status)
        }
        if nodes[1].status != "warning" {
                t.Errorf("DKIM status: got %q", nodes[1].status)
        }
        if nodes[2].status != "missing" {
                t.Errorf("DMARC status: got %q", nodes[2].status)
        }
}

func TestExtractExposure_B13(t *testing.T) {
        e := extractExposure(map[string]any{})
        if e.status != "clear" {
                t.Errorf("no key: got %q", e.status)
        }

        e = extractExposure(map[string]any{
                "secret_exposure": map[string]any{"status": "exposed", "finding_count": float64(2), "findings": []any{
                        map[string]any{"type": "AWS_KEY", "severity": "critical", "redacted": "AKIA..."},
                }},
        })
        if e.status != "exposed" {
                t.Errorf("exposed: got %q", e.status)
        }
        if e.findingCount != 2 {
                t.Errorf("findingCount: %d want 2", e.findingCount)
        }
        if len(e.findings) != 1 {
                t.Errorf("findings len: %d want 1", len(e.findings))
        }
}

func TestPluralS_B13(t *testing.T) {
        if got := pluralS(1); got != "" {
                t.Errorf("pluralS(1)=%q want empty", got)
        }
        if got := pluralS(0); got != "s" {
                t.Errorf("pluralS(0)=%q want s", got)
        }
        if got := pluralS(5); got != "s" {
                t.Errorf("pluralS(5)=%q want s", got)
        }
}

func TestCleanDomainInput_B13(t *testing.T) {
        cases := []struct{ in, want string }{
                {"https://example.com/path", "example.com"},
                {"http://example.com/", "example.com"},
                {"example.com", "example.com"},
                {"example.com/foo/bar", "example.com"},
        }
        for _, tc := range cases {
                if got := cleanDomainInput(tc.in); got != tc.want {
                        t.Errorf("cleanDomainInput(%q)=%q want %q", tc.in, got, tc.want)
                }
        }
}

func TestFormatHumanTTL_B13(t *testing.T) {
        cases := []struct {
                ttl  uint32
                want string
        }{
                {86400, "1 day"},
                {172800, "2 days"},
                {3600, "1 hour"},
                {7200, "2 hours"},
                {60, "1 minute"},
                {300, "5 minutes"},
                {30, "30 seconds"},
                {1, "1 seconds"},
        }
        for _, tc := range cases {
                if got := formatHumanTTL(tc.ttl); got != tc.want {
                        t.Errorf("formatHumanTTL(%d)=%q want %q", tc.ttl, got, tc.want)
                }
        }
}

func TestTtlForProfile_B13(t *testing.T) {
        if got := ttlForProfile("A", "stability"); got != 3600 {
                t.Errorf("A stability: %d want 3600", got)
        }
        if got := ttlForProfile("A", "agility"); got != 300 {
                t.Errorf("A agility: %d want 300", got)
        }
        if got := ttlForProfile("NS", "stability"); got != 86400 {
                t.Errorf("NS stability: %d want 86400", got)
        }
        if got := ttlForProfile("NS", "agility"); got != 3600 {
                t.Errorf("NS agility: %d want 3600", got)
        }
}

func TestDetermineTunerStatus_B13(t *testing.T) {
        status, class, _ := determineTunerStatus(300, 300, false, "", "stability")
        if status != "Optimal" || class != "success" {
                t.Errorf("optimal: got %q/%q", status, class)
        }

        status, class, _ = determineTunerStatus(300, 300, true, "locked reason", "stability")
        if status != "Provider-Locked" || class != "secondary" {
                t.Errorf("locked: got %q/%q", status, class)
        }

        status, class, _ = determineTunerStatus(0, 3600, false, "", "stability")
        if status != "Not Set" || class != mapKeyWarning {
                t.Errorf("not set: got %q/%q", status, class)
        }

        status, _, _ = determineTunerStatus(3000, 3600, false, "", "stability")
        if status != "Acceptable" {
                t.Errorf("acceptable: got %q", status)
        }

        status, _, _ = determineTunerStatus(86400, 3600, false, "", "stability")
        if status != "Adjust" {
                t.Errorf("high adjust: got %q", status)
        }

        status, _, _ = determineTunerStatus(60, 3600, false, "", "stability")
        if status != "Adjust" {
                t.Errorf("low adjust: got %q", status)
        }
}

func TestCalculateQueryReduction_B13(t *testing.T) {
        if got := calculateQueryReduction(0, 3600); got != "" {
                t.Errorf("zero observed: %q", got)
        }
        if got := calculateQueryReduction(3600, 0); got != "" {
                t.Errorf("zero typical: %q", got)
        }

        got := calculateQueryReduction(300, 3600)
        if !strings.Contains(got, "fewer") {
                t.Errorf("expected fewer: %q", got)
        }

        got = calculateQueryReduction(3600, 300)
        if !strings.Contains(got, "more") {
                t.Errorf("expected more: %q", got)
        }

        if got := calculateQueryReduction(3600, 3600); got != "" {
                t.Errorf("equal: expected empty, got %q", got)
        }
}

func TestBuildPropagationNote_B13(t *testing.T) {
        if got := buildPropagationNote("MX", 7200); got != "" {
                t.Errorf("MX should be empty, got %q", got)
        }
        got := buildPropagationNote("A", 7200)
        if !strings.Contains(got, "propagate") {
                t.Errorf("A high TTL: %q", got)
        }
        got = buildPropagationNote("A", 120)
        if !strings.Contains(got, "fast propagation") {
                t.Errorf("A low TTL: %q", got)
        }
        if got := buildPropagationNote("A", 1800); got != "" {
                t.Errorf("A mid TTL should be empty: %q", got)
        }
}

func TestFormatTotalReduction_B13(t *testing.T) {
        if got := formatTotalReduction(0, 100); got != "" {
                t.Errorf("zero old: %q", got)
        }
        got := formatTotalReduction(1000, 500)
        if !strings.Contains(got, "fewer") {
                t.Errorf("reduction: %q", got)
        }
        got = formatTotalReduction(500, 1000)
        if !strings.Contains(got, "more") {
                t.Errorf("increase: %q", got)
        }
}

func TestHasMigrationRecord_B13(t *testing.T) {
        records := []TTLRecordResult{
                {RecordType: "MX"},
                {RecordType: "TXT"},
        }
        if hasMigrationRecord(records) {
                t.Error("no A/AAAA should be false")
        }
        records = append(records, TTLRecordResult{RecordType: "A"})
        if !hasMigrationRecord(records) {
                t.Error("with A should be true")
        }
}

func TestBuildRoute53JSON_B13(t *testing.T) {
        got := buildRoute53JSON("A", 300)
        if !strings.Contains(got, `"Type": "A"`) {
                t.Errorf("missing Type: %q", got)
        }
        if !strings.Contains(got, `"TTL": 300`) {
                t.Errorf("missing TTL: %q", got)
        }
}

func TestMaskURL_B13(t *testing.T) {
        short := "https://a.com/hook"
        if got := maskURL(short); got != short {
                t.Errorf("short URL: got %q want %q", got, short)
        }
        long := "https://hooks.example.com/callbacks/abc123def456/notifications/XXXXXXXXXXXXXXXXXXXXXXXX"
        got := maskURL(long)
        if len(got) > 35 {
                t.Errorf("long URL not masked: %q", got)
        }
        if !strings.Contains(got, "...") {
                t.Errorf("expected ... in masked URL: %q", got)
        }
}

func TestCadenceToNextRun_B13(t *testing.T) {
        now := time.Now().UTC()
        ts := cadenceToNextRun("hourly")
        if !ts.Valid {
                t.Fatal("hourly: invalid timestamp")
        }
        diff := ts.Time.Sub(now)
        if diff < 50*time.Minute || diff > 70*time.Minute {
                t.Errorf("hourly: expected ~1h, got %v", diff)
        }

        ts = cadenceToNextRun("weekly")
        diff = ts.Time.Sub(now)
        if diff < 6*24*time.Hour || diff > 8*24*time.Hour {
                t.Errorf("weekly: expected ~7d, got %v", diff)
        }

        ts = cadenceToNextRun("unknown")
        diff = ts.Time.Sub(now)
        if diff < 23*time.Hour || diff > 25*time.Hour {
                t.Errorf("default: expected ~24h, got %v", diff)
        }
}

func TestConvertWatchlistEntries_B13(t *testing.T) {
        now := time.Now().UTC()
        entries := []dbq.DomainWatchlist{
                {
                        ID:      1,
                        Domain:  "example.com",
                        Cadence: "daily",
                        Enabled: true,
                        LastRunAt: pgtype.Timestamp{Time: now, Valid: true},
                        NextRunAt: pgtype.Timestamp{Time: now.Add(24 * time.Hour), Valid: true},
                        CreatedAt: pgtype.Timestamp{Time: now.Add(-48 * time.Hour), Valid: true},
                },
                {
                        ID:      2,
                        Domain:  "test.com",
                        Cadence: "weekly",
                        Enabled: false,
                },
        }
        items := convertWatchlistEntries(entries)
        if len(items) != 2 {
                t.Fatalf("expected 2 items, got %d", len(items))
        }
        if items[0].Domain != "example.com" || !items[0].Enabled {
                t.Errorf("item0: %+v", items[0])
        }
        if items[0].LastRunAt == "" {
                t.Error("expected LastRunAt to be formatted")
        }
        if items[1].LastRunAt != "" {
                t.Error("expected empty LastRunAt for invalid timestamp")
        }
}

func TestExtractMapSafe_B13(t *testing.T) {
        got := extractMapSafe(nil, "key")
        if len(got) != 0 {
                t.Error("nil input should return empty map")
        }
        got = extractMapSafe(map[string]any{"key": "not a map"}, "key")
        if len(got) != 0 {
                t.Error("non-map value should return empty map")
        }
        got = extractMapSafe(map[string]any{"key": map[string]any{"a": 1}}, "key")
        if got["a"] != 1 {
                t.Errorf("expected a=1, got %v", got)
        }
}

func TestExtractStringSlice_B13(t *testing.T) {
        if got := extractStringSlice(nil, "k"); got != nil {
                t.Error("nil map should return nil")
        }
        if got := extractStringSlice(map[string]any{}, "k"); got != nil {
                t.Error("missing key should return nil")
        }
        got := extractStringSlice(map[string]any{"k": []any{"a", "b"}}, "k")
        if len(got) != 2 || got[0] != "a" {
                t.Errorf("any slice: %v", got)
        }
        got = extractStringSlice(map[string]any{"k": []string{"x", "y"}}, "k")
        if len(got) != 2 || got[0] != "x" {
                t.Errorf("string slice: %v", got)
        }
}

func TestMergeTTLValues_B13(t *testing.T) {
        ttls := map[string]uint32{"A": 300}
        mergeTTLValues(ttls, map[string]any{"A": float64(600), "MX": float64(3600)}, false)
        if ttls["A"] != 600 {
                t.Errorf("overwrite: A=%d want 600", ttls["A"])
        }
        if ttls["MX"] != 3600 {
                t.Errorf("new: MX=%d want 3600", ttls["MX"])
        }

        ttls2 := map[string]uint32{"A": 300}
        mergeTTLValues(ttls2, map[string]any{"A": float64(600), "NS": float64(86400)}, true)
        if ttls2["A"] != 300 {
                t.Errorf("skipExisting: A=%d want 300", ttls2["A"])
        }
        if ttls2["NS"] != 86400 {
                t.Errorf("new with skip: NS=%d want 86400", ttls2["NS"])
        }
}

func TestExtractTTLMap_B13(t *testing.T) {
        results := map[string]any{
                "resolver_ttl": map[string]any{"A": float64(300)},
                "basic_records": map[string]any{
                        "_ttl": map[string]any{"A": float64(600), "MX": float64(3600)},
                },
        }
        ttls := extractTTLMap(results)
        if ttls["A"] != 300 {
                t.Errorf("resolver_ttl should take precedence: A=%d", ttls["A"])
        }
        if ttls["MX"] != 3600 {
                t.Errorf("basic_records _ttl: MX=%d", ttls["MX"])
        }
}

func TestGetTTL_B13(t *testing.T) {
        ttls := map[string]uint32{"A": 300}
        if got := getTTL(ttls, "A"); got != "300" {
                t.Errorf("A: %q want 300", got)
        }
        if got := getTTL(ttls, "MX"); got != "; TTL unknown" {
                t.Errorf("MX: %q", got)
        }
}

func TestEscapeTXT_B13(t *testing.T) {
        if got := escapeTXT(`v=spf1 include:"_spf.google.com" ~all`); !strings.Contains(got, `\"`) {
                t.Errorf("expected escaped quotes: %q", got)
        }
        if got := escapeTXT("no quotes here"); got != "no quotes here" {
                t.Errorf("no change expected: %q", got)
        }
}

func TestWriteRecordSection_B13(t *testing.T) {
        var sb strings.Builder
        writeRecordSection(&sb, "A Records", "example.com.", []string{"1.2.3.4"}, map[string]uint32{"A": 300}, "A")
        out := sb.String()
        if !strings.Contains(out, "A Records") {
                t.Error("missing label")
        }
        if !strings.Contains(out, "1.2.3.4") {
                t.Error("missing record")
        }

        sb.Reset()
        writeRecordSection(&sb, "AAAA Records", "example.com.", nil, nil, "AAAA")
        if !strings.Contains(sb.String(), "none discovered") {
                t.Error("empty records should say none discovered")
        }
}

func TestWriteSRVSection_B13(t *testing.T) {
        var sb strings.Builder
        writeSRVSection(&sb, "example.com.", []string{"_sip._tcp: 10 5 5060 sip.example.com."})
        out := sb.String()
        if !strings.Contains(out, "_sip._tcp.example.com.") {
                t.Errorf("unexpected SRV output: %q", out)
        }

        sb.Reset()
        writeSRVSection(&sb, "example.com.", nil)
        if !strings.Contains(sb.String(), "none discovered") {
                t.Error("empty SRV should say none discovered")
        }
}

func TestGenerateObservedSnapshot_B13(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "A":  []any{"1.2.3.4"},
                        "MX": []any{"10 mail.example.com."},
                },
                "resolver_ttl": map[string]any{"A": float64(300)},
        }
        snap := GenerateObservedSnapshot("example.com", results, "1.0.0")
        if !strings.Contains(snap, "$ORIGIN example.com.") {
                t.Error("missing ORIGIN")
        }
        if !strings.Contains(snap, "1.2.3.4") {
                t.Error("missing A record")
        }
        if !strings.Contains(snap, "OBSERVED RECORDS SNAPSHOT") {
                t.Error("missing header")
        }
}

func TestExtractEmailSubdomainRecords_B13(t *testing.T) {
        auth := map[string]any{"DMARC": []any{"v=DMARC1; p=reject"}}
        results := map[string]any{}
        got := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", "example.com")
        if len(got) != 1 || got[0] != "v=DMARC1; p=reject" {
                t.Errorf("auth records: %v", got)
        }

        auth2 := map[string]any{}
        results2 := map[string]any{
                "dmarc_analysis": map[string]any{"record": "v=DMARC1; p=none"},
        }
        got = extractEmailSubdomainRecords(auth2, results2, "DMARC", "_dmarc", "example.com")
        if len(got) != 1 {
                t.Errorf("analysis fallback: %v", got)
        }

        got = extractEmailSubdomainRecords(map[string]any{}, map[string]any{}, "UNKNOWN_KEY", "_x", "example.com")
        if got != nil {
                t.Errorf("unknown key should return nil: %v", got)
        }
}

func TestProgressStore_B13(t *testing.T) {
        ps := NewProgressStore()
        defer ps.Close()

        token, sp := ps.NewToken()
        if token == "" || sp == nil {
                t.Fatal("NewToken failed")
        }
        if len(token) != 32 {
                t.Errorf("expected 32 hex chars, got %d", len(token))
        }

        got := ps.Get(token)
        if got != sp {
                t.Error("Get should return same progress")
        }

        if ps.Get("nonexistent") != nil {
                t.Error("missing token should return nil")
        }

        ps.Delete(token)
        if ps.Get(token) != nil {
                t.Error("deleted token should return nil")
        }
}

func TestScanProgress_UpdatePhase_B13(t *testing.T) {
        sp := &scanProgress{
                startTime: time.Now(),
                phases: map[string]*phaseStatus{
                        "dns": {Status: "pending", expectedTasks: 3},
                },
        }

        sp.UpdatePhase("dns", "done", 100)
        phase := sp.phases["dns"]
        if phase.Status != "running" {
                t.Errorf("1 of 3 done should be running, got %q", phase.Status)
        }
        if phase.completedTasks != 1 {
                t.Errorf("completedTasks: %d", phase.completedTasks)
        }

        sp.UpdatePhase("dns", "done", 100)
        sp.UpdatePhase("dns", "done", 100)
        if phase.Status != "done" {
                t.Errorf("3 of 3 done should be done, got %q", phase.Status)
        }

        sp.UpdatePhase("dns", "done", 100)
        if phase.completedTasks != 3 {
                t.Error("should not increment past done")
        }

        sp.UpdatePhase("new_phase", "done", 50)
        if np, ok := sp.phases["new_phase"]; !ok || np.Status != "done" {
                t.Error("new phase should be created as done")
        }
}

func TestScanProgress_MarkComplete_B13(t *testing.T) {
        sp := &scanProgress{
                startTime: time.Now(),
                phases: map[string]*phaseStatus{
                        "dns":  {Status: "running", expectedTasks: 3, completedTasks: 1},
                        "tls":  {Status: "pending", expectedTasks: 2},
                },
        }

        sp.MarkComplete(42, "/results/42")
        if !sp.complete {
                t.Error("should be complete")
        }
        if sp.analysisID != 42 {
                t.Errorf("analysisID: %d", sp.analysisID)
        }
        for name, ps := range sp.phases {
                if ps.Status != "done" {
                        t.Errorf("phase %s should be done, got %q", name, ps.Status)
                }
        }
}

func TestScanProgress_MarkFailed_B13(t *testing.T) {
        sp := &scanProgress{
                startTime: time.Now(),
                phases:    map[string]*phaseStatus{},
        }
        sp.MarkFailed("timeout")
        if !sp.complete || !sp.failed {
                t.Error("should be complete+failed")
        }
        if sp.failReason != "timeout" {
                t.Errorf("failReason: %q", sp.failReason)
        }
}

func TestScanProgress_ToJSON_B13(t *testing.T) {
        sp := &scanProgress{
                startTime: time.Now(),
                phases: map[string]*phaseStatus{
                        "dns": {Status: "done", DurationMs: 100, expectedTasks: 1, completedTasks: 1},
                },
        }
        j := sp.toJSON()
        if j["status"] != "running" {
                t.Errorf("not complete should be running, got %v", j["status"])
        }

        sp.MarkComplete(1, "/r/1")
        j = sp.toJSON()
        if j["status"] != "complete" {
                t.Errorf("expected complete, got %v", j["status"])
        }
        if j["redirect_url"] != "/r/1" {
                t.Errorf("redirect_url: %v", j["redirect_url"])
        }

        sp2 := &scanProgress{
                startTime: time.Now(),
                phases:    map[string]*phaseStatus{},
        }
        sp2.MarkFailed("oops")
        j = sp2.toJSON()
        if j["status"] != "failed" {
                t.Errorf("expected failed, got %v", j["status"])
        }
        if j["error"] != "oops" {
                t.Errorf("error: %v", j["error"])
        }
}

func TestScanProgress_MakeProgressCallback_B13(t *testing.T) {
        sp := &scanProgress{
                startTime: time.Now(),
                phases: map[string]*phaseStatus{
                        "dns": {Status: "pending", expectedTasks: 1},
                },
        }
        cb := sp.MakeProgressCallback()
        cb("dns", "done", 50)
        if sp.phases["dns"].Status != "done" {
                t.Errorf("callback should update phase, got %q", sp.phases["dns"].Status)
        }
}

func TestCheckProviderLock_NS_B13(t *testing.T) {
        locked, reason := checkProviderLock("NS", 86400, "Cloudflare", icuae.ProviderProfile{}, true)
        if !locked {
                t.Error("NS should always be locked when hasProvider")
        }
        if !strings.Contains(reason, "NS record") {
                t.Errorf("unexpected reason: %q", reason)
        }
}

func TestCheckProviderLock_NoProvider_B13(t *testing.T) {
        locked, _ := checkProviderLock("A", 300, "", icuae.ProviderProfile{}, false)
        if locked {
                t.Error("no provider should not be locked")
        }
}

func TestCheckProviderLock_CloudflareProxied_B13(t *testing.T) {
        profile := icuae.ProviderProfile{ProxiedTTL: 300}
        locked, reason := checkProviderLock("A", 300, "Cloudflare", profile, true)
        if !locked {
                t.Error("Cloudflare proxied A should be locked")
        }
        if !strings.Contains(reason, "Cloudflare") {
                t.Errorf("unexpected reason: %q", reason)
        }
}

func TestCheckProviderLock_Route53Alias_B13(t *testing.T) {
        profile := icuae.ProviderProfile{AliasTTL: 60}
        locked, reason := checkProviderLock("A", 60, "AWS Route 53", profile, true)
        if !locked {
                t.Error("Route53 alias should be locked")
        }
        if !strings.Contains(reason, "Route 53") {
                t.Errorf("unexpected reason: %q", reason)
        }
}

func TestCheckProviderLock_MinAllowed_B13(t *testing.T) {
        profile := icuae.ProviderProfile{MinAllowedTTL: 120}
        locked, reason := checkProviderLock("A", 300, "CustomDNS", profile, true)
        if locked {
                t.Error("MinAllowedTTL should not lock, just note")
        }
        if !strings.Contains(reason, "minimum TTL") {
                t.Errorf("unexpected reason: %q", reason)
        }
}

func TestWriteTXTSection_B13(t *testing.T) {
        var sb strings.Builder
        basic := map[string]any{"TXT": []any{"v=spf1 -all"}}
        auth := map[string]any{"DMARC": []any{"v=DMARC1; p=reject"}}
        results := map[string]any{}
        ttls := map[string]uint32{"TXT": 300}
        writeTXTSection(&sb, "example.com.", basic, auth, results, "example.com", ttls)
        out := sb.String()
        if !strings.Contains(out, "v=spf1 -all") {
                t.Error("missing SPF TXT")
        }
        if !strings.Contains(out, "_dmarc.example.com.") {
                t.Error("missing DMARC subdomain")
        }
}

func TestWriteTXTSection_Empty_B13(t *testing.T) {
        var sb strings.Builder
        writeTXTSection(&sb, "example.com.", map[string]any{}, map[string]any{}, map[string]any{}, "example.com", nil)
        if sb.String() != "" {
                t.Error("empty TXT should produce no output")
        }
}
