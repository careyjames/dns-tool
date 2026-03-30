package analyzer

import (
	"strings"
	"testing"
	"time"
)

func TestSeparateHeadersAndBody(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantBody   bool
		wantHdrLen bool
	}{
		{
			"headers with body",
			"From: a@b.com\nTo: c@d.com\n\nBody text here",
			true,
			true,
		},
		{
			"headers only",
			"From: a@b.com\nTo: c@d.com",
			false,
			true,
		},
		{
			"crlf separator",
			"From: a@b.com\r\nTo: c@d.com\r\n\r\nBody text",
			true,
			true,
		},
		{
			"no header fields",
			"just some text\n\nmore text",
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, body, hadBody := SeparateHeadersAndBody(tt.raw)
			if hadBody != tt.wantBody {
				t.Errorf("hadBody = %v, want %v", hadBody, tt.wantBody)
			}
			if tt.wantBody && body == "" {
				t.Error("expected non-empty body")
			}
			if tt.wantHdrLen && headers == "" {
				t.Error("expected non-empty headers")
			}
		})
	}
}

func TestHasHeaderFields(t *testing.T) {
	tests := []struct {
		text   string
		expect bool
	}{
		{"From: a@b.com\nTo: c@d.com", true},
		{"Just plain text", false},
		{"Single-Header: value", false},
		{"X-First: one\nX-Second: two\nX-Third: three", true},
	}
	for _, tt := range tests {
		got := hasHeaderFields(tt.text)
		if got != tt.expect {
			t.Errorf("hasHeaderFields(%q) = %v, want %v", tt.text[:20], got, tt.expect)
		}
	}
}

func TestUnfoldHeaders(t *testing.T) {
	input := "Subject: This is a\n\tlong subject line\nFrom: a@b.com"
	result := unfoldHeaders(input)
	if strings.Contains(result, "\t") {
		t.Error("expected tabs to be removed during unfolding")
	}
	if !strings.Contains(result, "long subject line") {
		t.Error("expected unfolded content to be preserved")
	}
}

func TestUnfoldHeaders_CRLF(t *testing.T) {
	input := "Subject: Test\r\n\tcontinuation\r\nFrom: a@b.com"
	result := unfoldHeaders(input)
	if !strings.Contains(result, "continuation") {
		t.Error("expected continuation to be preserved")
	}
}

func TestParseHeaderFields(t *testing.T) {
	unfolded := "From: a@b.com\nTo: c@d.com\nSubject: Hello World"
	fields := parseHeaderFields(unfolded)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}
	if fields[0].Name != "from" || fields[0].Value != "a@b.com" {
		t.Errorf("unexpected first field: %+v", fields[0])
	}
}

func TestExtractHeader(t *testing.T) {
	fields := []headerField{
		{Name: "from", Value: "a@b.com"},
		{Name: "to", Value: "c@d.com"},
	}
	if got := extractHeader(fields, "from"); got != "a@b.com" {
		t.Errorf("expected a@b.com, got %q", got)
	}
	if got := extractHeader(fields, "subject"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractAllHeaders(t *testing.T) {
	fields := []headerField{
		{Name: "received", Value: "first"},
		{Name: "from", Value: "a@b.com"},
		{Name: "received", Value: "second"},
	}
	vals := extractAllHeaders(fields, "received")
	if len(vals) != 2 {
		t.Errorf("expected 2 received headers, got %d", len(vals))
	}
}

func TestParseAuthPart(t *testing.T) {
	tests := []struct {
		name     string
		part     string
		authType string
		result   string
		domain   string
	}{
		{"spf pass", "spf=pass header.mailfrom=example.com", "spf", "pass", "example.com"},
		{"dkim fail", "dkim=fail header.d=example.com", "dkim", "fail", "example.com"},
		{"no equals", "spfpass", "spf", "", ""},
		{"result only", "spf=pass", "spf", "pass", ""},
		{"with detail", "spf=softfail (sender IP is 1.2.3.4)", "spf", "softfail", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := parseAuthPart(tt.part, tt.authType)
			if ar.Result != tt.result {
				t.Errorf("Result = %q, want %q", ar.Result, tt.result)
			}
			if tt.domain != "" && ar.Domain != tt.domain {
				t.Errorf("Domain = %q, want %q", ar.Domain, tt.domain)
			}
		})
	}
}

func TestExtractDomainFromEmailAddress(t *testing.T) {
	tests := []struct {
		addr   string
		expect string
	}{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"John Doe <user@example.com>", "example.com"},
		{"", ""},
		{"no-at-sign", ""},
		{"  user@example.com  ", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := extractDomainFromEmailAddress(tt.addr)
			if got != tt.expect {
				t.Errorf("extractDomainFromEmailAddress(%q) = %q, want %q", tt.addr, got, tt.expect)
			}
		})
	}
}

func TestClassifyReturnPathAlignment(t *testing.T) {
	tests := []struct {
		from, rp, expect string
	}{
		{"example.com", "example.com", "aligned"},
		{"Example.Com", "example.com", "aligned"},
		{"sub.example.com", "example.com", "relaxed"},
		{"example.com", "sub.example.com", "relaxed"},
		{"example.com", "other.com", "misaligned"},
	}
	for _, tt := range tests {
		t.Run(tt.from+"_"+tt.rp, func(t *testing.T) {
			got := classifyReturnPathAlignment(tt.from, tt.rp)
			if got != tt.expect {
				t.Errorf("got %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestDomainsRelaxedMatch(t *testing.T) {
	tests := []struct {
		a, b   string
		expect bool
	}{
		{"example.com", "sub.example.com", true},
		{"sub.example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"example.com", "example.com", false},
	}
	for _, tt := range tests {
		got := domainsRelaxedMatch(tt.a, tt.b)
		if got != tt.expect {
			t.Errorf("domainsRelaxedMatch(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expect)
		}
	}
}

func TestClassifyDKIMAlignment(t *testing.T) {
	tests := []struct {
		name    string
		results []AuthResult
		from    string
		expect  string
	}{
		{"aligned", []AuthResult{{Domain: "example.com"}}, "example.com", "aligned"},
		{"misaligned", []AuthResult{{Domain: "other.com"}}, "example.com", "misaligned"},
		{"empty domain", []AuthResult{{Domain: ""}}, "example.com", "misaligned"},
		{"with @ prefix", []AuthResult{{Domain: "@example.com"}}, "example.com", "aligned"},
		{"relaxed match", []AuthResult{{Domain: "sub.example.com"}}, "example.com", "aligned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDKIMAlignment(tt.results, tt.from)
			if got != tt.expect {
				t.Errorf("got %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestFormatDelay(t *testing.T) {
	tests := []struct {
		delay  time.Duration
		expect string
	}{
		{500 * time.Millisecond, "<1s"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1.5m"},
		{2 * time.Hour, "2.0h"},
	}
	for _, tt := range tests {
		got := formatDelay(tt.delay)
		if got != tt.expect {
			t.Errorf("formatDelay(%v) = %q, want %q", tt.delay, got, tt.expect)
		}
	}
}

func TestParseEmailDate(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"Mon, 02 Jan 2006 15:04:05 -0700", true},
		{"Mon, 2 Jan 2006 15:04:05 -0700", true},
		{"Mon, 02 Jan 2006 15:04:05 -0700 (MST)", true},
		{"not a date", false},
		{"", false},
	}
	for _, tt := range tests {
		_, err := parseEmailDate(tt.input)
		if tt.valid && err != nil {
			t.Errorf("parseEmailDate(%q) unexpected error: %v", tt.input, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("parseEmailDate(%q) expected error", tt.input)
		}
	}
}

func TestGenerateSPFFlags(t *testing.T) {
	tests := []struct {
		name     string
		result   string
		severity string
	}{
		{"fail", "fail", "danger"},
		{"softfail", "softfail", "danger"},
		{"none", "none", "warning"},
		{"empty", "", "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &EmailHeaderAnalysis{SPFResult: AuthResult{Result: tt.result}}
			generateSPFFlags(r)
			if len(r.Flags) == 0 {
				t.Fatal("expected at least one flag")
			}
			if r.Flags[0].Severity != tt.severity {
				t.Errorf("severity = %q, want %q", r.Flags[0].Severity, tt.severity)
			}
		})
	}
}

func TestGenerateSPFFlags_Pass(t *testing.T) {
	r := &EmailHeaderAnalysis{SPFResult: AuthResult{Result: "pass"}}
	generateSPFFlags(r)
	if len(r.Flags) != 0 {
		t.Error("expected no flags for SPF pass")
	}
}

func TestGenerateDKIMFlags(t *testing.T) {
	r := &EmailHeaderAnalysis{}
	generateDKIMFlags(r)
	if len(r.Flags) != 1 || r.Flags[0].Severity != "info" {
		t.Error("expected info flag for no DKIM results")
	}
}

func TestGenerateDKIMFlags_AllPass(t *testing.T) {
	r := &EmailHeaderAnalysis{
		DKIMResults: []AuthResult{{Result: "pass", Domain: "example.com"}},
	}
	generateDKIMFlags(r)
	if len(r.Flags) != 1 || r.Flags[0].Severity != "success" {
		t.Error("expected success flag for all DKIM pass")
	}
}

func TestGenerateDKIMFlags_Fail(t *testing.T) {
	r := &EmailHeaderAnalysis{
		DKIMResults: []AuthResult{{Result: "fail", Domain: "example.com"}},
	}
	generateDKIMFlags(r)
	if len(r.Flags) != 1 || r.Flags[0].Severity != "danger" {
		t.Error("expected danger flag for DKIM fail")
	}
}

func TestGenerateDMARCFlags(t *testing.T) {
	tests := []struct {
		result   string
		severity string
	}{
		{"fail", "danger"},
		{"", "info"},
	}
	for _, tt := range tests {
		r := &EmailHeaderAnalysis{DMARCResult: AuthResult{Result: tt.result}}
		generateDMARCFlags(r)
		if len(r.Flags) == 0 {
			t.Fatal("expected flag")
		}
		if r.Flags[0].Severity != tt.severity {
			t.Errorf("severity = %q, want %q", r.Flags[0].Severity, tt.severity)
		}
	}
}

func TestGenerateDMARCFlags_Pass(t *testing.T) {
	r := &EmailHeaderAnalysis{DMARCResult: AuthResult{Result: "pass"}}
	generateDMARCFlags(r)
	if len(r.Flags) != 0 {
		t.Error("expected no flags for DMARC pass")
	}
}

func TestGenerateAlignmentFlags_Misaligned(t *testing.T) {
	r := &EmailHeaderAnalysis{
		AlignmentFromReturnPath: "misaligned",
		From:                    "user@example.com",
		ReturnPath:              "bounce@other.com",
	}
	generateAlignmentFlags(r)
	if len(r.Flags) == 0 {
		t.Error("expected alignment flag")
	}
}

func TestGenerateAlignmentFlags_ReplyToDiffers(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From:    "user@example.com",
		ReplyTo: "reply@other.com",
	}
	generateAlignmentFlags(r)
	if len(r.Flags) == 0 {
		t.Error("expected reply-to mismatch flag")
	}
}

func TestGenerateRoutingFlags_UnknownHop(t *testing.T) {
	r := &EmailHeaderAnalysis{
		ReceivedHops: []ReceivedHop{
			{Index: 1, From: "unknown.host", IP: "1.2.3.4", IsPrivate: false},
		},
	}
	generateRoutingFlags(r)
	if len(r.Flags) == 0 {
		t.Error("expected routing flag for unknown host")
	}
}

func TestGenerateRoutingFlags_ManyHops(t *testing.T) {
	r := &EmailHeaderAnalysis{HopCount: 10}
	r.ReceivedHops = make([]ReceivedHop, 10)
	generateRoutingFlags(r)
	found := false
	for _, f := range r.Flags {
		if f.Category == "Routing" && strings.Contains(f.Message, "10 hops") {
			found = true
		}
	}
	if !found {
		t.Error("expected routing flag for many hops")
	}
}

func TestGenerateVerdict(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*EmailHeaderAnalysis)
		verdict string
	}{
		{
			"clean",
			func(r *EmailHeaderAnalysis) {},
			"clean",
		},
		{
			"caution with warning",
			func(r *EmailHeaderAnalysis) {
				r.Flags = []HeaderFlag{{Severity: "warning"}}
			},
			"caution",
		},
		{
			"suspicious with danger",
			func(r *EmailHeaderAnalysis) {
				r.Flags = []HeaderFlag{{Severity: "danger"}}
			},
			"suspicious",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &EmailHeaderAnalysis{}
			tt.setup(r)
			generateVerdict(r)
			if r.Verdict != tt.verdict {
				t.Errorf("verdict = %q, want %q", r.Verdict, tt.verdict)
			}
		})
	}
}

func TestTallyVerdictCounts(t *testing.T) {
	r := &EmailHeaderAnalysis{
		Flags: []HeaderFlag{
			{Severity: "danger"},
			{Severity: "danger"},
			{Severity: "warning"},
			{Severity: "info"},
		},
		BodyIndicators: []PhishingIndicator{
			{Severity: "danger"},
		},
		SubjectScamIndicators: []PhishingIndicator{
			{Severity: "danger"},
		},
		BigQuestions: []BigQuestion{
			{Severity: "danger"},
		},
	}
	vc := tallyVerdictCounts(r)
	if vc.danger != 2 {
		t.Errorf("danger = %d, want 2", vc.danger)
	}
	if vc.warning != 1 {
		t.Errorf("warning = %d, want 1", vc.warning)
	}
	if vc.phishingDanger != 1 {
		t.Errorf("phishingDanger = %d, want 1", vc.phishingDanger)
	}
	if vc.subjectDanger != 1 {
		t.Errorf("subjectDanger = %d, want 1", vc.subjectDanger)
	}
	if vc.bigQDanger != 1 {
		t.Errorf("bigQDanger = %d, want 1", vc.bigQDanger)
	}
}

func TestIsSuspicious(t *testing.T) {
	tests := []struct {
		name        string
		vc          verdictCounts
		spamFlagged bool
		expect      bool
	}{
		{"danger > 0", verdictCounts{danger: 1}, false, true},
		{"phishingDanger >= 2", verdictCounts{phishingDanger: 2}, false, true},
		{"spam + phishing", verdictCounts{phishingDanger: 1}, true, true},
		{"clean", verdictCounts{}, false, false},
		{"warning only", verdictCounts{warning: 3}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSuspicious(tt.vc, tt.spamFlagged)
			if got != tt.expect {
				t.Errorf("isSuspicious() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestSuspiciousSummary(t *testing.T) {
	tests := []struct {
		name   string
		vc     verdictCounts
		result *EmailHeaderAnalysis
		substr string
	}{
		{
			"spam + subject",
			verdictCounts{subjectDanger: 1},
			&EmailHeaderAnalysis{SpamFlagged: true},
			"flagged as spam",
		},
		{
			"spam + phishing",
			verdictCounts{phishingDanger: 1},
			&EmailHeaderAnalysis{SpamFlagged: true},
			"flagged as spam",
		},
		{
			"subject danger >= 2",
			verdictCounts{subjectDanger: 2},
			&EmailHeaderAnalysis{},
			"subject line",
		},
		{
			"brand mismatch",
			verdictCounts{},
			&EmailHeaderAnalysis{SenderBrandMismatch: true},
			"brand",
		},
		{
			"default",
			verdictCounts{danger: 1},
			&EmailHeaderAnalysis{},
			"Suspicious",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suspiciousSummary(tt.vc, tt.result)
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.substr)) {
				t.Errorf("suspiciousSummary() = %q, want to contain %q", got, tt.substr)
			}
		})
	}
}

func TestScanPhraseCategory(t *testing.T) {
	cfg := phraseScanConfig{
		phrases:        []string{"urgent", "act now", "immediately"},
		multiCategory:  "Multi",
		multiSev:       "danger",
		multiDesc:      "multiple matches",
		minForMulti:    2,
		singleCategory: "Single",
		singleSev:      "warning",
		singleDesc:     "single match",
	}

	result := scanPhraseCategory("this is urgent and act now", cfg)
	if result == nil {
		t.Fatal("expected non-nil for multi match")
	}
	if result.Category != "Multi" {
		t.Errorf("category = %q, want Multi", result.Category)
	}

	result = scanPhraseCategory("this is urgent", cfg)
	if result == nil {
		t.Fatal("expected non-nil for single match")
	}
	if result.Category != "Single" {
		t.Errorf("category = %q, want Single", result.Category)
	}

	result = scanPhraseCategory("nothing here", cfg)
	if result != nil {
		t.Error("expected nil for no match")
	}
}

func TestScanFirstMatch(t *testing.T) {
	result := scanFirstMatch("send payment now", []string{"send payment", "wire transfer"}, "Payment", "danger", "desc", "Matched: ")
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.Category != "Payment" {
		t.Errorf("category = %q, want Payment", result.Category)
	}

	result = scanFirstMatch("nothing here", []string{"send payment"}, "Payment", "danger", "desc", "Matched: ")
	if result != nil {
		t.Error("expected nil for no match")
	}
}

func TestNormalizeHomoglyphs(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"hello", "hello"},
		{"h3llo", "hello"},
		{"g00gle", "google"},
		{"HELLO", "HEllo"},
	}
	for _, tt := range tests {
		got := normalizeHomoglyphs(tt.input)
		if got != tt.expect {
			t.Errorf("normalizeHomoglyphs(%q) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

func TestExtractAllEmailAddresses(t *testing.T) {
	s := "user1@example.com, user2@test.org and user3@domain.net"
	result := extractAllEmailAddresses(s)
	if len(result) != 3 {
		t.Errorf("expected 3 addresses, got %d", len(result))
	}
}

func TestExtractFirstEmailFromField(t *testing.T) {
	got := extractFirstEmailFromField("rfc822;user@example.com")
	if got != "user@example.com" {
		t.Errorf("got %q, want user@example.com", got)
	}

	got = extractFirstEmailFromField("no-email-here")
	if got != "no-email-here" {
		t.Errorf("got %q, want 'no-email-here'", got)
	}
}

func TestStripHTMLTags(t *testing.T) {
	html := `<html><head><style>body{color:red}</style></head><body><script>alert('xss')</script><p>Hello &amp; welcome</p></body></html>`
	result := stripHTMLTags(html)
	if !strings.Contains(result, "Hello") {
		t.Error("expected text content to be preserved")
	}
	if !strings.Contains(result, "&") {
		t.Error("expected &amp; to be decoded")
	}
	if strings.Contains(result, "alert") {
		t.Error("expected script content to be removed")
	}
	if strings.Contains(result, "color:red") {
		t.Error("expected style content to be removed")
	}
}

func TestDecodeEmailBody_Base64(t *testing.T) {
	encoded := "SGVsbG8gV29ybGQ="
	headers := []headerField{
		{Name: "content-transfer-encoding", Value: "base64"},
		{Name: "content-type", Value: "text/plain"},
	}
	result := decodeEmailBody(encoded, headers)
	if result != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", result)
	}
}

func TestDecodeEmailBody_QuotedPrintable(t *testing.T) {
	encoded := "Hello=20World"
	headers := []headerField{
		{Name: "content-transfer-encoding", Value: "quoted-printable"},
		{Name: "content-type", Value: "text/plain"},
	}
	result := decodeEmailBody(encoded, headers)
	if result != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", result)
	}
}

func TestDecodeEmailBody_HTML(t *testing.T) {
	body := "<p>Hello World</p>"
	headers := []headerField{
		{Name: "content-type", Value: "text/html"},
	}
	result := decodeEmailBody(body, headers)
	if strings.Contains(result, "<p>") {
		t.Error("expected HTML tags to be stripped")
	}
}

func TestCheckAllAuthPass(t *testing.T) {
	tests := []struct {
		name   string
		result *EmailHeaderAnalysis
		expect bool
	}{
		{
			"all pass",
			&EmailHeaderAnalysis{
				SPFResult:   AuthResult{Result: "pass"},
				DMARCResult: AuthResult{Result: "pass"},
				DKIMResults: []AuthResult{{Result: "pass"}},
			},
			true,
		},
		{
			"spf fail",
			&EmailHeaderAnalysis{
				SPFResult:   AuthResult{Result: "fail"},
				DMARCResult: AuthResult{Result: "pass"},
				DKIMResults: []AuthResult{{Result: "pass"}},
			},
			false,
		},
		{
			"no dkim pass",
			&EmailHeaderAnalysis{
				SPFResult:   AuthResult{Result: "pass"},
				DMARCResult: AuthResult{Result: "pass"},
				DKIMResults: []AuthResult{{Result: "fail"}},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkAllAuthPass(tt.result)
			if got != tt.expect {
				t.Errorf("checkAllAuthPass() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestAnalyzeEmailHeaders_BasicParsing(t *testing.T) {
	raw := "From: sender@example.com\nTo: recipient@test.com\nSubject: Test Email\nDate: Mon, 02 Jan 2006 15:04:05 -0700\nMessage-ID: <123@example.com>"
	result := AnalyzeEmailHeaders(raw)
	if result.From != "sender@example.com" {
		t.Errorf("From = %q", result.From)
	}
	if result.To != "recipient@test.com" {
		t.Errorf("To = %q", result.To)
	}
	if result.Subject != "Test Email" {
		t.Errorf("Subject = %q", result.Subject)
	}
	if result.MessageID != "<123@example.com>" {
		t.Errorf("MessageID = %q", result.MessageID)
	}
}

func TestAnalyzeEmailHeaders_WithAuthResults(t *testing.T) {
	raw := "From: sender@example.com\nTo: recipient@test.com\nAuthentication-Results: mx.google.com; spf=pass; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
	result := AnalyzeEmailHeaders(raw)
	if result.SPFResult.Result != "pass" {
		t.Errorf("SPF result = %q, want 'pass'", result.SPFResult.Result)
	}
	if len(result.DKIMResults) == 0 {
		t.Error("expected DKIM results")
	}
	if result.DMARCResult.Result != "pass" {
		t.Errorf("DMARC result = %q, want 'pass'", result.DMARCResult.Result)
	}
}

func TestParseReceivedHop(t *testing.T) {
	raw := "from mail.example.com ([192.168.1.1]) by mx.test.com with ESMTPS id abc; Mon, 02 Jan 2006 15:04:05 -0700"
	hop, _ := parseReceivedHop(raw, 1)
	if hop.From != "mail.example.com" {
		t.Errorf("From = %q", hop.From)
	}
	if hop.By != "mx.test.com" {
		t.Errorf("By = %q", hop.By)
	}
	if hop.With != "ESMTPS" {
		t.Errorf("With = %q", hop.With)
	}
	if hop.IP != "192.168.1.1" {
		t.Errorf("IP = %q", hop.IP)
	}
}

func TestExtractHopIP_Private(t *testing.T) {
	hop := &ReceivedHop{}
	extractHopIP(hop, "from host [127.0.0.1]")
	if hop.IP != "127.0.0.1" {
		t.Errorf("IP = %q", hop.IP)
	}
	if !hop.IsPrivate {
		t.Error("expected loopback to be private")
	}
}

func TestExtractHopIP_NoIP(t *testing.T) {
	hop := &ReceivedHop{}
	extractHopIP(hop, "from host by server")
	if hop.IP != "" {
		t.Errorf("expected empty IP, got %q", hop.IP)
	}
}

func TestCalculateHopDelays(t *testing.T) {
	now := time.Now()
	hops := []ReceivedHop{{}, {}}
	timestamps := []time.Time{now, now.Add(-5 * time.Second)}
	calculateHopDelays(hops, timestamps)
	if hops[0].Delay == "" {
		t.Error("expected delay to be calculated")
	}
}

func TestDetectBrandMismatch(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From:    "scammer@fakeemail.com",
		Subject: "Your PayPal account has been suspended",
	}
	detectBrandMismatch(r)
	if !r.SenderBrandMismatch {
		t.Error("expected brand mismatch for PayPal subject from non-PayPal domain")
	}
}

func TestDetectBrandMismatch_Legitimate(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From:    "noreply@paypal.com",
		Subject: "Your PayPal receipt",
	}
	detectBrandMismatch(r)
	if r.SenderBrandMismatch {
		t.Error("expected no brand mismatch for legitimate PayPal email")
	}
}

func TestMatchesBrand(t *testing.T) {
	got := matchesBrand("PayPal", []string{"paypal"}, "paypal security alert", "", "", "fakeemail.com")
	if !got {
		t.Error("expected match for paypal keyword from non-paypal domain")
	}

	got = matchesBrand("PayPal", []string{"paypal"}, "paypal security alert", "", "", "paypal.com")
	if got {
		t.Error("expected no match when domain contains brand")
	}
}

func TestCheckSubjectPhoneNumbers(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Call 1-800-555-1234 for support"}
	checkSubjectPhoneNumbers(r)
	if len(r.SubjectScamIndicators) == 0 {
		t.Error("expected phone number indicator")
	}
}

func TestCheckSubjectPhoneNumbers_WithSubstitution(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Call 1-8OO-555-1234 now"}
	checkSubjectPhoneNumbers(r)
	if len(r.SubjectScamIndicators) == 0 {
		t.Fatal("expected indicator")
	}
	if r.SubjectScamIndicators[0].Severity != "danger" {
		t.Error("expected danger severity for letter substitution")
	}
}

func TestCheckSubjectMoneyAmounts(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Payment of $499.99 confirmed"}
	checkSubjectMoneyAmounts(r)
	if len(r.SubjectScamIndicators) == 0 {
		t.Error("expected money amount indicator")
	}
}

func TestCheckSubjectHomoglyphs(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Micr0s0ft Security Alert"}
	checkSubjectHomoglyphs(r)
	if len(r.SubjectScamIndicators) == 0 {
		t.Error("expected homoglyph indicator")
	}
}

func TestCheckSubjectHomoglyphs_NoChange(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "just a test"}
	checkSubjectHomoglyphs(r)
	if len(r.SubjectScamIndicators) != 0 {
		t.Error("expected no indicator for regular text")
	}
}

func TestCheckSubjectScamPhrases(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "Your payment of invoice confirmed - security alert"}
	checkSubjectScamPhrases(r)
	if len(r.SubjectScamIndicators) == 0 {
		t.Error("expected scam phrase indicator")
	}
}

func TestCheckSubjectScamPhrases_Single(t *testing.T) {
	r := &EmailHeaderAnalysis{Subject: "invoice from company"}
	checkSubjectScamPhrases(r)
	if len(r.SubjectScamIndicators) != 1 {
		t.Errorf("expected 1 indicator, got %d", len(r.SubjectScamIndicators))
	}
	if r.SubjectScamIndicators[0].Severity != "warning" {
		t.Errorf("expected warning for single phrase, got %q", r.SubjectScamIndicators[0].Severity)
	}
}

func TestScanFormattingIndicators(t *testing.T) {
	body := "THIS IS VERY URGENT PLEASE ACT NOW IMMEDIATELY REQUIRED!!!! WARNING!!!!"
	indicators := scanFormattingIndicators(body, nil)
	if len(indicators) == 0 {
		t.Error("expected formatting indicator")
	}
}

func TestScanContactMethods(t *testing.T) {
	body := "Please contact: scammer@gmail.com for assistance"
	indicators := scanContactMethods(body, nil)
	if len(indicators) == 0 {
		t.Error("expected contact method indicator")
	}
}

func TestFallbackSPFFromReceivedSPF(t *testing.T) {
	fields := []headerField{
		{Name: "received-spf", Value: "Pass (mailfrom) identity=mailfrom"},
	}
	r := &EmailHeaderAnalysis{}
	fallbackSPFFromReceivedSPF(fields, r)
	if r.SPFResult.Result != "pass" {
		t.Errorf("expected 'pass', got %q", r.SPFResult.Result)
	}
}

func TestFallbackSPFFromReceivedSPF_Empty(t *testing.T) {
	fields := []headerField{}
	r := &EmailHeaderAnalysis{}
	fallbackSPFFromReceivedSPF(fields, r)
	if r.SPFResult.Result != "" {
		t.Error("expected empty result")
	}
}

func TestDetectOriginatingIP(t *testing.T) {
	fields := []headerField{
		{Name: "x-originating-ip", Value: "[1.2.3.4]"},
	}
	r := &EmailHeaderAnalysis{}
	detectOriginatingIP(fields, r)
	if r.OriginatingIP != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", r.OriginatingIP)
	}
}

func TestDetectDMARCPolicy(t *testing.T) {
	fields := []headerField{
		{Name: "x-dmarc-policy", Value: "p=none"},
	}
	r := &EmailHeaderAnalysis{}
	detectDMARCPolicy(fields, r)
	if r.DMARCPolicy != "none" {
		t.Errorf("expected 'none', got %q", r.DMARCPolicy)
	}
}

func TestParseARCChain(t *testing.T) {
	fields := []headerField{
		{Name: "arc-message-signature", Value: "i=1; a=rsa-sha256"},
		{Name: "arc-seal", Value: "i=1; a=rsa-sha256"},
		{Name: "arc-authentication-results", Value: "i=1; spf=pass"},
	}
	r := &EmailHeaderAnalysis{}
	parseARCChain(fields, r)
	if len(r.ARCChain) != 1 {
		t.Errorf("expected 1 ARC set, got %d", len(r.ARCChain))
	}
	if r.ARCChain[0].Instance != 1 {
		t.Errorf("expected instance 1")
	}
}

func TestAnalyzeSubjectLine_Empty(t *testing.T) {
	r := &EmailHeaderAnalysis{}
	analyzeSubjectLine(r)
	if r.HasSubjectAnalysis {
		t.Error("expected no subject analysis for empty subject")
	}
}

func TestGenerateIntelFlags_SpamFlagged(t *testing.T) {
	r := &EmailHeaderAnalysis{SpamFlagged: true}
	generateIntelFlags(r)
	found := false
	for _, f := range r.Flags {
		if f.Category == "Spam Detection" {
			found = true
		}
	}
	if !found {
		t.Error("expected spam detection flag")
	}
}

func TestGenerateIntelFlags_BCCDelivery(t *testing.T) {
	r := &EmailHeaderAnalysis{BCCDelivery: true, BCCRecipient: "me@example.com"}
	generateIntelFlags(r)
	found := false
	for _, f := range r.Flags {
		if f.Category == "BCC Delivery" {
			found = true
		}
	}
	if !found {
		t.Error("expected BCC delivery flag")
	}
}

func TestScanCryptoAddresses(t *testing.T) {
	body := "Send payment to 0x742d35Cc6634C0532925a3b844Bc9e7595f7DdEA for your files"
	indicators := scanCryptoAddresses(body, nil)
	if len(indicators) == 0 {
		t.Error("expected crypto address indicator")
	}
}

func TestScanCryptoAddresses_NoCrypto(t *testing.T) {
	indicators := scanCryptoAddresses("Hello world, no crypto here", nil)
	if len(indicators) != 0 {
		t.Error("expected no indicators for non-crypto text")
	}
}

func TestDetectSpamFlags(t *testing.T) {
	tests := []struct {
		name        string
		fields      []headerField
		wantFlagged bool
	}{
		{
			"x-spam-flag yes",
			[]headerField{{Name: "x-spam-flag", Value: "Yes"}},
			true,
		},
		{
			"x-suspected-spam true",
			[]headerField{{Name: "x-suspected-spam", Value: "true"}},
			true,
		},
		{
			"x-apple-action junk",
			[]headerField{{Name: "x-apple-action", Value: "JUNK"}},
			true,
		},
		{
			"x-apple-movetofolder junk",
			[]headerField{{Name: "x-apple-movetofolder", Value: "Junk"}},
			true,
		},
		{
			"x-barracuda-spam-status yes",
			[]headerField{{Name: "x-barracuda-spam-status", Value: "Yes"}},
			true,
		},
		{
			"no spam headers",
			[]headerField{{Name: "from", Value: "test@example.com"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &EmailHeaderAnalysis{}
			detectSpamFlags(tt.fields, r)
			if r.SpamFlagged != tt.wantFlagged {
				t.Errorf("SpamFlagged = %v, want %v", r.SpamFlagged, tt.wantFlagged)
			}
		})
	}
}

func TestDetectVendorSpamScores(t *testing.T) {
	fields := []headerField{
		{Name: "x-barracuda-spam-score", Value: "5.5"},
		{Name: "x-mimecast-spam-score", Value: "3"},
		{Name: "x-proofpoint-spam-details-enc", Value: "encoded-data"},
	}
	r := &EmailHeaderAnalysis{}
	detectVendorSpamScores(fields, r)
	if len(r.SpamFlagSources) != 3 {
		t.Errorf("expected 3 spam flag sources, got %d", len(r.SpamFlagSources))
	}
}

func TestDetectVendorSpamScores_MicrosoftSCL(t *testing.T) {
	fields := []headerField{
		{Name: "x-forefront-antispam-report", Value: "SCL:7;SFV:SKI"},
	}
	r := &EmailHeaderAnalysis{}
	detectVendorSpamScores(fields, r)
	if !r.MicrosoftSCLFound {
		t.Error("expected MicrosoftSCLFound to be true")
	}
	if r.MicrosoftSCL != 7 {
		t.Errorf("expected SCL 7, got %d", r.MicrosoftSCL)
	}
	if !r.SpamFlagged {
		t.Error("expected SpamFlagged for SCL >= 5")
	}
}

func TestDetectVendorSpamScores_MicrosoftSCLLow(t *testing.T) {
	fields := []headerField{
		{Name: "x-forefront-antispam-report", Value: "SCL:1"},
	}
	r := &EmailHeaderAnalysis{}
	detectVendorSpamScores(fields, r)
	if r.SpamFlagged {
		t.Error("expected not SpamFlagged for low SCL")
	}
}

func TestDetectVendorSpamScores_CLXScore(t *testing.T) {
	fields := []headerField{
		{Name: "x-clx-score", Value: "-500"},
	}
	r := &EmailHeaderAnalysis{}
	detectVendorSpamScores(fields, r)
	if len(r.SpamFlagSources) == 0 {
		t.Error("expected spam flag source for very negative CLX score")
	}
}

func TestDetectBCCDelivery(t *testing.T) {
	fields := []headerField{
		{Name: "delivered-to", Value: "hidden@example.com"},
	}
	r := &EmailHeaderAnalysis{
		To: "visible@example.com",
	}
	detectBCCDelivery(fields, r)
	if !r.BCCDelivery {
		t.Error("expected BCC delivery to be detected")
	}
	if r.BCCRecipient != "hidden@example.com" {
		t.Errorf("BCCRecipient = %q, want 'hidden@example.com'", r.BCCRecipient)
	}
}

func TestDetectBCCDelivery_MatchingTo(t *testing.T) {
	fields := []headerField{
		{Name: "delivered-to", Value: "user@example.com"},
	}
	r := &EmailHeaderAnalysis{
		To: "user@example.com",
	}
	detectBCCDelivery(fields, r)
	if r.BCCDelivery {
		t.Error("expected no BCC when delivered-to matches To")
	}
}

func TestDetectBCCDelivery_EmptyTo(t *testing.T) {
	fields := []headerField{
		{Name: "delivered-to", Value: "user@example.com"},
	}
	r := &EmailHeaderAnalysis{}
	detectBCCDelivery(fields, r)
	if r.BCCDelivery {
		t.Error("expected no BCC when To is empty")
	}
}

func TestDetectBCCDelivery_OriginalRecipient(t *testing.T) {
	fields := []headerField{
		{Name: "original-recipient", Value: "rfc822;hidden@example.com"},
	}
	r := &EmailHeaderAnalysis{
		To: "visible@example.com",
	}
	detectBCCDelivery(fields, r)
	if !r.BCCDelivery {
		t.Error("expected BCC delivery via original-recipient")
	}
}

func TestScanRawForAuthResults(t *testing.T) {
	r := &EmailHeaderAnalysis{
		RawHeaders: "spf=pass dkim=fail header.d=example.com dmarc=none header.from=example.com",
	}
	scanRawForAuthResults(r)
	if r.SPFResult.Result != "pass" {
		t.Errorf("SPF = %q, want 'pass'", r.SPFResult.Result)
	}
	if len(r.DKIMResults) == 0 || r.DKIMResults[0].Result != "fail" {
		t.Error("expected DKIM fail from raw scan")
	}
	if r.DMARCResult.Result != "none" {
		t.Errorf("DMARC = %q, want 'none'", r.DMARCResult.Result)
	}
}

func TestScanRawForAuthResults_AlreadySet(t *testing.T) {
	r := &EmailHeaderAnalysis{
		RawHeaders:  "spf=fail dkim=fail dmarc=fail",
		SPFResult:   AuthResult{Result: "pass"},
		DKIMResults: []AuthResult{{Result: "pass"}},
		DMARCResult: AuthResult{Result: "pass"},
	}
	scanRawForAuthResults(r)
	if r.SPFResult.Result != "pass" {
		t.Error("should not overwrite existing SPF result")
	}
	if r.DKIMResults[0].Result != "pass" {
		t.Error("should not overwrite existing DKIM result")
	}
	if r.DMARCResult.Result != "pass" {
		t.Error("should not overwrite existing DMARC result")
	}
}

func TestParseAuthResultHeader(t *testing.T) {
	r := &EmailHeaderAnalysis{}
	parseAuthResultHeader("mx.google.com; spf=pass; dkim=pass header.d=example.com; dmarc=pass header.from=example.com", r)
	if r.SPFResult.Result != "pass" {
		t.Errorf("SPF = %q, want 'pass'", r.SPFResult.Result)
	}
	if len(r.DKIMResults) == 0 {
		t.Error("expected DKIM result")
	}
	if r.DMARCResult.Result != "pass" {
		t.Errorf("DMARC = %q, want 'pass'", r.DMARCResult.Result)
	}
}

func TestCheckAlignment(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From:       "user@example.com",
		ReturnPath: "<bounce@other.com>",
		DKIMResults: []AuthResult{
			{Result: "pass", Domain: "example.com"},
		},
	}
	checkAlignment(r)
	if r.AlignmentFromReturnPath != "misaligned" {
		t.Errorf("ReturnPath alignment = %q, want 'misaligned'", r.AlignmentFromReturnPath)
	}
	if r.AlignmentFromDKIM != "aligned" {
		t.Errorf("DKIM alignment = %q, want 'aligned'", r.AlignmentFromDKIM)
	}
}

func TestCheckAlignment_NoReturnPath(t *testing.T) {
	r := &EmailHeaderAnalysis{
		From: "user@example.com",
	}
	checkAlignment(r)
	if r.AlignmentFromReturnPath != "" {
		t.Error("expected empty alignment when no return path")
	}
}

func TestParseReceivedChain(t *testing.T) {
	fields := []headerField{
		{Name: "received", Value: "from server1.example.com ([1.2.3.4]) by mx.test.com with ESMTP; Mon, 02 Jan 2006 15:04:05 -0700"},
		{Name: "received", Value: "from server2.example.com ([5.6.7.8]) by server1.example.com with SMTP; Mon, 02 Jan 2006 15:03:55 -0700"},
	}
	r := &EmailHeaderAnalysis{}
	parseReceivedChain(fields, r)
	if r.HopCount != 2 {
		t.Errorf("HopCount = %d, want 2", r.HopCount)
	}
	if len(r.ReceivedHops) != 2 {
		t.Errorf("expected 2 hops, got %d", len(r.ReceivedHops))
	}
}

func TestExtractHopTimestamp(t *testing.T) {
	hop := &ReceivedHop{}
	ts := extractHopTimestamp(hop, "from server by mx; Mon, 02 Jan 2006 15:04:05 -0700")
	if ts.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if hop.Timestamp == "" {
		t.Error("expected timestamp to be set")
	}
}

func TestExtractHopTimestamp_NoSemicolon(t *testing.T) {
	hop := &ReceivedHop{}
	ts := extractHopTimestamp(hop, "from server by mx")
	if !ts.IsZero() {
		t.Error("expected zero timestamp when no semicolon")
	}
}

func TestGenerateContextBigQuestions_BCCDelivery(t *testing.T) {
	r := &EmailHeaderAnalysis{
		BCCDelivery:  true,
		BCCRecipient: "hidden@example.com",
		To:           "visible@example.com",
	}
	generateContextBigQuestions(r)
	if len(r.BigQuestions) == 0 {
		t.Error("expected big question for BCC delivery")
	}
}

func TestGenerateContextBigQuestions_OriginatingIP(t *testing.T) {
	r := &EmailHeaderAnalysis{
		OriginatingIP: "1.2.3.4",
		From:          "user@example.com",
	}
	generateContextBigQuestions(r)
	if len(r.BigQuestions) == 0 {
		t.Error("expected big question for originating IP")
	}
}

func TestGenerateContextBigQuestions_DMARCPolicyNone(t *testing.T) {
	r := &EmailHeaderAnalysis{
		DMARCPolicy: "none",
		From:        "user@example.com",
	}
	generateContextBigQuestions(r)
	found := false
	for _, q := range r.BigQuestions {
		if strings.Contains(q.Question, "spoofing") {
			found = true
		}
	}
	if !found {
		t.Error("expected big question about DMARC p=none")
	}
}

func TestGenerateContextBigQuestions_BrandMismatch(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SenderBrandMismatch:       true,
		SenderBrandMismatchDetail: "References 'PayPal' but sent from fakeemail.com",
	}
	generateContextBigQuestions(r)
	found := false
	for _, q := range r.BigQuestions {
		if strings.Contains(q.Question, "brand") {
			found = true
		}
	}
	if !found {
		t.Error("expected big question about brand mismatch")
	}
}

func TestGenerateContextBigQuestions_SpamFlagged(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SpamFlagged:     true,
		SpamFlagSources: []string{"X-Spam-Flag: Yes"},
	}
	generateContextBigQuestions(r)
	found := false
	for _, q := range r.BigQuestions {
		if strings.Contains(q.Question, "spam") {
			found = true
		}
	}
	if !found {
		t.Error("expected big question about spam flagging")
	}
}

func TestGenerateContextBigQuestions_MisalignedReturnPath(t *testing.T) {
	r := &EmailHeaderAnalysis{
		AlignmentFromReturnPath: "misaligned",
		SPFResult:               AuthResult{Result: "pass"},
		From:                    "user@example.com",
		ReturnPath:              "bounce@other.com",
	}
	generateContextBigQuestions(r)
	found := false
	for _, q := range r.BigQuestions {
		if strings.Contains(q.Question, "Return-Path") {
			found = true
		}
	}
	if !found {
		t.Error("expected big question about misaligned return-path")
	}
}

func TestGenerateContextBigQuestions_ManyHops(t *testing.T) {
	r := &EmailHeaderAnalysis{
		HopCount: 6,
	}
	generateContextBigQuestions(r)
	found := false
	for _, q := range r.BigQuestions {
		if strings.Contains(q.Question, "hops") {
			found = true
		}
	}
	if !found {
		t.Error("expected big question about many hops")
	}
}

func TestGenerateAuthBigQuestions_SpamAndSubject(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SPFResult:          AuthResult{Result: "pass"},
		DMARCResult:        AuthResult{Result: "pass"},
		DKIMResults:        []AuthResult{{Result: "pass"}},
		SpamFlagged:        true,
		HasSubjectAnalysis: true,
	}
	generateAuthBigQuestions(r, true)
	if len(r.BigQuestions) == 0 {
		t.Error("expected big question for spam+subject+all auth pass")
	}
	if r.BigQuestions[0].Severity != "danger" {
		t.Errorf("expected danger severity, got %q", r.BigQuestions[0].Severity)
	}
}

func TestGenerateAuthBigQuestions_SpamOnly(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SpamFlagged: true,
	}
	generateAuthBigQuestions(r, true)
	if len(r.BigQuestions) == 0 {
		t.Error("expected big question for spam+all auth pass")
	}
}

func TestGenerateAuthBigQuestions_SubjectOnly(t *testing.T) {
	r := &EmailHeaderAnalysis{
		HasSubjectAnalysis: true,
	}
	generateAuthBigQuestions(r, true)
	if len(r.BigQuestions) == 0 {
		t.Error("expected big question for subject analysis+all auth pass")
	}
}

func TestGenerateAuthBigQuestions_BodyAnalysis(t *testing.T) {
	r := &EmailHeaderAnalysis{
		HasBodyAnalysis: true,
	}
	generateAuthBigQuestions(r, true)
	if len(r.BigQuestions) == 0 {
		t.Error("expected big question for body analysis+all auth pass")
	}
	if r.BigQuestions[0].Severity != "warning" {
		t.Errorf("expected warning severity, got %q", r.BigQuestions[0].Severity)
	}
}

func TestGenerateAuthBigQuestions_NotAllPass(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SpamFlagged: true,
	}
	generateAuthBigQuestions(r, false)
	if len(r.BigQuestions) != 0 {
		t.Error("expected no big questions when not all auth pass")
	}
}

func TestGenerateBigQuestions(t *testing.T) {
	r := &EmailHeaderAnalysis{
		BCCDelivery:  true,
		BCCRecipient: "hidden@example.com",
		To:           "visible@example.com",
	}
	generateBigQuestions(r)
	if !r.HasBigQuestions {
		t.Error("expected HasBigQuestions to be true")
	}
}

func TestGenerateBigQuestions_NoBigQuestions(t *testing.T) {
	r := &EmailHeaderAnalysis{}
	generateBigQuestions(r)
	if r.HasBigQuestions {
		t.Error("expected HasBigQuestions to be false")
	}
}

func TestScanBodyPhrasePatterns_SextortionMulti(t *testing.T) {
	body := "i recorded you through webcam while you visited adult website"
	indicators := scanBodyPhrasePatterns(body, nil)
	found := false
	for _, ind := range indicators {
		if ind.Category == "Sextortion Language" {
			found = true
		}
	}
	if !found {
		t.Error("expected sextortion indicator for multiple matches")
	}
}

func TestScanBodyPhrasePatterns_UrgencyMulti(t *testing.T) {
	body := "act now within 24 hours or your account will be suspended"
	indicators := scanBodyPhrasePatterns(body, nil)
	found := false
	for _, ind := range indicators {
		if ind.Category == "Urgency Pressure" {
			found = true
		}
	}
	if !found {
		t.Error("expected urgency pressure indicator")
	}
}

func TestScanBodyPhrasePatterns_GenericGreeting(t *testing.T) {
	body := "dear customer, please verify your account"
	indicators := scanBodyPhrasePatterns(body, nil)
	found := false
	for _, ind := range indicators {
		if ind.Category == "Generic Greeting" {
			found = true
		}
	}
	if !found {
		t.Error("expected generic greeting indicator")
	}
}

func TestScanBodyPhrasePatterns_PaymentDemand(t *testing.T) {
	body := "please send payment via wire transfer immediately"
	indicators := scanBodyPhrasePatterns(body, nil)
	found := false
	for _, ind := range indicators {
		if ind.Category == "Payment Demand" {
			found = true
		}
	}
	if !found {
		t.Error("expected payment demand indicator")
	}
}

func TestScanAdvancedPhrasePatterns_LotteryFraud(t *testing.T) {
	body := "you have won a prize in the lottery. claim your winnings now"
	indicators := scanAdvancedPhrasePatterns(body, nil)
	found := false
	for _, ind := range indicators {
		if ind.Category == "Lottery / Advance-Fee Fraud" {
			found = true
		}
	}
	if !found {
		t.Error("expected lottery fraud indicator")
	}
}

func TestScanAdvancedPhrasePatterns_BusinessScam(t *testing.T) {
	body := "we noticed your growth potential and would like to offer a business loan with guaranteed approval and no pressure to commit"
	indicators := scanAdvancedPhrasePatterns(body, nil)
	found := false
	for _, ind := range indicators {
		if strings.Contains(ind.Category, "Social Engineering") || strings.Contains(ind.Category, "Business") {
			found = true
		}
	}
	if !found {
		t.Error("expected business social engineering indicator")
	}
}

func TestScanURLIndicators_HighDensity(t *testing.T) {
	body := "Click http://a.com http://b.com http://c.com http://d.com http://e.com http://f.com for deals"
	indicators := scanURLIndicators(body, nil)
	found := false
	for _, ind := range indicators {
		if ind.Category == "High URL Density" {
			found = true
		}
	}
	if !found {
		t.Error("expected high URL density indicator")
	}
}

func TestScanFormattingIndicators_NoMatches(t *testing.T) {
	body := "This is a normal email with nothing suspicious."
	indicators := scanFormattingIndicators(body, nil)
	if len(indicators) != 0 {
		t.Error("expected no formatting indicators for normal text")
	}
}

func TestScanContactMethods_NoContact(t *testing.T) {
	body := "Hello, this is a normal email without suspicious contacts."
	indicators := scanContactMethods(body, nil)
	if len(indicators) != 0 {
		t.Error("expected no contact method indicators")
	}
}

func TestAnalyzeSubjectLine_WithIndicators(t *testing.T) {
	r := &EmailHeaderAnalysis{
		Subject: "Your payment of $499.99 invoice confirmed - security alert",
	}
	analyzeSubjectLine(r)
	if !r.HasSubjectAnalysis {
		t.Error("expected HasSubjectAnalysis to be true")
	}
}

func TestDetectHeaderIntelligence(t *testing.T) {
	fields := []headerField{
		{Name: "x-originating-ip", Value: "[10.0.0.1]"},
		{Name: "x-dmarc-policy", Value: "p=reject"},
	}
	r := &EmailHeaderAnalysis{
		From:    "user@example.com",
		Subject: "Test",
	}
	detectHeaderIntelligence(fields, r)
	if r.OriginatingIP != "10.0.0.1" {
		t.Errorf("OriginatingIP = %q, want '10.0.0.1'", r.OriginatingIP)
	}
	if r.DMARCPolicy != "reject" {
		t.Errorf("DMARCPolicy = %q, want 'reject'", r.DMARCPolicy)
	}
}

func TestFallbackSPFFromReceivedSPF_SoftFail(t *testing.T) {
	fields := []headerField{
		{Name: "received-spf", Value: "Softfail (domain of sender)"},
	}
	r := &EmailHeaderAnalysis{}
	fallbackSPFFromReceivedSPF(fields, r)
	if r.SPFResult.Result != "softfail" {
		t.Errorf("expected 'softfail', got %q", r.SPFResult.Result)
	}
}

func TestFallbackSPFFromReceivedSPF_NoMatch(t *testing.T) {
	fields := []headerField{
		{Name: "received-spf", Value: "unknown-status"},
	}
	r := &EmailHeaderAnalysis{}
	fallbackSPFFromReceivedSPF(fields, r)
	if r.SPFResult.Result != "" {
		t.Errorf("expected empty, got %q", r.SPFResult.Result)
	}
}

func TestScanPhraseCategory_JoinAllEvidence(t *testing.T) {
	cfg := phraseScanConfig{
		phrases:               []string{"urgent", "act now"},
		multiCategory:         "Multi",
		multiSev:              "danger",
		multiDesc:             "multiple",
		minForMulti:           3,
		singleCategory:        "Single",
		singleSev:             "warning",
		singleDesc:            "single",
		singleEvidenceJoinAll: true,
	}
	result := scanPhraseCategory("this is urgent", cfg)
	if result == nil {
		t.Fatal("expected non-nil for single match")
	}
	if !strings.Contains(result.Evidence, "Phrases matched:") {
		t.Errorf("expected 'Phrases matched:' in evidence with joinAll, got %q", result.Evidence)
	}
}

func TestCalculateHopDelays_ZeroTimestamp(t *testing.T) {
	hops := []ReceivedHop{{}, {}}
	timestamps := []time.Time{time.Now(), {}}
	calculateHopDelays(hops, timestamps)
	if hops[0].Delay != "" {
		t.Error("expected empty delay when one timestamp is zero")
	}
}

func TestParseReceivedHop_NoIP(t *testing.T) {
	raw := "from mail.example.com by mx.test.com with ESMTP; Mon, 02 Jan 2006 15:04:05 -0700"
	hop, _ := parseReceivedHop(raw, 1)
	if hop.IP != "" {
		t.Errorf("expected empty IP, got %q", hop.IP)
	}
}

func TestUnfoldHeaders_ContinuationAsNewField(t *testing.T) {
	input := "Subject: Test\n\tX-New-Header: value\nFrom: a@b.com"
	result := unfoldHeaders(input)
	if !strings.Contains(result, "X-New-Header:") {
		t.Error("expected continuation line starting with header field to be treated as new field")
	}
}

func TestDetectDMARCPolicy_Reject(t *testing.T) {
	fields := []headerField{
		{Name: "x-dmarc-policy", Value: "p=reject"},
	}
	r := &EmailHeaderAnalysis{}
	detectDMARCPolicy(fields, r)
	if r.DMARCPolicy != "reject" {
		t.Errorf("expected 'reject', got %q", r.DMARCPolicy)
	}
}

func TestDetectDMARCPolicy_NoHeader(t *testing.T) {
	fields := []headerField{}
	r := &EmailHeaderAnalysis{}
	detectDMARCPolicy(fields, r)
	if r.DMARCPolicy != "" {
		t.Errorf("expected empty, got %q", r.DMARCPolicy)
	}
}

func TestStripHTMLTags_Entities(t *testing.T) {
	html := `&lt;hello&gt; &quot;world&quot; &#39;test&#39; &mdash; &ndash; &rsquo; &lsquo; &rdquo; &ldquo; &apos;`
	result := stripHTMLTags(html)
	if !strings.Contains(result, "<hello>") {
		t.Error("expected &lt; to be decoded")
	}
	if !strings.Contains(result, `"world"`) {
		t.Error("expected &quot; to be decoded")
	}
}

func TestGenerateVerdict_Caution_BodyIndicators(t *testing.T) {
	r := &EmailHeaderAnalysis{
		BodyIndicators: []PhishingIndicator{{Severity: "warning"}},
	}
	generateVerdict(r)
	if r.Verdict != "caution" {
		t.Errorf("verdict = %q, want 'caution'", r.Verdict)
	}
}

func TestGenerateVerdict_Caution_SpamFlagged(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SpamFlagged: true,
	}
	generateVerdict(r)
	if r.Verdict != "caution" {
		t.Errorf("verdict = %q, want 'caution'", r.Verdict)
	}
}

func TestGenerateVerdict_Suspicious_MultiplePhishing(t *testing.T) {
	r := &EmailHeaderAnalysis{
		BodyIndicators: []PhishingIndicator{
			{Severity: "danger"},
			{Severity: "danger"},
		},
	}
	generateVerdict(r)
	if r.Verdict != "suspicious" {
		t.Errorf("verdict = %q, want 'suspicious'", r.Verdict)
	}
}

func TestGenerateVerdict_Suspicious_SubjectDanger(t *testing.T) {
	r := &EmailHeaderAnalysis{
		SubjectScamIndicators: []PhishingIndicator{
			{Severity: "danger"},
			{Severity: "danger"},
		},
	}
	generateVerdict(r)
	if r.Verdict != "suspicious" {
		t.Errorf("verdict = %q, want 'suspicious'", r.Verdict)
	}
}

func TestAnalyzeEmailHeaders_WithBody(t *testing.T) {
	raw := "From: sender@example.com\nTo: recipient@test.com\nContent-Type: text/plain\n\nThis is the body with dear customer please send payment"
	result := AnalyzeEmailHeaders(raw)
	if !result.BodyStripped {
		t.Error("expected BodyStripped to be true")
	}
}

func TestIsSuspicious_BigQDanger(t *testing.T) {
	vc := verdictCounts{bigQDanger: 2}
	if !isSuspicious(vc, false) {
		t.Error("expected suspicious with bigQDanger >= 2")
	}
}

func TestIsSuspicious_SpamAndSubjectDanger(t *testing.T) {
	vc := verdictCounts{subjectDanger: 1}
	if !isSuspicious(vc, true) {
		t.Error("expected suspicious with spam + subjectDanger")
	}
}

func TestSuspiciousSummary_PhishingDangerNoAuthDanger(t *testing.T) {
	vc := verdictCounts{phishingDanger: 2, danger: 0}
	r := &EmailHeaderAnalysis{}
	got := suspiciousSummary(vc, r)
	if !strings.Contains(strings.ToLower(got), "mass-mail") {
		t.Errorf("expected mass-mail reference, got %q", got)
	}
}
