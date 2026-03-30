package analyzer

import (
	"fmt"
	"testing"
)

func TestClassifyExposureResults(t *testing.T) {
	tests := []struct {
		name         string
		findings     []ExposureFinding
		checkedPaths []string
		wantStatus   string
	}{
		{
			"no findings",
			nil,
			[]string{"/.env", "/.git/config"},
			"clear",
		},
		{
			"critical finding",
			[]ExposureFinding{{Severity: "critical", Path: "/.env"}},
			[]string{"/.env"},
			"critical",
		},
		{
			"non-critical finding",
			[]ExposureFinding{{Severity: "high", Path: "/server-status"}},
			[]string{"/server-status"},
			"exposed",
		},
		{
			"mixed findings with critical",
			[]ExposureFinding{
				{Severity: "high", Path: "/phpinfo.php"},
				{Severity: "critical", Path: "/.env"},
			},
			[]string{"/.env", "/phpinfo.php"},
			"critical",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, message := classifyExposureResults(tt.findings, tt.checkedPaths)
			if status != tt.wantStatus {
				t.Errorf("classifyExposureResults() status = %q, want %q", status, tt.wantStatus)
			}
			if message == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func TestClassifyExposureResults_MessageContent(t *testing.T) {
	status, message := classifyExposureResults(nil, []string{"a", "b", "c"})
	if status != "clear" {
		t.Errorf("status = %q, want clear", status)
	}
	expected := fmt.Sprintf("No well-known exposure paths detected (%d paths checked)", 3)
	if message != expected {
		t.Errorf("message = %q, want %q", message, expected)
	}
}

func TestExposureChecks_ContentChecks(t *testing.T) {
	for _, check := range exposureChecks {
		if check.ContentCheck == nil {
			t.Errorf("exposure check for %s has nil ContentCheck", check.Path)
			continue
		}
		if check.ContentCheck("") {
			t.Errorf("exposure check for %s should not match empty body", check.Path)
		}
	}
}

func TestExposureCheck_EnvContentCheck(t *testing.T) {
	envCheck := exposureChecks[0]
	if envCheck.Path != "/.env" {
		t.Skip("first check is not .env")
	}
	if !envCheck.ContentCheck("DB_PASSWORD=secret123") {
		t.Error("should match env file with DB_PASSWORD")
	}
	if !envCheck.ContentCheck("API_KEY=abc123") {
		t.Error("should match env file with API_KEY")
	}
	if envCheck.ContentCheck("just some random text without keywords") {
		t.Error("should not match random text")
	}
}

func TestExposureCheck_GitConfigContentCheck(t *testing.T) {
	gitCheck := exposureChecks[1]
	if gitCheck.Path != "/.git/config" {
		t.Skip("second check is not .git/config")
	}
	if !gitCheck.ContentCheck("[core]\n\tbare = false") {
		t.Error("should match git config with [core]")
	}
	if !gitCheck.ContentCheck("[remote \"origin\"]") {
		t.Error("should match git config with [remote")
	}
	if gitCheck.ContentCheck("404 not found") {
		t.Error("should not match 404 page")
	}
}

func TestExposureCheck_GitHEADContentCheck(t *testing.T) {
	headCheck := exposureChecks[2]
	if headCheck.Path != "/.git/HEAD" {
		t.Skip("third check is not .git/HEAD")
	}
	if !headCheck.ContentCheck("ref: refs/heads/main") {
		t.Error("should match git HEAD ref")
	}
	if headCheck.ContentCheck("some other content") {
		t.Error("should not match non-ref content")
	}
}
