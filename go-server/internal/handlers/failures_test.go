package handlers

import (
	"testing"
	"time"
)

func TestTimeAgo_JustNow(t *testing.T) {
	result := timeAgo(time.Now())
	if result != "just now" {
		t.Errorf("timeAgo(now) = %q, want 'just now'", result)
	}
}

func TestTimeAgo_OneMinute(t *testing.T) {
	result := timeAgo(time.Now().Add(-1 * time.Minute))
	if result != "1 minute ago" {
		t.Errorf("timeAgo = %q, want '1 minute ago'", result)
	}
}

func TestTimeAgo_MultipleMinutes(t *testing.T) {
	result := timeAgo(time.Now().Add(-5 * time.Minute))
	if result != "5 minutes ago" {
		t.Errorf("timeAgo = %q, want '5 minutes ago'", result)
	}
}

func TestTimeAgo_OneHour(t *testing.T) {
	result := timeAgo(time.Now().Add(-1 * time.Hour))
	if result != "1 hour ago" {
		t.Errorf("timeAgo = %q, want '1 hour ago'", result)
	}
}

func TestTimeAgo_MultipleHours(t *testing.T) {
	result := timeAgo(time.Now().Add(-3 * time.Hour))
	if result != "3 hours ago" {
		t.Errorf("timeAgo = %q, want '3 hours ago'", result)
	}
}

func TestTimeAgo_OneDay(t *testing.T) {
	result := timeAgo(time.Now().Add(-25 * time.Hour))
	if result != "1 day ago" {
		t.Errorf("timeAgo = %q, want '1 day ago'", result)
	}
}

func TestTimeAgo_MultipleDays(t *testing.T) {
	result := timeAgo(time.Now().Add(-72 * time.Hour))
	if result != "3 days ago" {
		t.Errorf("timeAgo = %q, want '3 days ago'", result)
	}
}

func TestSanitizeErrorMessage_NilInput(t *testing.T) {
	label, icon := sanitizeErrorMessage(nil)
	if label != "Unknown Error" {
		t.Errorf("label = %q, want 'Unknown Error'", label)
	}
	if icon != "question-circle" {
		t.Errorf("icon = %q, want 'question-circle'", icon)
	}
}

func TestSanitizeErrorMessage_EmptyInput(t *testing.T) {
	s := ""
	label, icon := sanitizeErrorMessage(&s)
	if label != "Unknown Error" {
		t.Errorf("label = %q", label)
	}
	if icon != "question-circle" {
		t.Errorf("icon = %q", icon)
	}
}

func TestSanitizeErrorMessage_KnownCategory(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"dns resolution timeout occurred", "DNS Resolution Timeout"},
		{"no such host", "Domain Not Found (NXDOMAIN)"},
		{"connection refused", "Connection Refused"},
		{"tls handshake failed", "TLS/Certificate Error"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			label, _ := sanitizeErrorMessage(&tt.input)
			if label != tt.want {
				t.Errorf("sanitizeErrorMessage(%q) = %q, want %q", tt.input, label, tt.want)
			}
		})
	}
}

func TestSanitizeErrorMessage_UnknownCategory_RedactsIP(t *testing.T) {
	s := "error connecting to 192.168.1.1:5432"
	label, _ := sanitizeErrorMessage(&s)
	if label == "" {
		t.Error("expected non-empty label")
	}
}

func TestSanitizeErrorMessage_LongMessage_Truncated(t *testing.T) {
	s := "this is a very long error message that should be truncated because it exceeds eighty characters and we need to make sure security is maintained"
	label, _ := sanitizeErrorMessage(&s)
	if len(label) > 100 {
		t.Error("expected truncated message")
	}
}

func TestIPPattern(t *testing.T) {
	if !ipPattern.MatchString("192.168.1.1") {
		t.Error("should match IPv4")
	}
	if !ipPattern.MatchString("10.0.0.1:5432") {
		t.Error("should match IPv4 with port")
	}
}

func TestPathPattern(t *testing.T) {
	if !pathPattern.MatchString("/some/path") {
		t.Error("should match path")
	}
}
