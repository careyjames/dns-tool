package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestConvertAuditRows(t *testing.T) {
	t.Run("empty rows", func(t *testing.T) {
		entries := convertAuditRows(nil)
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})

	t.Run("rows with all fields", func(t *testing.T) {
		hash := "abc123"
		now := time.Now()
		rows := []dbq.ListHashedAnalysesRow{
			{
				ID:          1,
				Domain:      "example.com",
				PostureHash: &hash,
				CreatedAt:   pgtype.Timestamp{Time: now, Valid: true},
			},
		}
		entries := convertAuditRows(rows)
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].ID != 1 {
			t.Errorf("ID = %d", entries[0].ID)
		}
		if entries[0].Domain != "example.com" {
			t.Errorf("Domain = %q", entries[0].Domain)
		}
		if entries[0].Hash != "abc123" {
			t.Errorf("Hash = %q", entries[0].Hash)
		}
		if entries[0].Timestamp == "" {
			t.Error("expected non-empty Timestamp")
		}
	})

	t.Run("nil posture hash", func(t *testing.T) {
		rows := []dbq.ListHashedAnalysesRow{
			{
				ID:          2,
				Domain:      "test.com",
				PostureHash: nil,
				CreatedAt:   pgtype.Timestamp{Valid: false},
			},
		}
		entries := convertAuditRows(rows)
		if entries[0].Hash != "" {
			t.Errorf("Hash = %q, want empty", entries[0].Hash)
		}
		if entries[0].Timestamp != "" {
			t.Errorf("Timestamp = %q, want empty", entries[0].Timestamp)
		}
	})

	t.Run("multiple rows", func(t *testing.T) {
		hash1 := "hash1"
		hash2 := "hash2"
		now := time.Now()
		rows := []dbq.ListHashedAnalysesRow{
			{ID: 1, Domain: "a.com", PostureHash: &hash1, CreatedAt: pgtype.Timestamp{Time: now, Valid: true}},
			{ID: 2, Domain: "b.com", PostureHash: &hash2, CreatedAt: pgtype.Timestamp{Time: now, Valid: true}},
			{ID: 3, Domain: "c.com", PostureHash: nil, CreatedAt: pgtype.Timestamp{Valid: false}},
		}
		entries := convertAuditRows(rows)
		if len(entries) != 3 {
			t.Errorf("expected 3 entries, got %d", len(entries))
		}
	})
}

func TestParsePageParam(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{"no page param", "/", 1},
		{"valid page 3", "/?page=3", 3},
		{"valid page 1", "/?page=1", 1},
		{"invalid page string", "/?page=abc", 1},
		{"zero page", "/?page=0", 1},
		{"negative page", "/?page=-5", 1},
		{"large page", "/?page=999", 999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, tt.query, nil)
			got := parsePageParam(c)
			if got != tt.expected {
				t.Errorf("got %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestNewAuditLogHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewAuditLogHandler(cfg, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("Config not set correctly")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}

func TestAuditLogEntryStruct(t *testing.T) {
	e := AuditLogEntry{
		ID:        42,
		Domain:    "example.com",
		Hash:      "deadbeef",
		Timestamp: "2024-01-15T10:00:00Z",
	}
	if e.ID != 42 {
		t.Errorf("ID = %d", e.ID)
	}
	if e.Domain != "example.com" {
		t.Errorf("Domain = %q", e.Domain)
	}
}

func TestAuditLogDataStruct(t *testing.T) {
	d := AuditLogData{
		Entries:    []AuditLogEntry{{ID: 1, Domain: "test.com"}},
		Total:      100,
		Page:       2,
		TotalPages: 5,
		HasPrev:    true,
		HasNext:    true,
		PrevPage:   1,
		NextPage:   3,
	}
	if d.Total != 100 {
		t.Errorf("Total = %d", d.Total)
	}
	if len(d.Entries) != 1 {
		t.Errorf("Entries len = %d", len(d.Entries))
	}
}
