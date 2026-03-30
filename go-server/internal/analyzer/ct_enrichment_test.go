package analyzer

import (
	"context"
	"testing"

	"dnstool/go-server/internal/dbq"
)

type mockSTBudgetDB struct {
	budget           dbq.GetSTBudgetRow
	budgetErr        error
	topDomains       []dbq.GetTopAnalyzedDomainsRow
	priorityDomains  []dbq.ListPriorityDomainsRow
	upsertErr        error
	upsertCalled     int
}

func (m *mockSTBudgetDB) GetSTBudget(_ context.Context, _ string) (dbq.GetSTBudgetRow, error) {
	return m.budget, m.budgetErr
}

func (m *mockSTBudgetDB) UpsertSTBudget(_ context.Context, _ dbq.UpsertSTBudgetParams) error {
	m.upsertCalled++
	return m.upsertErr
}

func (m *mockSTBudgetDB) GetTopAnalyzedDomains(_ context.Context, _ int32) ([]dbq.GetTopAnalyzedDomainsRow, error) {
	return m.topDomains, nil
}

func (m *mockSTBudgetDB) ListPriorityDomains(_ context.Context) ([]dbq.ListPriorityDomainsRow, error) {
	return m.priorityDomains, nil
}

type mockCTStoreEnrich struct {
	data    map[string][]map[string]any
	setCalls int
}

func (m *mockCTStoreEnrich) Get(_ context.Context, domain string) ([]map[string]any, bool) {
	d, ok := m.data[domain]
	return d, ok
}

func (m *mockCTStoreEnrich) Set(_ context.Context, domain string, subs []map[string]any, _ string) {
	if m.data == nil {
		m.data = make(map[string][]map[string]any)
	}
	m.data[domain] = subs
	m.setCalls++
}

func TestNewCTEnrichmentJob(t *testing.T) {
	db := &mockSTBudgetDB{}
	store := &mockCTStoreEnrich{}
	job := NewCTEnrichmentJob(db, store)
	if job == nil {
		t.Fatal("expected non-nil job")
	}
	if job.budgetDB != db {
		t.Error("budgetDB mismatch")
	}
	if job.ctStore != store {
		t.Error("ctStore mismatch")
	}
}

func TestCTEnrichmentJob_BuildEnrichmentList_Empty(t *testing.T) {
	db := &mockSTBudgetDB{}
	store := &mockCTStoreEnrich{}
	job := NewCTEnrichmentJob(db, store)

	targets := job.buildEnrichmentList(context.Background())
	if len(targets) != 0 {
		t.Errorf("expected empty targets, got %d", len(targets))
	}
}

func TestCTEnrichmentJob_BuildEnrichmentList_WithPriority(t *testing.T) {
	db := &mockSTBudgetDB{
		priorityDomains: []dbq.ListPriorityDomainsRow{
			{Domain: "example.com"},
			{Domain: "test.org"},
		},
	}
	store := &mockCTStoreEnrich{}
	job := NewCTEnrichmentJob(db, store)

	targets := job.buildEnrichmentList(context.Background())
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if !targets[0].Priority {
		t.Error("expected first target to be priority")
	}
	if targets[0].Domain != "example.com" {
		t.Errorf("first domain = %q", targets[0].Domain)
	}
}

func TestCTEnrichmentJob_BuildEnrichmentList_WithTopDomains(t *testing.T) {
	db := &mockSTBudgetDB{
		topDomains: []dbq.GetTopAnalyzedDomainsRow{
			{Domain: "popular.com"},
			{Domain: "another.net"},
		},
	}
	store := &mockCTStoreEnrich{}
	job := NewCTEnrichmentJob(db, store)

	targets := job.buildEnrichmentList(context.Background())
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].Priority {
		t.Error("expected top domains to not be priority")
	}
}

func TestCTEnrichmentJob_BuildEnrichmentList_Deduplication(t *testing.T) {
	db := &mockSTBudgetDB{
		priorityDomains: []dbq.ListPriorityDomainsRow{
			{Domain: "example.com"},
		},
		topDomains: []dbq.GetTopAnalyzedDomainsRow{
			{Domain: "example.com"},
			{Domain: "unique.net"},
		},
	}
	store := &mockCTStoreEnrich{}
	job := NewCTEnrichmentJob(db, store)

	targets := job.buildEnrichmentList(context.Background())
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets (deduped), got %d", len(targets))
	}
}

func TestCTEnrichmentJob_MergeST_NewSubdomains(t *testing.T) {
	store := &mockCTStoreEnrich{
		data: map[string][]map[string]any{
			"example.com": {
				{mapKeyName: "mail.example.com", mapKeyIsCurrent: true},
			},
		},
	}
	db := &mockSTBudgetDB{}
	job := NewCTEnrichmentJob(db, store)

	job.mergeST(context.Background(), "example.com", []string{"www.example.com", "api.example.com"})

	got := store.data["example.com"]
	if len(got) != 3 {
		t.Fatalf("expected 3 subdomains after merge, got %d", len(got))
	}
	if store.setCalls != 1 {
		t.Errorf("expected 1 Set call, got %d", store.setCalls)
	}
}

func TestCTEnrichmentJob_MergeST_DuplicateSkipped(t *testing.T) {
	store := &mockCTStoreEnrich{
		data: map[string][]map[string]any{
			"example.com": {
				{mapKeyName: "mail.example.com"},
			},
		},
	}
	db := &mockSTBudgetDB{}
	job := NewCTEnrichmentJob(db, store)

	job.mergeST(context.Background(), "example.com", []string{"mail.example.com"})

	if store.setCalls != 0 {
		t.Errorf("expected 0 Set calls for duplicate, got %d", store.setCalls)
	}
}

func TestCTEnrichmentJob_MergeST_NoCacheEntry(t *testing.T) {
	store := &mockCTStoreEnrich{
		data: map[string][]map[string]any{},
	}
	db := &mockSTBudgetDB{}
	job := NewCTEnrichmentJob(db, store)

	job.mergeST(context.Background(), "new.com", []string{"sub.new.com"})

	got := store.data["new.com"]
	if len(got) != 1 {
		t.Fatalf("expected 1 subdomain, got %d", len(got))
	}
	if got[0][mapKeySource] != "securitytrails" {
		t.Errorf("expected source=securitytrails, got %v", got[0][mapKeySource])
	}
}

func TestEnrichmentTargetFields(t *testing.T) {
	et := enrichmentTarget{Domain: "example.com", Priority: true}
	if et.Domain != "example.com" {
		t.Errorf("Domain = %q", et.Domain)
	}
	if !et.Priority {
		t.Error("expected Priority=true")
	}
}

func TestCTEnrichmentConstants(t *testing.T) {
	if stEnrichmentDelay <= 0 {
		t.Error("stEnrichmentDelay is non-positive")
	}
	if stEnrichmentInterval <= 0 {
		t.Error("stEnrichmentInterval is non-positive")
	}
	if stTopDomainLimit <= 0 {
		t.Error("stTopDomainLimit is non-positive")
	}
}
