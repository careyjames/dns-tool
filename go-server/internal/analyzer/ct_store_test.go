// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "sync"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgtype"
)

type mockDBTX struct {
        mu      sync.Mutex
        cache   map[string]dbq.CtSubdomainCache
        purged  bool
        failGet bool
        failSet bool
}

func newMockDBTX() *mockDBTX {
        return &mockDBTX{cache: make(map[string]dbq.CtSubdomainCache)}
}

func (m *mockDBTX) GetCTCache(_ context.Context, domain string) (dbq.CtSubdomainCache, error) {
        m.mu.Lock()
        defer m.mu.Unlock()
        if m.failGet {
                return dbq.CtSubdomainCache{}, fmt.Errorf("mock get error")
        }
        row, ok := m.cache[domain]
        if !ok {
                return dbq.CtSubdomainCache{}, fmt.Errorf("not found")
        }
        if row.ExpiresAt.Valid && row.ExpiresAt.Time.Before(time.Now()) {
                delete(m.cache, domain)
                return dbq.CtSubdomainCache{}, fmt.Errorf("expired")
        }
        return row, nil
}

func (m *mockDBTX) UpsertCTCache(_ context.Context, arg dbq.UpsertCTCacheParams) error {
        m.mu.Lock()
        defer m.mu.Unlock()
        if m.failSet {
                return fmt.Errorf("mock set error")
        }
        m.cache[arg.Domain] = dbq.CtSubdomainCache{
                Domain:      arg.Domain,
                Subdomains:  arg.Subdomains,
                UniqueCount: arg.UniqueCount,
                Source:      arg.Source,
                FetchedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
                ExpiresAt:   pgtype.Timestamp{Time: time.Now().Add(24 * time.Hour), Valid: true},
        }
        return nil
}

func (m *mockDBTX) PurgeCTCacheExpired(_ context.Context) error {
        m.mu.Lock()
        defer m.mu.Unlock()
        m.purged = true
        now := time.Now()
        for k, v := range m.cache {
                if v.ExpiresAt.Valid && v.ExpiresAt.Time.Before(now) {
                        delete(m.cache, k)
                }
        }
        return nil
}

func TestPgCTStore_RoundTrip(t *testing.T) {
        mock := newMockDBTX()
        store := NewPgCTStore(mock)
        ctx := context.Background()

        _, ok := store.Get(ctx, "example.com")
        if ok {
                t.Error("expected cache miss for unknown domain")
        }

        data := []map[string]any{
                {"name": "www.example.com", "is_current": true, "source": "crt.sh"},
                {"name": "mail.example.com", "is_current": false, "source": "crt.sh"},
        }
        store.Set(ctx, "example.com", data, "crt.sh")

        result, ok := store.Get(ctx, "example.com")
        if !ok {
                t.Fatal("expected cache hit after Set")
        }
        if len(result) != 2 {
                t.Fatalf("expected 2 subdomains, got %d", len(result))
        }

        name0, _ := result[0]["name"].(string)
        name1, _ := result[1]["name"].(string)
        if name0 != "www.example.com" || name1 != "mail.example.com" {
                t.Errorf("unexpected subdomain names: %s, %s", name0, name1)
        }
}

func TestPgCTStore_Overwrite(t *testing.T) {
        mock := newMockDBTX()
        store := NewPgCTStore(mock)
        ctx := context.Background()

        store.Set(ctx, "example.com", []map[string]any{
                {"name": "www.example.com"},
        }, "crt.sh")

        store.Set(ctx, "example.com", []map[string]any{
                {"name": "www.example.com"},
                {"name": "api.example.com"},
                {"name": "mail.example.com"},
        }, "crt.sh+securitytrails")

        result, ok := store.Get(ctx, "example.com")
        if !ok {
                t.Fatal("expected cache hit")
        }
        if len(result) != 3 {
                t.Fatalf("expected 3 subdomains after overwrite, got %d", len(result))
        }
}

func TestPgCTStore_TTLExpiry(t *testing.T) {
        mock := newMockDBTX()
        store := NewPgCTStore(mock)
        ctx := context.Background()

        store.Set(ctx, "example.com", []map[string]any{
                {"name": "www.example.com"},
        }, "crt.sh")

        mock.mu.Lock()
        entry := mock.cache["example.com"]
        entry.ExpiresAt = pgtype.Timestamp{Time: time.Now().Add(-1 * time.Hour), Valid: true}
        mock.cache["example.com"] = entry
        mock.mu.Unlock()

        _, ok := store.Get(ctx, "example.com")
        if ok {
                t.Error("expected cache miss for expired entry")
        }
}

func TestPgCTStore_GetError(t *testing.T) {
        mock := newMockDBTX()
        mock.failGet = true
        store := NewPgCTStore(mock)
        ctx := context.Background()

        _, ok := store.Get(ctx, "example.com")
        if ok {
                t.Error("expected cache miss when DB fails")
        }
}

func TestPgCTStore_SetError(t *testing.T) {
        mock := newMockDBTX()
        mock.failSet = true
        store := NewPgCTStore(mock)
        ctx := context.Background()

        store.Set(ctx, "example.com", []map[string]any{
                {"name": "www.example.com"},
        }, "crt.sh")

        mock.failSet = false
        mock.failGet = false
        _, ok := store.Get(ctx, "example.com")
        if ok {
                t.Error("expected no data when Set failed")
        }
}

func TestPgCTStore_CorruptJSON(t *testing.T) {
        mock := newMockDBTX()
        store := NewPgCTStore(mock)
        ctx := context.Background()

        mock.mu.Lock()
        mock.cache["example.com"] = dbq.CtSubdomainCache{
                Domain:      "example.com",
                Subdomains:  []byte(`{not valid json`),
                UniqueCount: 1,
                Source:      "crt.sh",
                FetchedAt:   pgtype.Timestamp{Time: time.Now(), Valid: true},
                ExpiresAt:   pgtype.Timestamp{Time: time.Now().Add(24 * time.Hour), Valid: true},
        }
        mock.mu.Unlock()

        _, ok := store.Get(ctx, "example.com")
        if ok {
                t.Error("expected cache miss for corrupt JSON")
        }
}

type mockBudgetDB struct {
        mu              sync.Mutex
        budgets         map[string]dbq.GetSTBudgetRow
        domains         []dbq.GetTopAnalyzedDomainsRow
        priorityDomains []dbq.ListPriorityDomainsRow
}

func newMockBudgetDB() *mockBudgetDB {
        return &mockBudgetDB{
                budgets: make(map[string]dbq.GetSTBudgetRow),
        }
}

func (m *mockBudgetDB) GetSTBudget(_ context.Context, monthKey string) (dbq.GetSTBudgetRow, error) {
        m.mu.Lock()
        defer m.mu.Unlock()
        b, ok := m.budgets[monthKey]
        if !ok {
                return dbq.GetSTBudgetRow{}, fmt.Errorf("not found")
        }
        return b, nil
}

func (m *mockBudgetDB) UpsertSTBudget(_ context.Context, arg dbq.UpsertSTBudgetParams) error {
        m.mu.Lock()
        defer m.mu.Unlock()
        m.budgets[arg.MonthKey] = dbq.GetSTBudgetRow{
                MonthKey:        arg.MonthKey,
                CallsUsed:       arg.CallsUsed,
                DomainsEnriched: arg.DomainsEnriched,
        }
        return nil
}

func (m *mockBudgetDB) GetTopAnalyzedDomains(_ context.Context, limit int32) ([]dbq.GetTopAnalyzedDomainsRow, error) {
        m.mu.Lock()
        defer m.mu.Unlock()
        if int(limit) >= len(m.domains) {
                return m.domains, nil
        }
        return m.domains[:limit], nil
}

func (m *mockBudgetDB) ListPriorityDomains(_ context.Context) ([]dbq.ListPriorityDomainsRow, error) {
        m.mu.Lock()
        defer m.mu.Unlock()
        return m.priorityDomains, nil
}

type memoryCTStore struct {
        mu   sync.Mutex
        data map[string][]map[string]any
}

func newMemoryCTStore() *memoryCTStore {
        return &memoryCTStore{data: make(map[string][]map[string]any)}
}

func (s *memoryCTStore) Get(_ context.Context, domain string) ([]map[string]any, bool) {
        s.mu.Lock()
        defer s.mu.Unlock()
        d, ok := s.data[domain]
        return d, ok
}

func (s *memoryCTStore) Set(_ context.Context, domain string, data []map[string]any, _ string) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.data[domain] = data
}

func TestCTEnrichment_BudgetPersistBeforeCall(t *testing.T) {
        budgetDB := newMockBudgetDB()
        ctStore := newMemoryCTStore()

        budgetDB.domains = []dbq.GetTopAnalyzedDomainsRow{
                {Domain: "example.com", AnalysisCount: 100},
                {Domain: "test.org", AnalysisCount: 50},
        }

        job := NewCTEnrichmentJob(budgetDB, ctStore)

        ctx := context.Background()
        job.run(ctx)

        monthKey := time.Now().Format("2006-01")
        budget, err := budgetDB.GetSTBudget(ctx, monthKey)
        if err != nil {
                t.Fatalf("expected budget row, got error: %v", err)
        }

        if budget.CallsUsed < 1 {
                t.Errorf("expected at least 1 call used, got %d", budget.CallsUsed)
        }

        var enriched []string
        if len(budget.DomainsEnriched) > 0 {
                _ = json.Unmarshal(budget.DomainsEnriched, &enriched)
        }
        if len(enriched) < 1 {
                t.Errorf("expected at least 1 domain enriched, got %d", len(enriched))
        }
}

func TestCTEnrichment_BudgetExhausted(t *testing.T) {
        budgetDB := newMockBudgetDB()
        ctStore := newMemoryCTStore()

        monthKey := time.Now().Format("2006-01")
        budgetDB.budgets[monthKey] = dbq.GetSTBudgetRow{
                MonthKey:  monthKey,
                CallsUsed: int32(stMonthlyBudget),
        }

        budgetDB.domains = []dbq.GetTopAnalyzedDomainsRow{
                {Domain: "example.com", AnalysisCount: 100},
        }

        job := NewCTEnrichmentJob(budgetDB, ctStore)
        job.run(context.Background())

        budget, _ := budgetDB.GetSTBudget(context.Background(), monthKey)
        if budget.CallsUsed != int32(stMonthlyBudget) {
                t.Errorf("expected calls_used to stay at %d, got %d", stMonthlyBudget, budget.CallsUsed)
        }
}

func TestCTEnrichment_SkipsAlreadyEnriched(t *testing.T) {
        budgetDB := newMockBudgetDB()
        ctStore := newMemoryCTStore()

        monthKey := time.Now().Format("2006-01")
        enrichedJSON, _ := json.Marshal([]string{"example.com"})
        budgetDB.budgets[monthKey] = dbq.GetSTBudgetRow{
                MonthKey:        monthKey,
                CallsUsed:       1,
                DomainsEnriched: enrichedJSON,
        }

        budgetDB.domains = []dbq.GetTopAnalyzedDomainsRow{
                {Domain: "example.com", AnalysisCount: 100},
        }

        job := NewCTEnrichmentJob(budgetDB, ctStore)
        job.run(context.Background())

        budget, _ := budgetDB.GetSTBudget(context.Background(), monthKey)
        if budget.CallsUsed != 1 {
                t.Errorf("expected calls_used to stay at 1 (already enriched), got %d", budget.CallsUsed)
        }
}

func TestCTEnrichment_MonthlyReset(t *testing.T) {
        budgetDB := newMockBudgetDB()

        now := time.Now()
        lastMonth := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01")
        budgetDB.budgets[lastMonth] = dbq.GetSTBudgetRow{
                MonthKey:  lastMonth,
                CallsUsed: int32(stMonthlyBudget),
        }

        currentMonth := now.Format("2006-01")
        _, err := budgetDB.GetSTBudget(context.Background(), currentMonth)
        if err == nil {
                t.Error("expected no budget for current month (fresh start)")
        }
}

func TestCTEnrichment_MergeST(t *testing.T) {
        ctStore := newMemoryCTStore()
        budgetDB := newMockBudgetDB()
        job := NewCTEnrichmentJob(budgetDB, ctStore)
        ctx := context.Background()

        ctStore.Set(ctx, "example.com", []map[string]any{
                {"name": "www.example.com", "is_current": true, "source": "crt.sh"},
        }, "crt.sh")

        job.mergeST(ctx, "example.com", []string{
                "www.example.com",
                "api.example.com",
                "mail.example.com",
        })

        result, ok := ctStore.Get(ctx, "example.com")
        if !ok {
                t.Fatal("expected data after merge")
        }
        if len(result) != 3 {
                t.Fatalf("expected 3 subdomains (1 existing + 2 new), got %d", len(result))
        }

        names := make(map[string]bool)
        for _, sd := range result {
                n, _ := sd["name"].(string)
                names[n] = true
        }
        for _, expected := range []string{"www.example.com", "api.example.com", "mail.example.com"} {
                if !names[expected] {
                        t.Errorf("expected %s in merged result", expected)
                }
        }
}

func TestCTEnrichment_MergeSTNoDuplicates(t *testing.T) {
        ctStore := newMemoryCTStore()
        budgetDB := newMockBudgetDB()
        job := NewCTEnrichmentJob(budgetDB, ctStore)
        ctx := context.Background()

        ctStore.Set(ctx, "example.com", []map[string]any{
                {"name": "www.example.com", "source": "crt.sh"},
                {"name": "api.example.com", "source": "crt.sh"},
        }, "crt.sh")

        job.mergeST(ctx, "example.com", []string{
                "www.example.com",
                "api.example.com",
        })

        result, ok := ctStore.Get(ctx, "example.com")
        if !ok {
                t.Fatal("expected data")
        }
        if len(result) != 2 {
                t.Fatalf("expected 2 subdomains (no new ones), got %d", len(result))
        }
}

func TestCTEnrichment_PriorityDomainsFirst(t *testing.T) {
        budgetDB := newMockBudgetDB()
        ctStore := newMemoryCTStore()

        budgetDB.priorityDomains = []dbq.ListPriorityDomainsRow{
                {Domain: "nlnetlabs.nl", Reason: "DANE pioneer"},
                {Domain: "ithelpsd.com", Reason: "Our domain"},
        }
        budgetDB.domains = []dbq.GetTopAnalyzedDomainsRow{
                {Domain: "popular.com", AnalysisCount: 500},
                {Domain: "nlnetlabs.nl", AnalysisCount: 10},
        }

        job := NewCTEnrichmentJob(budgetDB, ctStore)
        targets := job.buildEnrichmentList(context.Background())

        if len(targets) != 3 {
                t.Fatalf("expected 3 targets (2 priority + 1 user), got %d", len(targets))
        }
        if targets[0].Domain != "nlnetlabs.nl" || !targets[0].Priority {
                t.Errorf("expected first target to be priority nlnetlabs.nl, got %s (priority=%v)", targets[0].Domain, targets[0].Priority)
        }
        if targets[1].Domain != "ithelpsd.com" || !targets[1].Priority {
                t.Errorf("expected second target to be priority ithelpsd.com, got %s (priority=%v)", targets[1].Domain, targets[1].Priority)
        }
        if targets[2].Domain != "popular.com" || targets[2].Priority {
                t.Errorf("expected third target to be user popular.com, got %s (priority=%v)", targets[2].Domain, targets[2].Priority)
        }
}

func TestCTEnrichment_PriorityDedup(t *testing.T) {
        budgetDB := newMockBudgetDB()
        ctStore := newMemoryCTStore()

        budgetDB.priorityDomains = []dbq.ListPriorityDomainsRow{
                {Domain: "google.com", Reason: "Industry benchmark"},
        }
        budgetDB.domains = []dbq.GetTopAnalyzedDomainsRow{
                {Domain: "google.com", AnalysisCount: 1000},
                {Domain: "other.com", AnalysisCount: 50},
        }

        job := NewCTEnrichmentJob(budgetDB, ctStore)
        targets := job.buildEnrichmentList(context.Background())

        if len(targets) != 2 {
                t.Fatalf("expected 2 targets (google deduped), got %d", len(targets))
        }
        if targets[0].Domain != "google.com" || !targets[0].Priority {
                t.Errorf("expected google.com as priority, got %s", targets[0].Domain)
        }
        if targets[1].Domain != "other.com" {
                t.Errorf("expected other.com as user domain, got %s", targets[1].Domain)
        }
}

func TestCTEnrichment_MergeSTEmptyExisting(t *testing.T) {
        ctStore := newMemoryCTStore()
        budgetDB := newMockBudgetDB()
        job := NewCTEnrichmentJob(budgetDB, ctStore)
        ctx := context.Background()

        job.mergeST(ctx, "example.com", []string{
                "www.example.com",
                "api.example.com",
        })

        result, ok := ctStore.Get(ctx, "example.com")
        if !ok {
                t.Fatal("expected data after merge into empty store")
        }
        if len(result) != 2 {
                t.Fatalf("expected 2 subdomains, got %d", len(result))
        }
}
