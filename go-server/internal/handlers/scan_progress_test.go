package handlers

import (
	"sync"
	"testing"
	"time"
)

func TestProgressStore_UniqueTokenEntropy(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	tokens := make(map[string]bool)
	for i := 0; i < 50; i++ {
		tok, _ := ps.NewToken()
		if tokens[tok] {
			t.Fatalf("duplicate token generated: %s", tok)
		}
		tokens[tok] = true
		if len(tok) != 32 {
			t.Fatalf("expected 32-char hex token, got %d chars", len(tok))
		}
	}
}

func TestProgressStore_DeleteRemovesToken(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	tok, _ := ps.NewToken()
	ps.Delete(tok)
	if ps.Get(tok) != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestScanProgress_MarkComplete_SetsAllPhasesDone(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()
	sp.MarkComplete(42, "/analysis/42")

	data := sp.toJSON()
	if data["status"] != "complete" {
		t.Fatalf("expected 'complete', got %v", data["status"])
	}
	if data["analysis_id"] != int32(42) {
		t.Fatalf("expected analysis_id 42, got %v", data["analysis_id"])
	}
	if data["redirect_url"] != "/analysis/42" {
		t.Fatalf("expected redirect_url, got %v", data["redirect_url"])
	}

	phases := data["phases"].(map[string]any)
	for group, pRaw := range phases {
		p := pRaw.(map[string]any)
		if p["status"] != "done" {
			t.Fatalf("expected phase %s to be 'done' after MarkComplete, got %v", group, p["status"])
		}
	}
}

func TestScanProgress_MarkFailed_SetsError(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()
	sp.MarkFailed("timeout")

	data := sp.toJSON()
	if data["status"] != "failed" {
		t.Fatalf("expected 'failed', got %v", data["status"])
	}
	if data["error"] != "timeout" {
		t.Fatalf("expected error 'timeout', got %v", data["error"])
	}
	if _, exists := data["redirect_url"]; exists {
		t.Fatal("failed progress should not have redirect_url")
	}
}

func TestScanProgress_ConcurrentSafety(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sp.UpdatePhase("dns_records", "running", 0)
			sp.UpdatePhase("email_auth", "done", 100)
			_ = sp.toJSON()
		}()
	}
	wg.Wait()

	data := sp.toJSON()
	if data["status"] != "running" {
		t.Fatalf("expected 'running' after concurrent updates, got %v", data["status"])
	}
}

func TestScanProgress_DonePhaseIgnoresLaterUpdates(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()
	sp.UpdatePhase("web3_analysis", "done", 50)

	sp.UpdatePhase("web3_analysis", "running", 0)
	data := sp.toJSON()
	phases := data["phases"].(map[string]any)
	w3 := phases["web3_analysis"].(map[string]any)
	if w3["status"] != "done" {
		t.Fatalf("expected 'done' to persist, got %v", w3["status"])
	}
}

func TestScanProgress_TTLEviction(t *testing.T) {
	ps := &ProgressStore{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go ps.cleanupLoop()
	defer ps.Close()

	tok, sp := ps.NewToken()
	sp.mu.Lock()
	sp.startTime = time.Now().Add(-6 * time.Minute)
	sp.mu.Unlock()

	ps.store.Range(func(key, val any) bool {
		s := val.(*scanProgress)
		if time.Since(s.startTime) > 5*time.Minute {
			ps.store.Delete(key)
		}
		return true
	})

	if ps.Get(tok) != nil {
		t.Fatal("expected token to be evicted after TTL")
	}
}

func TestScanProgress_SingleTaskGroupCompletion(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()

	sp.UpdatePhase("web3_analysis", "running", 0)

	data := sp.toJSON()
	phases := data["phases"].(map[string]any)
	w3 := phases["web3_analysis"].(map[string]any)
	if w3["status"] != "running" {
		t.Fatalf("expected 'running', got %v", w3["status"])
	}

	sp.UpdatePhase("web3_analysis", "done", 50)
	data = sp.toJSON()
	phases = data["phases"].(map[string]any)
	w3 = phases["web3_analysis"].(map[string]any)
	if w3["status"] != "done" {
		t.Fatalf("expected 'done' for single-task group, got %v", w3["status"])
	}
}

func TestScanProgress_AnalysisEngineOneCallback(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()

	sp.UpdatePhase("analysis_engine", "running", 0)
	sp.UpdatePhase("analysis_engine", "done", 500)

	data := sp.toJSON()
	phases := data["phases"].(map[string]any)
	eng := phases["analysis_engine"].(map[string]any)
	if eng["status"] != "done" {
		t.Fatalf("expected 'done' for analysis_engine (1 expected callback), got %v", eng["status"])
	}
	if eng["tasks_total"] != 1 {
		t.Fatalf("expected analysis_engine tasks_total=1, got %v", eng["tasks_total"])
	}
}
