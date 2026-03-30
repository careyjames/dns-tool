package analyzer

import (
	"testing"
	"time"
)

func TestSTAPIBudget_CanSpend(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = time.Now().UTC().Format("2006-01")
	b.callCount = 0

	if !b.canSpend(1) {
		t.Error("expected canSpend(1) = true with fresh budget")
	}

	b.callCount = stMonthlyBudget - stBudgetReserve
	if b.canSpend(1) {
		t.Error("expected canSpend(1) = false at budget limit")
	}
}

func TestSTAPIBudget_CanSpend_NewMonthReset(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = "2020-01"
	b.callCount = stMonthlyBudget

	if !b.canSpend(1) {
		t.Error("expected canSpend to reset on new month")
	}
}

func TestSTAPIBudget_CanSpend_RateLimitCooldown(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = time.Now().UTC().Format("2006-01")
	b.callCount = 0
	b.rateLimitedAt = time.Now()

	if b.canSpend(1) {
		t.Error("expected canSpend = false during rate limit cooldown")
	}
}

func TestSTAPIBudget_Spend(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = time.Now().UTC().Format("2006-01")
	b.callCount = 5

	b.spend(3)

	if b.callCount != 8 {
		t.Errorf("expected callCount=8, got %d", b.callCount)
	}
}

func TestSTAPIBudget_MarkRateLimited(t *testing.T) {
	b := &stAPIBudget{}
	b.markRateLimited()

	if b.rateLimitedAt.IsZero() {
		t.Error("expected rateLimitedAt to be set")
	}
}

func TestSTAPIBudget_Stats(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = time.Now().UTC().Format("2006-01")
	b.callCount = 10

	stats := b.stats()

	if stats["used"] != 10 {
		t.Errorf("expected used=10, got %v", stats["used"])
	}
	if stats["budget"] != stMonthlyBudget {
		t.Errorf("expected budget=%d, got %v", stMonthlyBudget, stats["budget"])
	}
	if stats["available"] != true {
		t.Error("expected available=true")
	}
}

func TestSTAPIBudget_Stats_NewMonth(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = "2020-01"
	b.callCount = 999

	stats := b.stats()

	if stats["used"] != 0 {
		t.Errorf("expected used=0 for new month, got %v", stats["used"])
	}
}

func TestSTAPIBudget_Stats_CooldownActive(t *testing.T) {
	b := &stAPIBudget{}
	b.monthKey = time.Now().UTC().Format("2006-01")
	b.callCount = 10
	b.rateLimitedAt = time.Now()

	stats := b.stats()

	if stats["cooldown_active"] != true {
		t.Error("expected cooldown_active=true")
	}
	if stats["available"] != false {
		t.Error("expected available=false during cooldown")
	}
}
