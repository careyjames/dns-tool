// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type mockRateLimiter struct {
	allowed bool
	reason  string
	wait    int
	calls   int
}

func (m *mockRateLimiter) CheckAndRecord(ip, domain string) RateLimitResult {
	m.calls++
	return RateLimitResult{Allowed: m.allowed, Reason: m.reason, WaitSeconds: m.wait}
}

func setupAgentRateLimitRouter(limiter RateLimiter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/agent/search", AgentRateLimit(limiter), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	r.GET("/agent/api", AgentRateLimit(limiter), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.POST("/agent/search", AgentRateLimit(limiter), func(c *gin.Context) {
		c.String(http.StatusOK, "post-ok")
	})
	return r
}

func TestAgentRateLimit_AllowedGET(t *testing.T) {
	limiter := &mockRateLimiter{allowed: true}
	r := setupAgentRateLimitRouter(limiter)

	req := httptest.NewRequest(http.MethodGet, "/agent/search?q=example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if limiter.calls != 1 {
		t.Errorf("limiter.calls = %d, want 1", limiter.calls)
	}
}

func TestAgentRateLimit_BlockedGET_HTMLResponse(t *testing.T) {
	limiter := &mockRateLimiter{allowed: false, reason: "rate_limit", wait: 30}
	r := setupAgentRateLimitRouter(limiter)

	req := httptest.NewRequest(http.MethodGet, "/agent/search?q=example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if body == "" {
		t.Fatal("expected HTML rate-limit response body")
	}
}

func TestAgentRateLimit_BlockedGET_JSONResponse(t *testing.T) {
	limiter := &mockRateLimiter{allowed: false, reason: "rate_limit", wait: 15}
	r := setupAgentRateLimitRouter(limiter)

	req := httptest.NewRequest(http.MethodGet, "/agent/api?q=example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestAgentRateLimit_EmptyQuery_Bypasses(t *testing.T) {
	limiter := &mockRateLimiter{allowed: false}
	r := setupAgentRateLimitRouter(limiter)

	req := httptest.NewRequest(http.MethodGet, "/agent/search", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (empty q bypasses)", w.Code)
	}
	if limiter.calls != 0 {
		t.Errorf("limiter.calls = %d, want 0 (should not check for empty q)", limiter.calls)
	}
}

func TestAgentRateLimit_POSTMethod_Bypasses(t *testing.T) {
	limiter := &mockRateLimiter{allowed: false}
	r := setupAgentRateLimitRouter(limiter)

	req := httptest.NewRequest(http.MethodPost, "/agent/search?q=example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (POST bypasses agent limiter)", w.Code)
	}
	if limiter.calls != 0 {
		t.Errorf("limiter.calls = %d, want 0 (POST should bypass)", limiter.calls)
	}
}
