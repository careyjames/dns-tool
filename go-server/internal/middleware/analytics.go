// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/sha3"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	mapKeyDirect = "direct"
	mapKeyError  = "error"
)

type AnalyticsCollector struct {
	pool       *pgxpool.Pool
	baseHost   string
	excludeIPs map[string]bool

	mu              sync.Mutex
	dailySalt       string
	saltDate        string
	visitors        map[string]bool
	pageviews       int
	pageCounts      map[string]int
	refCounts       map[string]int
	analysisDomains map[string]bool
	analysesRun     int
}

func NewAnalyticsCollector(pool *pgxpool.Pool, baseURL string) *AnalyticsCollector {
	host := ""
	if u, err := url.Parse(baseURL); err == nil {
		host = u.Hostname()
	}
	excluded := parseExcludeIPs()
	ac := &AnalyticsCollector{
		pool:            pool,
		baseHost:        host,
		excludeIPs:      excluded,
		visitors:        make(map[string]bool),
		pageCounts:      make(map[string]int),
		refCounts:       make(map[string]int),
		analysisDomains: make(map[string]bool),
	}
	if len(excluded) > 0 {
		slog.Info("Analytics: excluding owner IPs from visitor counts", "count", len(excluded))
	}
	ac.rotateSalt()
	go ac.flushLoop()
	return ac
}

func parseExcludeIPs() map[string]bool {
	raw := os.Getenv("ANALYTICS_EXCLUDE_IPS")
	if raw == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, ip := range strings.Split(raw, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			m[ip] = true
		}
	}
	return m
}

func (ac *AnalyticsCollector) rotateSalt() {
	today := time.Now().UTC().Format("2006-01-02")
	if ac.saltDate == today {
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		slog.Error("rand.Read failed", "error", err)
	}
	ac.dailySalt = hex.EncodeToString(b)
	ac.saltDate = today
	ac.visitors = make(map[string]bool)
	ac.pageCounts = make(map[string]int)
	ac.refCounts = make(map[string]int)
	ac.analysisDomains = make(map[string]bool)
	ac.analysesRun = 0
	ac.pageviews = 0
}

func (ac *AnalyticsCollector) pseudoID(ip, ua string) string {
	h := sha3.Sum512([]byte(ac.dailySalt + "|" + ip + "|" + ua))
	return hex.EncodeToString(h[:8])
}

func (ac *AnalyticsCollector) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		if strings.HasPrefix(path, "/static/") ||
			strings.HasPrefix(path, "/favicon") ||
			path == "/robots.txt" ||
			path == "/sitemap.xml" ||
			path == "/health" ||
			path == "/sw.js" ||
			path == "/manifest.json" ||
			strings.HasPrefix(path, "/.well-known/") ||
			path == "/llms.txt" ||
			path == "/llms-full.txt" {
			c.Next()
			return
		}

		c.Set("analytics_collector", ac)
		c.Next()

		if c.Writer.Status() >= 400 {
			return
		}

		ip := c.ClientIP()

		if ac.excludeIPs[ip] {
			return
		}
		if role, exists := c.Get(mapKeyUserRole); exists && role == "admin" {
			return
		}

		ua := c.Request.UserAgent()
		referer := extractRefOrigin(c.Request.Referer(), ac.baseHost)
		pagePath := normalizePath(path)

		ac.mu.Lock()
		ac.rotateSalt()
		ac.pageviews++
		pid := ac.pseudoID(ip, ua)
		ac.visitors[pid] = true
		ac.pageCounts[pagePath]++
		if referer != "" && referer != mapKeyDirect {
			ac.refCounts[referer]++
		}
		ac.mu.Unlock()
	}
}

func (ac *AnalyticsCollector) RecordAnalysis(domain string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.analysesRun++
	ac.analysisDomains[strings.ToLower(domain)] = true
}

func extractRefOrigin(ref, baseHost string) string {
	if ref == "" {
		return mapKeyDirect
	}
	u, err := url.Parse(ref)
	if err != nil {
		return mapKeyDirect
	}
	host := u.Hostname()
	if host == "" {
		return mapKeyDirect
	}
	if baseHost != "" && (host == baseHost || strings.HasSuffix(host, "."+baseHost)) {
		return ""
	}
	return host
}

func normalizePath(p string) string {
	if p == "/" {
		return "/"
	}
	p = strings.TrimRight(p, "/")
	parts := strings.SplitN(p, "?", 2)
	return parts[0]
}

func (ac *AnalyticsCollector) flushLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ac.Flush()
	}
}

func (ac *AnalyticsCollector) Flush() {
	ac.mu.Lock()
	if ac.pageviews == 0 {
		ac.mu.Unlock()
		return
	}

	today := time.Now().UTC().Format("2006-01-02")
	pv := ac.pageviews
	uv := len(ac.visitors)
	ar := ac.analysesRun
	ud := len(ac.analysisDomains)

	topPages := make(map[string]int)
	for k, v := range ac.pageCounts {
		topPages[k] = v
	}
	refs := make(map[string]int)
	for k, v := range ac.refCounts {
		refs[k] = v
	}

	ac.pageviews = 0
	ac.analysesRun = 0
	ac.pageCounts = make(map[string]int)
	ac.refCounts = make(map[string]int)
	ac.mu.Unlock()

	pagesJSON, err := json.Marshal(topPages)
	if err != nil {
		slog.Warn("Analytics flush: marshal top_pages", mapKeyError, err)
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		slog.Warn("Analytics flush: marshal refs", mapKeyError, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = ac.pool.Exec(ctx, `
                INSERT INTO site_analytics (date, pageviews, unique_visitors, analyses_run, unique_domains_analyzed, referrer_sources, top_pages)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (date) DO UPDATE SET
                        pageviews = site_analytics.pageviews + EXCLUDED.pageviews,
                        unique_visitors = GREATEST(site_analytics.unique_visitors, EXCLUDED.unique_visitors),
                        analyses_run = site_analytics.analyses_run + EXCLUDED.analyses_run,
                        unique_domains_analyzed = GREATEST(site_analytics.unique_domains_analyzed, EXCLUDED.unique_domains_analyzed),
                        referrer_sources = (
                                SELECT COALESCE(jsonb_object_agg(key, val), '{}'::jsonb)
                                FROM (
                                        SELECT key, SUM(value::bigint) AS val
                                        FROM (
                                                SELECT key, value::bigint FROM jsonb_each_text(site_analytics.referrer_sources)
                                                UNION ALL
                                                SELECT key, value::bigint FROM jsonb_each_text(EXCLUDED.referrer_sources)
                                        ) t
                                        GROUP BY key
                                ) merged
                        ),
                        top_pages = (
                                SELECT COALESCE(jsonb_object_agg(key, val), '{}'::jsonb)
                                FROM (
                                        SELECT key, SUM(value::bigint) AS val
                                        FROM (
                                                SELECT key, value::bigint FROM jsonb_each_text(site_analytics.top_pages)
                                                UNION ALL
                                                SELECT key, value::bigint FROM jsonb_each_text(EXCLUDED.top_pages)
                                        ) t
                                        GROUP BY key
                                ) merged
                        ),
                        updated_at = NOW()
        `, today, pv, uv, ar, ud, refsJSON, pagesJSON)
	if err != nil {
		slog.Error("Analytics flush failed", mapKeyError, err)
	} else {
		slog.Debug("Analytics flushed", "date", today, "pageviews", pv, "unique_visitors", uv)
	}
}
