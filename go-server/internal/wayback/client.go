// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package wayback

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	saveEndpoint  = "https://web.archive.org/save/"
	archivePrefix = "https://web.archive.org/"
	userAgent     = "DNS-Tool-OSINT/1.0 (+https://dnstool.it-help.tech)"
	httpTimeout   = 30 * time.Second
	maxRetries    = 3
	retryBaseWait = 10 * time.Second
)

type ArchiveResult struct {
	URL string
	Err error
}

func Archive(ctx context.Context, targetURL string) ArchiveResult {
	return archiveWithRetry(ctx, saveEndpoint, targetURL)
}

func archiveWithRetry(ctx context.Context, endpoint, targetURL string) ArchiveResult {
	var lastResult ArchiveResult
	for attempt := range maxRetries {
		if attempt > 0 {
			wait := retryBaseWait * time.Duration(attempt)
			slog.Info("Wayback Machine retry", "attempt", attempt+1, "wait", wait, "target", targetURL)
			select {
			case <-ctx.Done():
				return ArchiveResult{Err: fmt.Errorf("wayback: context cancelled during retry: %w", ctx.Err())}
			case <-time.After(wait):
			}
		}
		lastResult = archiveWith(ctx, endpoint, targetURL)
		if lastResult.Err == nil {
			return lastResult
		}
		slog.Warn("Wayback Machine attempt failed", "attempt", attempt+1, "target", targetURL, "error", lastResult.Err)
	}
	return lastResult
}

func archiveWith(ctx context.Context, endpoint, targetURL string) ArchiveResult {
	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqURL := endpoint + targetURL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return ArchiveResult{Err: fmt.Errorf("wayback: build request: %w", err)}
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return ArchiveResult{Err: fmt.Errorf("wayback: request failed: %w", err)}
	}
	defer resp.Body.Close() //nolint:errcheck

	loc := resp.Header.Get("Location")
	if loc != "" && isValidArchiveURL(loc) {
		slog.Info("Wayback Machine archived page", "target", targetURL, "snapshot", loc)
		return ArchiveResult{URL: loc}
	}

	if resp.StatusCode == http.StatusOK {
		snapshot := "https://web.archive.org/web/" + time.Now().UTC().Format("20060102150405") + "/" + targetURL
		slog.Info("Wayback Machine archived page (200)", "target", targetURL, "snapshot", snapshot)
		return ArchiveResult{URL: snapshot}
	}

	return ArchiveResult{Err: fmt.Errorf("wayback: unexpected status %d for %s", resp.StatusCode, targetURL)}
}

func isValidArchiveURL(u string) bool {
	return strings.HasPrefix(u, archivePrefix)
}
