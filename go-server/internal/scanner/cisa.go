// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package scanner

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var cisaURL = "https://rules.ncats.cyber.dhs.gov/all.txt"

var (
	cisaIPNets []*net.IPNet
	cisaListMu sync.RWMutex
)

func StartCISARefresh() {
	go func() {
		fetchCISAList()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			fetchCISAList()
		}
	}()
}

func fetchCISAList() {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cisaURL)
	if err != nil {
		slog.Warn("CISA IP list fetch failed", "error", err)
		return
	}
	defer safeClose(resp.Body, "cisa-response")

	if resp.StatusCode != http.StatusOK {
		slog.Warn("CISA IP list non-200 response", "status", resp.StatusCode)
		return
	}

	nets := parseCISABody(resp.Body)

	if len(nets) > 0 {
		cisaListMu.Lock()
		cisaIPNets = nets
		cisaListMu.Unlock()
		slog.Info("CISA IP list refreshed", "entries", len(nets))
	}
}

func parseCISABody(r io.Reader) []*net.IPNet {
	var nets []*net.IPNet
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "/") {
			if strings.Contains(line, ":") {
				line += "/128"
			} else {
				line += "/32"
			}
		}

		_, cidr, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		nets = append(nets, cidr)
	}
	return nets
}

func safeClose(c io.Closer, label string) {
	if err := c.Close(); err != nil {
		slog.Debug("close error", "resource", label, "error", err)
	}
}

func CISAListSize() int {
	cisaListMu.RLock()
	defer cisaListMu.RUnlock()
	return len(cisaIPNets)
}
