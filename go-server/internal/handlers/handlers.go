// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
	"io"
	"log/slog"
)

func safeClose(c io.Closer, label string) {
	if err := c.Close(); err != nil {
		slog.Debug("close error", "resource", label, "error", err)
	}
}
