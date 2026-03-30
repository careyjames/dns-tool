package handlers

// dns-tool:scrutiny design

import (
        "crypto/rand"
        "encoding/hex"
        "log/slog"
        "net/http"
        "sync"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/logging"

        "github.com/gin-gonic/gin"
)

type phaseStatus struct {
        Status        string `json:"status"`
        DurationMs    int    `json:"duration_ms,omitempty"`
        CompletedAtMs int    `json:"completed_at_ms,omitempty"`
        StartedAtMs   int    `json:"started_at_ms,omitempty"`
        expectedTasks int
        completedTasks int
}

type scanProgress struct {
        mu          sync.Mutex
        startTime   time.Time
        phases      map[string]*phaseStatus
        complete    bool
        failed      bool
        failReason  string
        redirectURL string
        analysisID  int32
}

type ProgressStore struct {
        store    sync.Map
        stopCh   chan struct{}
        doneCh   chan struct{}
        closeOnce sync.Once
}

func NewProgressStore() *ProgressStore {
        ps := &ProgressStore{
                stopCh: make(chan struct{}),
                doneCh: make(chan struct{}),
        }
        go ps.cleanupLoop()
        return ps
}

func (ps *ProgressStore) Close() {
        if ps.stopCh == nil {
                return
        }
        ps.closeOnce.Do(func() {
                close(ps.stopCh)
                <-ps.doneCh
        })
}

func (ps *ProgressStore) NewToken() (string, *scanProgress) {
        b := make([]byte, 16)
        _, _ = rand.Read(b)
        token := hex.EncodeToString(b)

        callbackCounts := analyzer.PhaseGroupCallbackCounts()

        progress := &scanProgress{
                startTime: time.Now(),
                phases:    make(map[string]*phaseStatus),
        }

        for _, group := range analyzer.PhaseGroupOrder {
                progress.phases[group] = &phaseStatus{
                        Status:        "pending",
                        expectedTasks: callbackCounts[group],
                }
        }

        ps.store.Store(token, progress)
        return token, progress
}

func (ps *ProgressStore) Get(token string) *scanProgress {
        val, ok := ps.store.Load(token)
        if !ok {
                return nil
        }
        return val.(*scanProgress)
}

func (ps *ProgressStore) Delete(token string) {
        ps.store.Delete(token)
}

func (ps *ProgressStore) cleanupLoop() {
        defer close(ps.doneCh)
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()
        for {
                select {
                case <-ps.stopCh:
                        return
                case <-ticker.C:
                        ps.store.Range(func(key, val any) bool {
                                sp := val.(*scanProgress)
                                if time.Since(sp.startTime) > 5*time.Minute {
                                        ps.store.Delete(key)
                                }
                                return true
                        })
                }
        }
}

func (sp *scanProgress) UpdatePhase(group, status string, durationMs int) {
        sp.mu.Lock()
        defer sp.mu.Unlock()
        elapsedMs := int(time.Since(sp.startTime).Milliseconds())
        ps, exists := sp.phases[group]
        if !exists {
                startedAt := elapsedMs - durationMs
                if startedAt < 0 {
                        startedAt = 0
                }
                sp.phases[group] = &phaseStatus{Status: status, DurationMs: durationMs, CompletedAtMs: elapsedMs, StartedAtMs: startedAt, expectedTasks: 1, completedTasks: 1}
                return
        }
        if ps.Status == "done" {
                return
        }
        if ps.StartedAtMs == 0 {
                ps.StartedAtMs = elapsedMs
        }
        if status == "done" {
                ps.completedTasks++
                ps.DurationMs += durationMs
                if ps.expectedTasks > 0 && ps.completedTasks >= ps.expectedTasks {
                        ps.Status = "done"
                        ps.CompletedAtMs = elapsedMs
                } else {
                        ps.Status = "running"
                }
        } else {
                ps.Status = status
        }
}

func (sp *scanProgress) MarkComplete(analysisID int32, redirectURL string) {
        sp.mu.Lock()
        defer sp.mu.Unlock()
        sp.complete = true
        sp.analysisID = analysisID
        sp.redirectURL = redirectURL
        elapsedMs := int(time.Since(sp.startTime).Milliseconds())
        for _, ps := range sp.phases {
                if ps.Status != "done" {
                        ps.Status = "done"
                        ps.completedTasks = ps.expectedTasks
                        if ps.CompletedAtMs == 0 {
                                ps.CompletedAtMs = elapsedMs
                        }
                }
        }
}

func (sp *scanProgress) MarkFailed(errMsg string) {
        sp.mu.Lock()
        defer sp.mu.Unlock()
        sp.complete = true
        sp.failed = true
        sp.failReason = errMsg
        sp.redirectURL = ""
}

func (sp *scanProgress) MakeProgressCallback() analyzer.ProgressCallback {
        return func(group, status string, durationMs int) {
                sp.UpdatePhase(group, status, durationMs)
        }
}

func (sp *scanProgress) MakeInstrumentedProgressCallback(domain, traceID string) analyzer.ProgressCallback {
        return func(group, status string, durationMs int) {
                if status == "running" || status == "started" {
                        slog.LogAttrs(nil, slog.LevelDebug, "phase started",
                                logging.PhaseStarted(domain, traceID, group, "")...)
                }
                sp.UpdatePhase(group, status, durationMs)
                if status == "done" {
                        slog.LogAttrs(nil, slog.LevelDebug, "phase finished",
                                logging.PhaseFinished(domain, traceID, group, "", int64(durationMs), "success")...)
                }
        }
}

func (sp *scanProgress) toJSON() map[string]any {
        sp.mu.Lock()
        defer sp.mu.Unlock()
        elapsedMs := int(time.Since(sp.startTime).Milliseconds())

        status := "running"
        if sp.complete && sp.failed {
                status = "failed"
        } else if sp.complete {
                status = "complete"
        }

        phases := make(map[string]any, len(sp.phases))
        for group, ps := range sp.phases {
                p := map[string]any{
                        "status":          ps.Status,
                        "duration_ms":     ps.DurationMs,
                        "completed_at_ms": ps.CompletedAtMs,
                        "started_at_ms":   ps.StartedAtMs,
                }
                if ps.expectedTasks > 0 {
                        p["tasks_total"] = ps.expectedTasks
                        p["tasks_done"] = ps.completedTasks
                }
                phases[group] = p
        }

        result := map[string]any{
                "status":     status,
                "elapsed_ms": elapsedMs,
                "phases":     phases,
        }

        if sp.complete && sp.redirectURL != "" {
                result["redirect_url"] = sp.redirectURL
                result["analysis_id"] = sp.analysisID
        }
        if sp.failed && sp.failReason != "" {
                result["error"] = sp.failReason
        }

        return result
}

func ScanProgressHandler(store *ProgressStore) gin.HandlerFunc {
        return func(c *gin.Context) {
                token := c.Param("token")
                sp := store.Get(token)
                if sp == nil {
                        c.JSON(http.StatusNotFound, gin.H{"error": "progress token not found or expired"})
                        return
                }
                c.JSON(http.StatusOK, sp.toJSON())
        }
}
