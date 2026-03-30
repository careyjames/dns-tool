// dns-tool:scrutiny plumbing
package logging

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "strings"
        "sync"
        "time"
)

const (
        discordRateWindow  = 60 * time.Second
        discordHTTPTimeout = 10 * time.Second
        maxDiscordBody     = 1024
)

type DiscordSink struct {
        webhookURL string
        client     *http.Client
        mu         sync.Mutex
        lastSent   map[string]time.Time
        minLevel   slog.Level
}

func NewDiscordSink(webhookURL string) *DiscordSink {
        return &DiscordSink{
                webhookURL: webhookURL,
                client:     &http.Client{Timeout: discordHTTPTimeout},
                lastSent:   make(map[string]time.Time),
                minLevel:   slog.LevelError,
        }
}

func (d *DiscordSink) ShouldSend(level slog.Level, event string, category string) bool {
        if d.webhookURL == "" {
                return false
        }
        isSecurityCategory := category == CategorySecurity
        isCriticalLevel := level >= slog.LevelError
        if !isSecurityCategory && !isCriticalLevel {
                return false
        }
        d.mu.Lock()
        defer d.mu.Unlock()
        key := fmt.Sprintf("%s:%s:%d", category, event, level)
        if last, ok := d.lastSent[key]; ok && time.Since(last) < discordRateWindow {
                return false
        }
        d.lastSent[key] = time.Now()
        return true
}

type discordEmbed struct {
        Title       string         `json:"title"`
        Description string         `json:"description"`
        Color       int            `json:"color"`
        Fields      []discordField `json:"fields,omitempty"`
        Timestamp   string         `json:"timestamp,omitempty"`
}

type discordField struct {
        Name   string `json:"name"`
        Value  string `json:"value"`
        Inline bool   `json:"inline"`
}

type discordPayload struct {
        Username string         `json:"username"`
        Embeds   []discordEmbed `json:"embeds"`
}

func levelColor(level slog.Level) int {
        switch {
        case level >= slog.LevelError:
                return 0xDC3545
        case level >= slog.LevelWarn:
                return 0xFFC107
        default:
                return 0x6C757D
        }
}

func levelLabel(level slog.Level) string {
        switch {
        case level >= slog.LevelError:
                return "CRITICAL"
        case level >= slog.LevelWarn:
                return "WARNING"
        default:
                return "INFO"
        }
}

func (d *DiscordSink) Send(ctx context.Context, level slog.Level, msg string, attrs map[string]string) {
        fields := make([]discordField, 0, len(attrs))
        for k, v := range attrs {
                if v == "" || v == "[REDACTED]" {
                        continue
                }
                fields = append(fields, discordField{
                        Name:   k,
                        Value:  truncate(v, 200),
                        Inline: true,
                })
        }

        payload := discordPayload{
                Username: "DNS Tool Logger",
                Embeds: []discordEmbed{
                        {
                                Title:       fmt.Sprintf("[%s] %s", levelLabel(level), truncate(msg, 200)),
                                Description: buildDescription(attrs),
                                Color:       levelColor(level),
                                Fields:      fields,
                                Timestamp:   time.Now().UTC().Format(time.RFC3339),
                        },
                },
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return
        }

        sendCtx, cancel := context.WithTimeout(ctx, discordHTTPTimeout)
        defer cancel()

        req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
        if err != nil {
                return
        }
        req.Header.Set("Content-Type", "application/json")

        resp, err := d.client.Do(req)
        if err != nil {
                return
        }
        defer func() {
                io.Copy(io.Discard, resp.Body) //nolint:errcheck
                resp.Body.Close()
        }()
}

func truncate(s string, max int) string {
        if len(s) <= max {
                return s
        }
        return s[:max] + "…"
}

func buildDescription(attrs map[string]string) string {
        var parts []string
        if d, ok := attrs[AttrDomain]; ok && d != "" {
                parts = append(parts, fmt.Sprintf("Domain: **%s**", d))
        }
        if c, ok := attrs[AttrCategory]; ok && c != "" {
                parts = append(parts, fmt.Sprintf("Category: %s", c))
        }
        if e, ok := attrs[AttrErrorChain]; ok && e != "" {
                parts = append(parts, fmt.Sprintf("```\n%s\n```", truncate(e, 500)))
        }
        if len(parts) == 0 {
                return ""
        }
        return strings.Join(parts, "\n")
}
