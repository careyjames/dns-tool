// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package notifier

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/dbq"
)

const (
        httpTimeout       = 10 * time.Second
        maxResponseBody   = 1024
        headerContentType = "Content-Type"
        mimeJSON          = "application/json"

        mapKeyDomain         = "domain"
        mapKeyNotificationId = "notification_id"
)

type NotifierDB interface {
        ListPendingNotifications(ctx context.Context, limit int32) ([]dbq.ListPendingNotificationsRow, error)
        UpdateDriftNotificationStatus(ctx context.Context, arg dbq.UpdateDriftNotificationStatusParams) error
}

type Notifier struct {
        Queries    NotifierDB
        Client     *http.Client
        AllowLocal bool
}

func New(queries *dbq.Queries) *Notifier {
        return &Notifier{
                Queries: queries,
                Client: &http.Client{
                        Timeout: httpTimeout,
                },
        }
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

func severityColor(severity string) int {
        switch strings.ToLower(severity) {
        case "critical":
                return 0xDC3545
        case "high":
                return 0xFD7E14
        case "medium":
                return 0xFFC107
        case "low":
                return 0x17A2B8
        default:
                return 0x6C757D
        }
}

func (n *Notifier) DeliverPending(ctx context.Context, batchSize int32) (int, error) {
        pending, err := n.Queries.ListPendingNotifications(ctx, batchSize)
        if err != nil {
                return 0, fmt.Errorf("listing pending notifications: %w", err)
        }
        if len(pending) == 0 {
                return 0, nil
        }

        delivered := 0
        for _, notif := range pending {
                if n.deliverSingle(ctx, notif) {
                        delivered++
                }
        }
        return delivered, nil
}

func (n *Notifier) sendByType(ctx context.Context, notif dbq.ListPendingNotificationsRow) (int, error) {
        if notif.EndpointType == "discord" {
                return n.sendDiscord(ctx, notif)
        }
        return n.sendGenericWebhook(ctx, notif)
}

func (n *Notifier) deliverSingle(ctx context.Context, notif dbq.ListPendingNotificationsRow) bool {
        httpCode, sendErr := n.sendByType(ctx, notif)

        status, respCode, respBody := classifyDeliveryResult(httpCode, sendErr)
        logDeliveryResult(notif, httpCode, sendErr)

        updateErr := n.Queries.UpdateDriftNotificationStatus(ctx, dbq.UpdateDriftNotificationStatusParams{
                ID:           notif.ID,
                Status:       status,
                ResponseCode: respCode,
                ResponseBody: respBody,
        })
        if updateErr != nil {
                slog.Error("Failed to update notification status",
                        mapKeyNotificationId, notif.ID,
                        "error", updateErr,
                )
        }
        return sendErr == nil
}

func classifyDeliveryResult(httpCode int, sendErr error) (string, *int32, *string) {
        status := "delivered"
        var respCode *int32
        var respBody *string
        if httpCode > 0 {
                code := int32(httpCode)
                respCode = &code
        }
        if sendErr != nil {
                status = "failed"
                errMsg := sendErr.Error()
                respBody = &errMsg
        }
        return status, respCode, respBody
}

func logDeliveryResult(notif dbq.ListPendingNotificationsRow, httpCode int, sendErr error) {
        if sendErr != nil {
                slog.Error("Notification delivery failed",
                        mapKeyNotificationId, notif.ID,
                        "endpoint_type", notif.EndpointType,
                        mapKeyDomain, notif.Domain,
                        "http_code", httpCode,
                        "error", sendErr,
                )
                return
        }
        slog.Info("Notification delivered",
                mapKeyNotificationId, notif.ID,
                "endpoint_type", notif.EndpointType,
                mapKeyDomain, notif.Domain,
                "http_code", httpCode,
        )
}

func parseDiffFields(raw []byte) []discordField {
        var diffFields []struct {
                Field string `json:"field"`
                Old   string `json:"old"`
                New   string `json:"new"`
        }
        if len(raw) == 0 || json.Unmarshal(raw, &diffFields) != nil {
                return nil
        }
        fields := make([]discordField, 0, len(diffFields))
        for _, df := range diffFields {
                fields = append(fields, discordField{
                        Name:   df.Field,
                        Value:  fmt.Sprintf("`%s` → `%s`", df.Old, df.New),
                        Inline: true,
                })
        }
        return fields
}

func (n *Notifier) sendDiscord(ctx context.Context, notif dbq.ListPendingNotificationsRow) (int, error) {
        if !n.AllowLocal {
                if err := isSSRFSafe(notif.Url); err != nil {
                        return 0, fmt.Errorf("SSRF check failed for Discord webhook: %w", err)
                }
        }

        fields := parseDiffFields(notif.DiffSummary)

        payload := discordPayload{
                Username: "DNS Tool Drift Engine",
                Embeds: []discordEmbed{
                        {
                                Title:       fmt.Sprintf("Drift Detected: %s", notif.Domain),
                                Description: fmt.Sprintf("Security posture change detected for **%s** (severity: **%s**).", notif.Domain, notif.Severity),
                                Color:       severityColor(notif.Severity),
                                Fields:      fields,
                                Timestamp:   time.Now().UTC().Format(time.RFC3339),
                        },
                },
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return 0, fmt.Errorf("marshaling Discord payload: %w", err)
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, notif.Url, bytes.NewReader(body))
        if err != nil {
                return 0, fmt.Errorf("creating Discord request: %w", err)
        }
        req.Header.Set(headerContentType, mimeJSON)

        resp, err := n.Client.Do(req)
        if err != nil {
                return 0, fmt.Errorf("sending Discord webhook: %w", err)
        }
        defer safeClose(resp.Body, "discord-webhook-response")

        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
                respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
                if readErr != nil {
                        slog.Warn("Failed to read Discord error response body", "error", readErr)
                }
                return resp.StatusCode, fmt.Errorf("Discord returned %d: %s", resp.StatusCode, string(respBody))
        }
        return resp.StatusCode, nil
}

func (n *Notifier) sendGenericWebhook(ctx context.Context, notif dbq.ListPendingNotificationsRow) (int, error) {
        if !n.AllowLocal {
                if err := isSSRFSafe(notif.Url); err != nil {
                        return 0, fmt.Errorf("SSRF check failed for webhook: %w", err)
                }
        }

        payload := map[string]any{
                "event":      "drift_detected",
                mapKeyDomain: notif.Domain,
                "severity":   notif.Severity,
                "timestamp":  time.Now().UTC().Format(time.RFC3339),
        }

        if len(notif.DiffSummary) > 0 {
                var raw json.RawMessage = notif.DiffSummary
                payload["diff_summary"] = raw
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return 0, fmt.Errorf("marshaling webhook payload: %w", err)
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, notif.Url, bytes.NewReader(body))
        if err != nil {
                return 0, fmt.Errorf("creating webhook request: %w", err)
        }
        req.Header.Set(headerContentType, mimeJSON)
        if notif.Secret != nil && *notif.Secret != "" {
                req.Header.Set("X-Webhook-Secret", *notif.Secret)
        }

        resp, err := n.Client.Do(req)
        if err != nil {
                return 0, fmt.Errorf("sending webhook: %w", err)
        }
        defer safeClose(resp.Body, "generic-webhook-response")

        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
                respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
                if readErr != nil {
                        slog.Warn("Failed to read webhook error response body", "error", readErr)
                }
                return resp.StatusCode, fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(respBody))
        }
        return resp.StatusCode, nil
}

func (n *Notifier) SendTestDiscord(ctx context.Context, webhookURL string) error {
        payload := discordPayload{
                Username: "DNS Tool Drift Engine",
                Embeds: []discordEmbed{
                        {
                                Title:       "Drift Engine Connected",
                                Description: "This is a verification message from the DNS Tool Drift Engine. Discord webhook integration is active and operational.",
                                Color:       0x28A745,
                                Fields: []discordField{
                                        {Name: "Status", Value: "Operational", Inline: true},
                                        {Name: "Monitored Domains", Value: strings.Join(missionCriticalDomains, "\n"), Inline: true},
                                        {Name: "Cadence", Value: "Daily", Inline: true},
                                },
                                Timestamp: time.Now().UTC().Format(time.RFC3339),
                        },
                },
        }

        body, err := json.Marshal(payload)
        if err != nil {
                return fmt.Errorf("marshaling test payload: %w", err)
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
        if err != nil {
                return fmt.Errorf("creating test request: %w", err)
        }
        req.Header.Set(headerContentType, mimeJSON)

        resp, err := n.Client.Do(req)
        if err != nil {
                return fmt.Errorf("sending test webhook: %w", err)
        }
        defer safeClose(resp.Body, "test-discord-response")

        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
                respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
                if readErr != nil {
                        slog.Warn("Failed to read test Discord error response body", "error", readErr)
                }
                return fmt.Errorf("Discord returned %d: %s", resp.StatusCode, string(respBody))
        }
        return nil
}

func isSSRFSafe(rawURL string) error {
        u, err := url.Parse(rawURL)
        if err != nil {
                return fmt.Errorf("invalid URL: %w", err)
        }
        if u.Scheme != "https" && u.Scheme != "http" {
                return fmt.Errorf("unsupported scheme: %s", u.Scheme)
        }
        host := u.Hostname()
        if host == "" {
                return fmt.Errorf("empty hostname")
        }
        ips, err := net.LookupHost(host)
        if err != nil {
                return fmt.Errorf("DNS lookup failed for %s: %w", host, err)
        }
        for _, ipStr := range ips {
                ip := net.ParseIP(ipStr)
                if ip == nil {
                        continue
                }
                if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
                        return fmt.Errorf("private/loopback IP blocked: %s resolves to %s", host, ipStr)
                }
        }
        return nil
}

func safeClose(c io.Closer, label string) {
        if err := c.Close(); err != nil {
                slog.Debug("close error", "resource", label, "error", err)
        }
}

var missionCriticalDomains = []string{
        "it-help.tech",
        "dnstool.it-help.tech",
}
