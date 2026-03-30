// dns-tool:scrutiny plumbing
package logging

import (
        "log/slog"
        "regexp"
        "strings"
)

var (
        emailRe   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
        webhookRe = regexp.MustCompile(`https?://(?:discord\.com|discordapp\.com)/api/webhooks/\S+`)
        tokenRe   = regexp.MustCompile(`(?i)(?:token|secret|key|password|authorization)[=:]\s*\S+`)
)

var sensitiveKeys = map[string]bool{
        "password":      true,
        "secret":        true,
        "token":         true,
        "authorization": true,
        "cookie":        true,
        "session_id":    true,
        "api_key":       true,
        "webhook_url":   true,
        "scan_token":    true,
        "csrf_token":    true,
        "probe_key":     true,
}

func RedactMessage(s string) string {
        return redactString(s)
}

func redactString(s string) string {
        s = emailRe.ReplaceAllString(s, "[REDACTED_EMAIL]")
        s = webhookRe.ReplaceAllString(s, "[REDACTED_WEBHOOK]")
        s = tokenRe.ReplaceAllString(s, "[REDACTED_CREDENTIAL]")
        return s
}

func redactAttr(a slog.Attr) slog.Attr {
        if sensitiveKeys[strings.ToLower(a.Key)] {
                a.Value = slog.StringValue("[REDACTED]")
                return a
        }

        switch a.Value.Kind() {
        case slog.KindString:
                a.Value = slog.StringValue(redactString(a.Value.String()))
        case slog.KindAny:
                if err, ok := a.Value.Any().(error); ok {
                        a.Value = slog.StringValue(redactString(err.Error()))
                } else {
                        str := a.Value.String()
                        redacted := redactString(str)
                        if redacted != str {
                                a.Value = slog.StringValue(redacted)
                        }
                }
        }

        if a.Value.Kind() == slog.KindGroup {
                attrs := a.Value.Group()
                redacted := make([]slog.Attr, len(attrs))
                for i, ga := range attrs {
                        redacted[i] = redactAttr(ga)
                }
                a.Value = slog.GroupValue(redacted...)
        }

        return a
}
