// dns-tool:scrutiny plumbing
package logging

import (
        "context"
        "io"
        "log/slog"
)

type MultiHandler struct {
        json    slog.Handler
        dbSink  *DBSink
        discord *DiscordSink
        attrs   []slog.Attr
        groups  []string
        level   slog.Level
}

type Config struct {
        FileWriter  io.Writer
        DBSink      *DBSink
        DiscordSink *DiscordSink
        MinLevel    slog.Level
}

func NewMultiHandler(cfg Config) *MultiHandler {
        jsonOpts := &slog.HandlerOptions{
                Level: cfg.MinLevel,
                ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
                        return redactAttr(a)
                },
        }

        var writer io.Writer = io.Discard
        if cfg.FileWriter != nil {
                writer = cfg.FileWriter
        }

        return &MultiHandler{
                json:    slog.NewJSONHandler(writer, jsonOpts),
                dbSink:  cfg.DBSink,
                discord: cfg.DiscordSink,
                level:   cfg.MinLevel,
        }
}

func (h *MultiHandler) Enabled(_ context.Context, level slog.Level) bool {
        return level >= h.level
}

func levelToSeverity(l slog.Level) string {
        switch {
        case l >= slog.LevelError:
                return "CRITICAL"
        case l >= slog.LevelWarn:
                return "WARNING"
        case l >= slog.LevelInfo:
                return "INFO"
        default:
                return "DEBUG"
        }
}

func (h *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
        redactedMsg := RedactMessage(r.Message)

        redacted := slog.NewRecord(r.Time, r.Level, redactedMsg, r.PC)
        redacted.AddAttrs(slog.String("severity", levelToSeverity(r.Level)))
        r.Attrs(func(a slog.Attr) bool {
                redacted.AddAttrs(redactAttr(a))
                return true
        })

        _ = h.json.Handle(ctx, redacted)

        event := ""
        category := ""
        domain := ""
        errorChain := ""
        attrs := make(map[string]string)

        for _, a := range h.attrs {
                ra := redactAttr(a)
                attrs[ra.Key] = ra.Value.String()
        }
        r.Attrs(func(a slog.Attr) bool {
                ra := redactAttr(a)
                attrs[ra.Key] = ra.Value.String()
                switch ra.Key {
                case AttrEvent:
                        event = ra.Value.String()
                case AttrCategory:
                        category = ra.Value.String()
                case AttrDomain:
                        domain = ra.Value.String()
                case AttrErrorChain:
                        errorChain = ra.Value.String()
                }
                return true
        })

        if h.dbSink != nil && r.Level >= slog.LevelWarn {
                h.dbSink.Write(DBLogEntry{
                        Timestamp: r.Time,
                        Level:     r.Level.String(),
                        Message:   redactedMsg,
                        Event:     event,
                        Category:  category,
                        Domain:    domain,
                        TraceID:   attrs[AttrTraceID],
                        Attrs:     attrs,
                })
        }

        if h.discord != nil && h.discord.ShouldSend(r.Level, event, category) {
                discordAttrs := map[string]string{
                        AttrCategory:   category,
                        AttrDomain:     domain,
                        AttrErrorChain: errorChain,
                }
                if tid, ok := attrs[AttrTraceID]; ok {
                        discordAttrs[AttrTraceID] = tid
                }
                go h.discord.Send(context.Background(), r.Level, redactedMsg, discordAttrs)
        }

        return nil
}

func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
        return &MultiHandler{
                json:    h.json.WithAttrs(attrs),
                dbSink:  h.dbSink,
                discord: h.discord,
                attrs:   append(append([]slog.Attr{}, h.attrs...), attrs...),
                groups:  h.groups,
                level:   h.level,
        }
}

func (h *MultiHandler) WithGroup(name string) slog.Handler {
        return &MultiHandler{
                json:    h.json.WithGroup(name),
                dbSink:  h.dbSink,
                discord: h.discord,
                attrs:   h.attrs,
                groups:  append(append([]string{}, h.groups...), name),
                level:   h.level,
        }
}
