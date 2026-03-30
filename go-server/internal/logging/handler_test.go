package logging

import (
        "bytes"
        "context"
        "log/slog"
        "strings"
        "testing"
        "time"
)

func TestNewMultiHandler(t *testing.T) {
        h := NewMultiHandler(Config{
                MinLevel: slog.LevelInfo,
        })
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestMultiHandler_Enabled(t *testing.T) {
        h := NewMultiHandler(Config{MinLevel: slog.LevelWarn})

        if h.Enabled(context.Background(), slog.LevelInfo) {
                t.Error("Info should not be enabled when min is Warn")
        }
        if !h.Enabled(context.Background(), slog.LevelWarn) {
                t.Error("Warn should be enabled when min is Warn")
        }
        if !h.Enabled(context.Background(), slog.LevelError) {
                t.Error("Error should be enabled when min is Warn")
        }
}

func TestMultiHandler_Handle_WritesToJSON(t *testing.T) {
        var buf bytes.Buffer
        h := NewMultiHandler(Config{
                FileWriter: &buf,
                MinLevel:   slog.LevelDebug,
        })

        record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
        err := h.Handle(context.Background(), record)
        if err != nil {
                t.Fatalf("Handle error: %v", err)
        }

        output := buf.String()
        if output == "" {
                t.Error("expected JSON output")
        }
        if !strings.Contains(output, "test message") {
                t.Errorf("output should contain message: %q", output)
        }
}

func TestMultiHandler_Handle_RedactsMessage(t *testing.T) {
        var buf bytes.Buffer
        h := NewMultiHandler(Config{
                FileWriter: &buf,
                MinLevel:   slog.LevelDebug,
        })

        record := slog.NewRecord(time.Now(), slog.LevelInfo, "login user@example.com", 0)
        h.Handle(context.Background(), record)

        output := buf.String()
        if strings.Contains(output, "user@example.com") {
                t.Errorf("email should be redacted in output: %q", output)
        }
}

func TestMultiHandler_Handle_AddsSeverity(t *testing.T) {
        var buf bytes.Buffer
        h := NewMultiHandler(Config{
                FileWriter: &buf,
                MinLevel:   slog.LevelDebug,
        })

        record := slog.NewRecord(time.Now(), slog.LevelError, "error msg", 0)
        h.Handle(context.Background(), record)

        output := buf.String()
        if !strings.Contains(output, "CRITICAL") {
                t.Errorf("expected CRITICAL severity: %q", output)
        }
}

func TestMultiHandler_Handle_WarnSeverity(t *testing.T) {
        var buf bytes.Buffer
        h := NewMultiHandler(Config{
                FileWriter: &buf,
                MinLevel:   slog.LevelDebug,
        })

        record := slog.NewRecord(time.Now(), slog.LevelWarn, "warn msg", 0)
        h.Handle(context.Background(), record)

        output := buf.String()
        if !strings.Contains(output, "WARNING") {
                t.Errorf("expected WARNING severity: %q", output)
        }
}

func TestMultiHandler_Handle_ExtractsAttrs(t *testing.T) {
        var buf bytes.Buffer
        h := NewMultiHandler(Config{
                FileWriter: &buf,
                MinLevel:   slog.LevelDebug,
        })

        record := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
        record.AddAttrs(
                slog.String(AttrEvent, "scan_complete"),
                slog.String(AttrCategory, CategoryScan),
                slog.String(AttrDomain, "test.com"),
        )
        err := h.Handle(context.Background(), record)
        if err != nil {
                t.Fatalf("Handle error: %v", err)
        }

        output := buf.String()
        if !strings.Contains(output, "scan_complete") {
                t.Errorf("output should contain event attr: %q", output)
        }
        if !strings.Contains(output, "test.com") {
                t.Errorf("output should contain domain: %q", output)
        }
}

func TestMultiHandler_Handle_RoutesToDBSink_WarnAndAbove(t *testing.T) {
        var buf bytes.Buffer
        dbSink := &DBSink{
                ch:   make(chan DBLogEntry, 10),
                done: make(chan struct{}),
        }

        h := NewMultiHandler(Config{
                FileWriter: &buf,
                DBSink:     dbSink,
                MinLevel:   slog.LevelDebug,
        })

        infoRecord := slog.NewRecord(time.Now(), slog.LevelInfo, "info msg", 0)
        h.Handle(context.Background(), infoRecord)

        select {
        case <-dbSink.ch:
                t.Error("INFO level should NOT be routed to DBSink")
        default:
        }

        warnRecord := slog.NewRecord(time.Now(), slog.LevelWarn, "warn msg", 0)
        warnRecord.AddAttrs(slog.String(AttrDomain, "warned.com"))
        h.Handle(context.Background(), warnRecord)

        select {
        case entry := <-dbSink.ch:
                if entry.Level != "WARN" {
                        t.Errorf("DBSink entry level = %q, want WARN", entry.Level)
                }
                if entry.Domain != "warned.com" {
                        t.Errorf("DBSink entry domain = %q, want warned.com", entry.Domain)
                }
        default:
                t.Error("WARN level should be routed to DBSink")
        }

        errorRecord := slog.NewRecord(time.Now(), slog.LevelError, "error msg", 0)
        h.Handle(context.Background(), errorRecord)

        select {
        case entry := <-dbSink.ch:
                if entry.Level != "ERROR" {
                        t.Errorf("DBSink entry level = %q, want ERROR", entry.Level)
                }
        default:
                t.Error("ERROR level should be routed to DBSink")
        }
}

func TestMultiHandler_Handle_RedactsAttrsInOutput(t *testing.T) {
        var buf bytes.Buffer
        h := NewMultiHandler(Config{
                FileWriter: &buf,
                MinLevel:   slog.LevelDebug,
        })

        fakeKey := "sk-" + "abc123def456"
        record := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
        record.AddAttrs(slog.String("token", "Bearer "+fakeKey))
        h.Handle(context.Background(), record)

        output := buf.String()
        if strings.Contains(output, fakeKey) {
                t.Errorf("token should be redacted: %q", output)
        }
}

func TestMultiHandler_WithAttrs(t *testing.T) {
        h := NewMultiHandler(Config{MinLevel: slog.LevelDebug})
        h2 := h.WithAttrs([]slog.Attr{slog.String("key", "value")})

        if h2 == nil {
                t.Fatal("expected non-nil handler")
        }
        mh, ok := h2.(*MultiHandler)
        if !ok {
                t.Fatal("expected *MultiHandler type")
        }
        if len(mh.attrs) != 1 {
                t.Errorf("expected 1 attr, got %d", len(mh.attrs))
        }
}

func TestMultiHandler_WithGroup(t *testing.T) {
        h := NewMultiHandler(Config{MinLevel: slog.LevelDebug})
        h2 := h.WithGroup("mygroup")

        if h2 == nil {
                t.Fatal("expected non-nil handler")
        }
        mh, ok := h2.(*MultiHandler)
        if !ok {
                t.Fatal("expected *MultiHandler type")
        }
        if len(mh.groups) != 1 || mh.groups[0] != "mygroup" {
                t.Errorf("groups = %v, want [mygroup]", mh.groups)
        }
}

func TestMultiHandler_WithAttrs_DoesNotMutateOriginal(t *testing.T) {
        h := NewMultiHandler(Config{MinLevel: slog.LevelDebug})
        h.WithAttrs([]slog.Attr{slog.String("key", "value")})

        if len(h.attrs) != 0 {
                t.Error("original handler should not be mutated")
        }
}

func TestMultiHandler_WithGroup_DoesNotMutateOriginal(t *testing.T) {
        h := NewMultiHandler(Config{MinLevel: slog.LevelDebug})
        h.WithGroup("group1")

        if len(h.groups) != 0 {
                t.Error("original handler should not be mutated")
        }
}

func TestMultiHandler_NilFileWriter_UsesDiscard(t *testing.T) {
        h := NewMultiHandler(Config{MinLevel: slog.LevelDebug})
        record := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
        err := h.Handle(context.Background(), record)
        if err != nil {
                t.Fatalf("Handle with nil file writer should not error: %v", err)
        }
}

func TestMultiHandler_Handle_WithPresetAttrs(t *testing.T) {
        var buf bytes.Buffer
        dbSink := &DBSink{
                ch:   make(chan DBLogEntry, 10),
                done: make(chan struct{}),
        }

        h := NewMultiHandler(Config{
                FileWriter: &buf,
                DBSink:     dbSink,
                MinLevel:   slog.LevelDebug,
        })

        h2 := h.WithAttrs([]slog.Attr{slog.String("service", "dns-tool")})

        warnRecord := slog.NewRecord(time.Now(), slog.LevelWarn, "preset test", 0)
        h2.Handle(context.Background(), warnRecord)

        select {
        case entry := <-dbSink.ch:
                if entry.Attrs["service"] != "dns-tool" {
                        t.Errorf("expected preset attr 'service'='dns-tool', got %v", entry.Attrs)
                }
        default:
                t.Error("expected WARN to route to DBSink")
        }
}

func TestLevelToSeverity(t *testing.T) {
        tests := []struct {
                level slog.Level
                want  string
        }{
                {slog.LevelError, "CRITICAL"},
                {slog.LevelWarn, "WARNING"},
                {slog.LevelInfo, "INFO"},
                {slog.LevelDebug, "DEBUG"},
                {slog.Level(-8), "DEBUG"},
                {slog.Level(12), "CRITICAL"},
        }
        for _, tt := range tests {
                t.Run(tt.want, func(t *testing.T) {
                        got := levelToSeverity(tt.level)
                        if got != tt.want {
                                t.Errorf("levelToSeverity(%v) = %q, want %q", tt.level, got, tt.want)
                        }
                })
        }
}
