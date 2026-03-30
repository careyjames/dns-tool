package logging

import (
        "os"
        "testing"
)

func TestLogger_Close_NilFields(t *testing.T) {
        l := &Logger{
                done: make(chan struct{}),
        }
        l.Close()
}

func TestLogger_Close_WithFileWriter(t *testing.T) {
        tmpDir := t.TempDir()
        fw, err := NewRotatingFileWriter(tmpDir, "test-close")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }

        l := &Logger{
                FileWriter: fw,
                done:       make(chan struct{}),
        }
        l.Close()
}

func TestLogger_Close_WithDBSink(t *testing.T) {
        dbSink := &DBSink{
                ch:   make(chan DBLogEntry, 10),
                done: make(chan struct{}),
        }
        dbSink.wg.Add(2)
        go func() {
                defer dbSink.wg.Done()
                <-dbSink.done
        }()
        go func() {
                defer dbSink.wg.Done()
                <-dbSink.done
        }()

        l := &Logger{
                DBSink: dbSink,
                done:   make(chan struct{}),
        }
        l.Close()
}

func TestSetup_CreatesLogDir(t *testing.T) {
        tmpDir := t.TempDir()
        os.Setenv("LOG_DIR", tmpDir+"/test-logs")
        defer os.Unsetenv("LOG_DIR")

        logger, err := Setup(nil, "")
        if err != nil {
                t.Fatalf("Setup failed: %v", err)
        }
        defer logger.Close()

        if logger.FileWriter == nil {
                t.Error("expected non-nil FileWriter")
        }
        if logger.DBSink != nil {
                t.Error("expected nil DBSink when pool is nil")
        }
        if logger.Discord != nil {
                t.Error("expected nil Discord when webhook is empty")
        }

        info, err := os.Stat(tmpDir + "/test-logs")
        if err != nil {
                t.Fatalf("log dir not created: %v", err)
        }
        if !info.IsDir() {
                t.Error("expected directory")
        }
}

func TestSetup_WithDiscordURL(t *testing.T) {
        tmpDir := t.TempDir()
        os.Setenv("LOG_DIR", tmpDir+"/discord-logs")
        defer os.Unsetenv("LOG_DIR")

        logger, err := Setup(nil, "https://discord.com/api/webhooks/test")
        if err != nil {
                t.Fatalf("Setup failed: %v", err)
        }
        defer logger.Close()

        if logger.Discord == nil {
                t.Error("expected non-nil Discord sink when webhook URL provided")
        }
}

func TestFileCleanupLoop_ExitsOnDone(t *testing.T) {
        l := &Logger{
                done: make(chan struct{}),
        }
        done := make(chan struct{})
        go func() {
                l.fileCleanupLoop()
                close(done)
        }()

        close(l.done)
        <-done
}

func TestFileCleanupLoop_WithFileWriter(t *testing.T) {
        tmpDir := t.TempDir()
        fw, err := NewRotatingFileWriter(tmpDir, "cleanup-test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }

        l := &Logger{
                FileWriter: fw,
                done:       make(chan struct{}),
        }
        done := make(chan struct{})
        go func() {
                l.fileCleanupLoop()
                close(done)
        }()

        close(l.done)
        <-done
        fw.Close()
}

func TestSetup_DefaultLogDir(t *testing.T) {
        os.Unsetenv("LOG_DIR")
        logger, err := Setup(nil, "")
        if err != nil {
                t.Fatalf("Setup with no LOG_DIR failed: %v", err)
        }
        defer logger.Close()

        if logger.FileWriter == nil {
                t.Error("expected non-nil FileWriter (defaults to 'logs' dir)")
        }
        if logger.DBSink != nil {
                t.Error("expected nil DBSink when pool is nil")
        }
        if logger.Discord != nil {
                t.Error("expected nil Discord when webhook is empty")
        }
}
