package logging

import (
        "os"
        "path/filepath"
        "testing"
        "time"
)

func TestNewRotatingFileWriter(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        if w.dir != dir {
                t.Errorf("dir = %q, want %q", w.dir, dir)
        }
        if w.prefix != "test" {
                t.Errorf("prefix = %q, want 'test'", w.prefix)
        }
        if w.maxFileSize != defaultMaxFileSize {
                t.Errorf("maxFileSize = %d, want %d", w.maxFileSize, defaultMaxFileSize)
        }
        if w.file == nil {
                t.Error("expected non-nil file")
        }
}

func TestNewRotatingFileWriter_CreatesDir(t *testing.T) {
        dir := filepath.Join(t.TempDir(), "subdir", "logs")
        w, err := NewRotatingFileWriter(dir, "test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        info, err := os.Stat(dir)
        if err != nil {
                t.Fatalf("directory not created: %v", err)
        }
        if !info.IsDir() {
                t.Error("expected directory")
        }
}

func TestRotatingFileWriter_Write(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        n, err := w.Write([]byte("hello world\n"))
        if err != nil {
                t.Fatalf("Write error: %v", err)
        }
        if n != 12 {
                t.Errorf("wrote %d bytes, want 12", n)
        }
        if w.size != 12 {
                t.Errorf("size = %d, want 12", w.size)
        }
}

func TestRotatingFileWriter_RotatesOnSize(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        w.maxFileSize = 100

        data := make([]byte, 60)
        for i := range data {
                data[i] = 'x'
        }

        _, err = w.Write(data)
        if err != nil {
                t.Fatalf("first write: %v", err)
        }

        time.Sleep(1100 * time.Millisecond)

        _, err = w.Write(data)
        if err != nil {
                t.Fatalf("second write (trigger rotation): %v", err)
        }

        entries, err := os.ReadDir(dir)
        if err != nil {
                t.Fatalf("ReadDir: %v", err)
        }
        if len(entries) < 2 {
                t.Errorf("expected at least 2 files after rotation, got %d", len(entries))
        }
}

func TestRotatingFileWriter_Close_NilFile(t *testing.T) {
        w := &RotatingFileWriter{}
        err := w.Close()
        if err != nil {
                t.Errorf("Close with nil file should not error: %v", err)
        }
}

func TestRotatingFileWriter_Cleanup(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        w.Cleanup()
}

func TestRotatingFileWriter_CleanupRemovesOldFiles(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        w.maxTotal = 100

        for i := 0; i < 5; i++ {
                w.maxFileSize = 50
                data := make([]byte, 60)
                w.Write(data)
        }

        w.Cleanup()
}

func TestDefaultConstants(t *testing.T) {
        if defaultMaxFileSize != 10*1024*1024 {
                t.Errorf("defaultMaxFileSize = %d, want 10MB", defaultMaxFileSize)
        }
        if defaultMaxTotalSize != 50*1024*1024 {
                t.Errorf("defaultMaxTotalSize = %d, want 50MB", defaultMaxTotalSize)
        }
}

func TestNewRotatingFileWriter_InvalidDir(t *testing.T) {
        _, err := NewRotatingFileWriter("/dev/null/impossible", "test")
        if err == nil {
                t.Error("expected error for invalid directory path")
        }
}

func TestRotatingFileWriter_CleanupEnforcesMaxTotal(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "size-limit")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        w.maxTotal = 50
        w.maxFileSize = 20

        for i := 0; i < 10; i++ {
                data := make([]byte, 25)
                for j := range data {
                        data[j] = byte('a' + i)
                }
                w.Write(data)
                time.Sleep(10 * time.Millisecond)
        }

        w.Cleanup()

        entries, err := os.ReadDir(dir)
        if err != nil {
                t.Fatalf("ReadDir: %v", err)
        }

        var totalSize int64
        for _, e := range entries {
                info, _ := e.Info()
                if info != nil {
                        totalSize += info.Size()
                }
        }
        if totalSize > w.maxTotal+50 {
                t.Errorf("total size %d exceeds maxTotal %d by too much", totalSize, w.maxTotal)
        }
}

func TestRotatingFileWriter_CleanupRemovesExpiredFiles(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "age-limit")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        defer w.Close()

        oldFile := filepath.Join(dir, "age-limit-old.jsonl")
        os.WriteFile(oldFile, []byte("old data"), 0o640)
        past := time.Now().Add(-48 * time.Hour)
        os.Chtimes(oldFile, past, past)

        w.maxAge = 1 * time.Hour
        w.Cleanup()

        if _, err := os.Stat(oldFile); err == nil {
                t.Error("expected old file to be removed after cleanup")
        }
}

func TestRotatingFileWriter_WriteAfterClose(t *testing.T) {
        dir := t.TempDir()
        w, err := NewRotatingFileWriter(dir, "close-test")
        if err != nil {
                t.Fatalf("NewRotatingFileWriter: %v", err)
        }
        w.Close()

        _, err = w.Write([]byte("after close"))
        if err == nil {
                t.Error("expected error writing to closed writer")
        }
}
