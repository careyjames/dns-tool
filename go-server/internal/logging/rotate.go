// dns-tool:scrutiny plumbing
package logging

import (
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "sync"
        "time"
)

const (
        defaultMaxFileSize  = 10 * 1024 * 1024
        defaultMaxTotalSize = 50 * 1024 * 1024
        defaultMaxAge       = 7 * 24 * time.Hour
)

type RotatingFileWriter struct {
        mu          sync.Mutex
        dir         string
        prefix      string
        maxFileSize int64
        maxTotal    int64
        maxAge      time.Duration
        file        *os.File
        size        int64
}

func NewRotatingFileWriter(dir, prefix string) (*RotatingFileWriter, error) {
        if err := os.MkdirAll(dir, 0o750); err != nil {
                return nil, fmt.Errorf("creating log dir: %w", err)
        }
        w := &RotatingFileWriter{
                dir:         dir,
                prefix:      prefix,
                maxFileSize: defaultMaxFileSize,
                maxTotal:    defaultMaxTotalSize,
                maxAge:      defaultMaxAge,
        }
        if err := w.rotate(); err != nil {
                return nil, err
        }
        return w, nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
        w.mu.Lock()
        defer w.mu.Unlock()

        if w.size+int64(len(p)) > w.maxFileSize {
                if err := w.rotate(); err != nil {
                        return 0, err
                }
        }

        n, err := w.file.Write(p)
        w.size += int64(n)
        return n, err
}

func (w *RotatingFileWriter) Close() error {
        w.mu.Lock()
        defer w.mu.Unlock()
        if w.file != nil {
                return w.file.Close()
        }
        return nil
}

func (w *RotatingFileWriter) rotate() error {
        if w.file != nil {
                w.file.Close()
        }
        name := filepath.Join(w.dir, fmt.Sprintf("%s-%s.jsonl", w.prefix, time.Now().UTC().Format("20060102-150405")))
        f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
        if err != nil {
                return fmt.Errorf("opening log file: %w", err)
        }
        w.file = f
        w.size = 0
        w.cleanup()
        return nil
}

func (w *RotatingFileWriter) cleanup() {
        entries, err := os.ReadDir(w.dir)
        if err != nil {
                return
        }

        type logFile struct {
                path    string
                size    int64
                modTime time.Time
        }

        var files []logFile
        cutoff := time.Now().Add(-w.maxAge)

        for _, e := range entries {
                if e.IsDir() {
                        continue
                }
                info, err := e.Info()
                if err != nil {
                        continue
                }
                fp := filepath.Join(w.dir, e.Name())

                if info.ModTime().Before(cutoff) {
                        os.Remove(fp)
                        continue
                }
                files = append(files, logFile{path: fp, size: info.Size(), modTime: info.ModTime()})
        }

        sort.Slice(files, func(i, j int) bool {
                return files[i].modTime.After(files[j].modTime)
        })

        var total int64
        for _, f := range files {
                total += f.size
                if total > w.maxTotal {
                        os.Remove(f.path)
                }
        }
}

func (w *RotatingFileWriter) Cleanup() {
        w.mu.Lock()
        defer w.mu.Unlock()
        w.cleanup()
}
