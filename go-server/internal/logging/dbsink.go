// dns-tool:scrutiny plumbing
package logging

import (
        "context"
        "encoding/json"
        "fmt"
        "os"
        "sync"
        "sync/atomic"
        "time"

        "github.com/jackc/pgx/v5/pgxpool"
)

var stderrLog = func(msg string) {
        fmt.Fprintf(os.Stderr, `{"time":"%s","level":"ERROR","msg":"%s","source":"dbsink"}`+"\n",
                time.Now().UTC().Format(time.RFC3339), msg)
}

const (
        dbFlushInterval = 5 * time.Second
        dbBatchSize     = 50
        dbMaxCap        = 10000
        dbPruneInterval = 5 * time.Minute
        dbChanSize      = 500
)

type DBLogEntry struct {
        Timestamp time.Time
        Level     string
        Message   string
        Event     string
        Category  string
        Domain    string
        TraceID   string
        Attrs     map[string]string
}

type DBSink struct {
        pool   *pgxpool.Pool
        ch     chan DBLogEntry
        done   chan struct{}
        wg     sync.WaitGroup
        closed atomic.Bool
}

func NewDBSink(pool *pgxpool.Pool) *DBSink {
        s := &DBSink{
                pool: pool,
                ch:   make(chan DBLogEntry, dbChanSize),
                done: make(chan struct{}),
        }
        s.wg.Add(2)
        go s.worker()
        go s.pruneLoop()
        return s
}

func (s *DBSink) Write(entry DBLogEntry) {
        if s.closed.Load() {
                return
        }
        select {
        case s.ch <- entry:
        default:
        }
}

func (s *DBSink) Close() {
        if s.closed.Swap(true) {
                return
        }
        close(s.done)
        s.wg.Wait()
}

func (s *DBSink) worker() {
        defer s.wg.Done()
        ticker := time.NewTicker(dbFlushInterval)
        defer ticker.Stop()
        batch := make([]DBLogEntry, 0, dbBatchSize)

        for {
                select {
                case entry := <-s.ch:
                        batch = append(batch, entry)
                        if len(batch) >= dbBatchSize {
                                s.flushBatch(batch)
                                batch = batch[:0]
                        }
                case <-ticker.C:
                        if len(batch) > 0 {
                                s.flushBatch(batch)
                                batch = batch[:0]
                        }
                case <-s.done:
                drain:
                        for {
                                select {
                                case entry := <-s.ch:
                                        batch = append(batch, entry)
                                default:
                                        break drain
                                }
                        }
                        if len(batch) > 0 {
                                s.flushBatch(batch)
                        }
                        return
                }
        }
}

func (s *DBSink) flushBatch(batch []DBLogEntry) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        for _, entry := range batch {
                attrsJSON, err := json.Marshal(entry.Attrs)
                if err != nil {
                        attrsJSON = []byte("{}")
                }

                tid := entry.TraceID
                if len(tid) > 64 {
                        tid = tid[:64]
                }

                _, err = s.pool.Exec(ctx,
                        `INSERT INTO system_log_entries (timestamp, level, message, event, category, domain, trace_id, attrs)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                        entry.Timestamp, entry.Level, entry.Message, entry.Event, entry.Category, entry.Domain, tid, attrsJSON,
                )
                if err != nil {
                        stderrLog("log db insert failed: " + err.Error())
                }
        }
}

func (s *DBSink) pruneLoop() {
        defer s.wg.Done()
        ticker := time.NewTicker(dbPruneInterval)
        defer ticker.Stop()
        for {
                select {
                case <-ticker.C:
                        s.prune()
                case <-s.done:
                        return
                }
        }
}

func (s *DBSink) prune() {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        _, err := s.pool.Exec(ctx,
                `DELETE FROM system_log_entries
                 WHERE id NOT IN (
                     SELECT id FROM system_log_entries
                     ORDER BY timestamp DESC
                     LIMIT $1
                 )`, dbMaxCap)
        if err != nil {
                stderrLog("log pruning failed: " + err.Error())
        }
}
