package logging

import (
	"sync"
	"testing"
	"time"
)

func TestDBSinkConstants(t *testing.T) {
	if dbFlushInterval != 5*time.Second {
		t.Errorf("dbFlushInterval = %v", dbFlushInterval)
	}
	if dbBatchSize != 50 {
		t.Errorf("dbBatchSize = %d", dbBatchSize)
	}
	if dbMaxCap != 10000 {
		t.Errorf("dbMaxCap = %d", dbMaxCap)
	}
	if dbChanSize != 500 {
		t.Errorf("dbChanSize = %d", dbChanSize)
	}
}

func TestStderrLog_DoesNotPanic(t *testing.T) {
	stderrLog("test log message")
}

func TestDBSink_WriteAndClose_DrainsBatch(t *testing.T) {
	sink := &DBSink{
		ch:   make(chan DBLogEntry, dbChanSize),
		done: make(chan struct{}),
	}

	sink.wg.Add(1)
	var flushed []DBLogEntry
	var mu sync.Mutex
	go func() {
		defer sink.wg.Done()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		batch := make([]DBLogEntry, 0, dbBatchSize)
		for {
			select {
			case entry := <-sink.ch:
				batch = append(batch, entry)
			case <-ticker.C:
				if len(batch) > 0 {
					mu.Lock()
					flushed = append(flushed, batch...)
					mu.Unlock()
					batch = batch[:0]
				}
			case <-sink.done:
			drain:
				for {
					select {
					case entry := <-sink.ch:
						batch = append(batch, entry)
					default:
						break drain
					}
				}
				if len(batch) > 0 {
					mu.Lock()
					flushed = append(flushed, batch...)
					mu.Unlock()
				}
				return
			}
		}
	}()

	sink.Write(DBLogEntry{Level: "INFO", Message: "msg1", Domain: "a.com"})
	sink.Write(DBLogEntry{Level: "WARN", Message: "msg2", Domain: "b.com"})
	sink.Write(DBLogEntry{Level: "ERROR", Message: "msg3", Domain: "c.com"})

	sink.closed.Store(true)
	close(sink.done)
	sink.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(flushed) != 3 {
		t.Fatalf("expected 3 flushed entries, got %d", len(flushed))
	}
	if flushed[0].Message != "msg1" {
		t.Errorf("first message = %q", flushed[0].Message)
	}
	if flushed[2].Domain != "c.com" {
		t.Errorf("third domain = %q", flushed[2].Domain)
	}
}

func TestDBSink_Write_DropsWhenClosed(t *testing.T) {
	sink := &DBSink{
		ch:   make(chan DBLogEntry, dbChanSize),
		done: make(chan struct{}),
	}
	sink.closed.Store(true)

	sink.Write(DBLogEntry{Level: "ERROR", Message: "should be dropped"})

	select {
	case <-sink.ch:
		t.Error("entry should not be written to closed sink")
	default:
	}
}

func TestDBSink_Write_DropsWhenChannelFull(t *testing.T) {
	sink := &DBSink{
		ch:   make(chan DBLogEntry, 1),
		done: make(chan struct{}),
	}

	sink.Write(DBLogEntry{Level: "INFO", Message: "first"})
	sink.Write(DBLogEntry{Level: "INFO", Message: "second - should be dropped"})

	if len(sink.ch) != 1 {
		t.Errorf("channel length = %d, want 1", len(sink.ch))
	}
}

func TestDBSink_Close_Idempotent(t *testing.T) {
	sink := &DBSink{
		ch:   make(chan DBLogEntry, dbChanSize),
		done: make(chan struct{}),
	}
	sink.wg.Add(2)
	go func() {
		defer sink.wg.Done()
		<-sink.done
	}()
	go func() {
		defer sink.wg.Done()
		<-sink.done
	}()

	sink.Close()
	sink.Close()
}

func TestDBLogEntry_FieldAssignment(t *testing.T) {
	now := time.Now()
	entry := DBLogEntry{
		Timestamp: now,
		Level:     "ERROR",
		Message:   "test message",
		Event:     "test_event",
		Category:  "security",
		Domain:    "example.com",
		TraceID:   "trace-123",
		Attrs:     map[string]string{"key": "value"},
	}
	if entry.Timestamp != now {
		t.Error("Timestamp mismatch")
	}
	if entry.Event != "test_event" {
		t.Errorf("Event = %q", entry.Event)
	}
	if entry.Category != "security" {
		t.Errorf("Category = %q", entry.Category)
	}
	if entry.Attrs["key"] != "value" {
		t.Errorf("Attrs[key] = %q", entry.Attrs["key"])
	}
}
