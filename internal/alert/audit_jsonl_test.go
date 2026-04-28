package alert

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustNewJSONLSink(t *testing.T, path string) *JSONLSink {
	t.Helper()
	s, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleEvent(seq int) AuditEvent {
	return NewAuditEvent("host.test", Finding{
		Severity:  Critical,
		Check:     "webshell_realtime",
		Message:   "boom",
		Timestamp: time.Date(2026, 4, 28, 10, 0, seq, 0, time.UTC),
		FilePath:  "/var/www/x.php",
	})
}

func readJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []map[string]any
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			t.Fatalf("invalid JSON line %q: %v", scanner.Bytes(), err)
		}
		out = append(out, m)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestJSONLSinkWritesOneLinePerEmit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := mustNewJSONLSink(t, path)

	for i := 0; i < 3; i++ {
		if err := s.Emit(sampleEvent(i)); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	_ = s.Close()

	lines := readJSONLines(t, path)
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3", len(lines))
	}
	for i, m := range lines {
		if m["check"] != "webshell_realtime" {
			t.Errorf("line %d check = %v", i, m["check"])
		}
		if m["v"] == nil {
			t.Errorf("line %d missing schema version", i)
		}
	}
}

func TestJSONLSinkAppendsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s1, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if emitErr := s1.Emit(sampleEvent(0)); emitErr != nil {
		t.Fatalf("Emit s1: %v", emitErr)
	}
	_ = s1.Close()

	s2, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if emitErr := s2.Emit(sampleEvent(1)); emitErr != nil {
		t.Fatalf("Emit s2: %v", emitErr)
	}
	_ = s2.Close()

	lines := readJSONLines(t, path)
	if len(lines) != 2 {
		t.Errorf("got %d lines, want 2 (append across reopen)", len(lines))
	}
}

func TestJSONLSinkConcurrentEmitsKeepLineBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := mustNewJSONLSink(t, path)

	const goroutines = 8
	const perGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				ev := sampleEvent(g*100 + i)
				ev.Message = strings.Repeat("payload ", 256) // ~2KB lines
				if err := s.Emit(ev); err != nil {
					t.Errorf("Emit: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	_ = s.Close()

	lines := readJSONLines(t, path)
	if len(lines) != goroutines*perGoroutine {
		t.Errorf("got %d lines, want %d (concurrent writes interleaved)",
			len(lines), goroutines*perGoroutine)
	}
}

func TestJSONLSinkCloseIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Emit(sampleEvent(0)); err == nil {
		t.Error("Emit on closed sink returned nil error")
	}
}

func TestJSONLSinkEmptyPathRejected(t *testing.T) {
	_, err := NewJSONLSink("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestJSONLSinkCreatesParentDir(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "nested", "deeper")
	path := filepath.Join(parent, "audit.jsonl")
	s, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	defer func() { _ = s.Close() }()
	if _, statErr := os.Stat(parent); statErr != nil {
		t.Errorf("parent dir not created: %v", statErr)
	}
}
