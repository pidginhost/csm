package alert

import (
	"bufio"
	"encoding/json"
	"io"
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

func TestAuditJSONL_IncludesTenantFields(t *testing.T) {
	dir := t.TempDir()
	sink := mustNewJSONLSink(t, filepath.Join(dir, "audit.jsonl"))
	defer func() {
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	finding := Finding{
		Check:    "phprelay.spam",
		Severity: High,
		Message:  "fanout exceeded",
		TenantID: "tenant-1",
		Domain:   "example.com",
		Mailbox:  "abuse@example.com",
	}
	evt := NewAuditEvent("host", finding)
	if err := sink.Emit(evt); err != nil {
		t.Fatal(err)
	}

	lines := readJSONLines(t, filepath.Join(dir, "audit.jsonl"))
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	raw, err := json.Marshal(lines[0])
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	for _, k := range []string{"tenant-1", "example.com", "abuse@example.com"} {
		if !strings.Contains(string(raw), k) {
			t.Fatalf("expected %s in audit line, got %s", k, raw)
		}
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

// The audit file is the SIEM shipper's source. Refusing appends until the next
// logrotate run would let a detection flood, including an attacker-driven one,
// blind the audit trail for up to a day. Size is logrotate's job, not a reason
// to drop records.
func TestJSONLSinkKeepsRecordsPastRotationSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := mustNewJSONLSink(t, path)
	// Sparse allocation stands in for a file already past the packaged
	// rotation size without writing a large fixture.
	const rotationSize = 100 * 1024 * 1024
	if err := os.Truncate(path, rotationSize); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := s.Emit(sampleEvent(i)); err != nil {
			t.Fatalf("audit record %d dropped past rotation size: %v", i, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= rotationSize {
		t.Fatalf("records were not appended: size %d", info.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(rotationSize, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	for i := range 3 {
		var event AuditEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("record %d is missing or invalid: %v", i, err)
		}
		if event.FindingID != sampleEvent(i).FindingID {
			t.Fatalf("record %d has unexpected identity: %s", i, event.FindingID)
		}
	}
	if err := decoder.Decode(new(AuditEvent)); err != io.EOF {
		t.Fatalf("unexpected trailing record or bytes: %v", err)
	}
}

func TestJSONLSinkInstancesAppendAfterCopytruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first, second := mustNewJSONLSink(t, path), mustNewJSONLSink(t, path)
	for _, sink := range []*JSONLSink{first, second} {
		if err := sink.Emit(sampleEvent(0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i, sink := range []*JSONLSink{first, second} {
		wg.Go(func() {
			for j := range 50 {
				event := sampleEvent(i*50 + j)
				event.Message = strings.Repeat("evidence ", 1024)
				if err := sink.Emit(event); err != nil {
					t.Errorf("append after rotation: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
	lines := readJSONLines(t, path)
	seen := make(map[string]bool)
	for _, line := range lines {
		seen[line["finding_id"].(string)] = true
	}
	if len(lines) != 100 || len(seen) != 100 {
		t.Fatalf("concurrent appends after rotation: lines=%d unique=%d, want 100 each", len(lines), len(seen))
	}
}
