package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

func writeActionLines(t *testing.T, path string, records ...actionlog.Record) {
	t.Helper()
	var buf bytes.Buffer
	for _, rec := range records {
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// A rotation must not hide the older half of a --since window, so the reader
// reads the rotated file first and the current one after it.
func TestReadActionLogSpansARotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	now := time.Now().UTC()

	writeActionLines(t, path+".1", actionlog.Record{Op: "respond.block_ip", Timestamp: now.Add(-2 * time.Hour), Target: "192.0.2.1"})
	writeActionLines(t, path, actionlog.Record{Op: "respond.kill_process", Timestamp: now.Add(-time.Minute), Target: "pid 9"})

	got, err := readActionLog(path, actionFilter{limit: 50})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2", len(got))
	}
	if got[0].Op != "respond.block_ip" || got[1].Op != "respond.kill_process" {
		t.Fatalf("records out of order: %s then %s", got[0].Op, got[1].Op)
	}
}

func TestReadActionLogAppliesSinceAndOpFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	now := time.Now().UTC()

	writeActionLines(t, path,
		actionlog.Record{Op: "respond.block_ip", Timestamp: now.Add(-48 * time.Hour), Target: "192.0.2.1"},
		actionlog.Record{Op: "respond.block_ip", Timestamp: now.Add(-time.Hour), Target: "192.0.2.2"},
		actionlog.Record{Op: "respond.quarantine_file", Timestamp: now.Add(-time.Hour), Target: "/home/a/x.php"},
	)

	got, err := readActionLog(path, actionFilter{since: now.Add(-24 * time.Hour), op: "respond.block_ip", limit: 50})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 || got[0].Target != "192.0.2.2" {
		t.Fatalf("records = %+v, want only the recent block", got)
	}
}

// A crash can leave a half-written final line. That must cost the last record,
// not the whole file.
func TestReadActionLogSurvivesATruncatedFinalLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	if err := os.WriteFile(path, []byte(`{"v":1,"op":"respond.block_ip","target":"192.0.2.1"}`+"\n"+`{"v":1,"op":"respo`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readActionLog(path, actionFilter{limit: 50})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 || got[0].Target != "192.0.2.1" {
		t.Fatalf("records = %+v, want the one complete record", got)
	}
}

func TestReadActionLogWithNoFileIsNotAnError(t *testing.T) {
	got, err := readActionLog(filepath.Join(t.TempDir(), "actions.jsonl"), actionFilter{limit: 50})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("records = %d, want 0", len(got))
	}
}

func TestWriteActionsSaysSoWhenThereAreNone(t *testing.T) {
	var buf bytes.Buffer
	if err := writeActions(&buf, nil, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(buf.String(), "No actions recorded") {
		t.Fatalf("output = %q, want an explicit empty message", buf.String())
	}
}

func TestWriteActionsJSONEmitsOneRecordPerLine(t *testing.T) {
	var buf bytes.Buffer
	records := []actionlog.Record{
		{Op: "respond.block_ip", Target: "192.0.2.1"},
		{Op: "respond.kill_process", Target: "pid 9"},
	}
	if err := writeActions(&buf, records, true); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	for _, line := range lines {
		var rec actionlog.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line is not JSON: %v", err)
		}
	}
}
