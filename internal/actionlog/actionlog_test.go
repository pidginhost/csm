package actionlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturingSink struct {
	mu      sync.Mutex
	records []Record
}

func (c *capturingSink) Write(r Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r)
	return nil
}

func withSink(t *testing.T) *capturingSink {
	t.Helper()
	c := &capturingSink{}
	SetSink(c, "host.example.com")
	t.Cleanup(func() { SetSink(nil, "") })
	return c
}

func TestWriteStampsSchemaTimestampAndHostname(t *testing.T) {
	c := withSink(t)
	Write(Record{Op: "respond.block_ip", Actor: Daemon, Target: "192.0.2.10", Result: Applied})

	if len(c.records) != 1 {
		t.Fatalf("records = %d, want 1", len(c.records))
	}
	got := c.records[0]
	if got.V != SchemaVersion {
		t.Errorf("v = %d, want %d", got.V, SchemaVersion)
	}
	if got.Timestamp.IsZero() {
		t.Error("record has no timestamp")
	}
	if got.Hostname != "host.example.com" {
		t.Errorf("hostname = %q, want host.example.com", got.Hostname)
	}
}

// An action that happened must never be rolled back because nobody installed
// a sink, so recording with no sink is a no-op rather than a panic.
func TestWriteWithoutSinkIsSilent(t *testing.T) {
	SetSink(nil, "")
	Write(Record{Op: "respond.kill_process", Result: Applied})
}

func TestFileSinkAppendsOneJSONLinePerRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	sink := NewFileSink(func() string { return path }, nil)
	SetSink(sink, "host.example.com")
	t.Cleanup(func() { SetSink(nil, "") })

	Write(Record{Op: "respond.quarantine_file", Target: "/home/a/public_html/x.php", Result: Applied})
	Write(Record{Op: "respond.block_ip", Target: "198.51.100.7", Result: DryRun})

	fh, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = fh.Close() }()

	var ops []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("record is not JSON: %v", err)
		}
		ops = append(ops, r.Op)
	}
	if len(ops) != 2 || ops[0] != "respond.quarantine_file" || ops[1] != "respond.block_ip" {
		t.Fatalf("ops = %v, want the two written records in order", ops)
	}
}

func TestFileSinkRotatesAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	if err := os.WriteFile(path, make([]byte, maxFileSize+1), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink := NewFileSink(func() string { return path }, nil)
	if err := sink.Write(Record{Op: "respond.block_ip", Result: Applied}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("oversized log was not rotated: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current: %v", err)
	}
	if info.Size() > maxFileSize {
		t.Fatalf("current log is %d bytes, want a fresh file", info.Size())
	}
}

// The digest is the evidence that makes a file action reviewable: a reader has
// to be able to tell "this exact content was removed" from "some file was".
func TestStatCapturesDigestSizeAndMode(t *testing.T) {
	const content = "<?php echo 1;"
	path := filepath.Join(t.TempDir(), "payload.php")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	want := hex.EncodeToString(sum[:])

	st := Stat(path)
	if !st.Exists {
		t.Fatal("existing file recorded as absent")
	}
	if st.Digest != want {
		t.Errorf("digest = %q, want %q", st.Digest, want)
	}
	if st.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", st.Size, len(content))
	}
	if st.Mode != "-rw-r-----" {
		t.Errorf("mode = %q, want -rw-r-----", st.Mode)
	}
}

func TestStatRecordsAMissingFileAsAbsent(t *testing.T) {
	st := Stat(filepath.Join(t.TempDir(), "gone.php"))
	if st.Exists {
		t.Fatal("missing file recorded as existing")
	}
	if st.Digest != "" {
		t.Fatal("missing file has a digest")
	}
}

func TestDescribeShowsTheDigestChange(t *testing.T) {
	r := Record{
		Timestamp: time.Unix(0, 0).UTC(),
		Op:        "respond.clean_file",
		Target:    "/home/a/public_html/index.php",
		Result:    Applied,
		Before:    &FileState{Exists: true, Digest: strings.Repeat("a", 64)},
		After:     &FileState{Exists: true, Digest: strings.Repeat("b", 64)},
	}
	line := r.Describe()
	if !strings.Contains(line, "aaaaaaaaaaaa -> bbbbbbbbbbbb") {
		t.Fatalf("describe does not show the digest change: %s", line)
	}
}

func TestDescribeShowsTheExactCommand(t *testing.T) {
	r := Record{
		Timestamp: time.Unix(0, 0).UTC(),
		Op:        "respond.freeze_mail",
		Target:    "1abcDE-000001-AB",
		Result:    Applied,
		Command:   []string{"exim", "-Mf", "1abcDE-000001-AB"},
	}
	if !strings.Contains(r.Describe(), `"exim" "-Mf" "1abcDE-000001-AB"`) {
		t.Fatalf("describe does not show the argv: %s", r.Describe())
	}
}

// Installing a sink must not cost anything until an action happens: a CLI that
// only reads should not load configuration to find out where the log lives.
func TestFileSinkResolvesItsPathOnceAndOnlyWhenWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	calls := 0
	sink := NewFileSink(func() string {
		calls++
		return path
	}, nil)

	if calls != 0 {
		t.Fatalf("path resolved %d times before any record", calls)
	}
	for i := 0; i < 3; i++ {
		if err := sink.Write(Record{Op: "respond.block_ip", Result: Applied}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("path resolved %d times, want once", calls)
	}
}
