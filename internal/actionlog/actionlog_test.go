package actionlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

type sinkFunc func(Record) error

func (f sinkFunc) Write(r Record) error { return f(r) }

func TestWriteContainsSinkFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		sink Sink
	}{
		{"nil", nil}, {"typed nil", (*FileSink)(nil)},
		{"panic", sinkFunc(func(Record) error { panic("broken sink") })},
		{"error", sinkFunc(func(Record) error { return errors.New("disk full") })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetSink(tc.sink, "")
			t.Cleanup(func() { SetSink(nil, "") })
			returned := false
			func() {
				defer func() {
					if v := recover(); v != nil {
						t.Errorf("sink panic escaped: %v", v)
					}
				}()
				Write(Record{Op: "test", Result: Applied})
				returned = true
			}()
			if !returned {
				t.Fatal("recording prevented action completion")
			}
		})
	}
}

func TestWriteDoesNotWaitForStalledSink(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	SetSink(sinkFunc(func(Record) error { close(entered); <-release; return nil }), "")
	t.Cleanup(func() { SetSink(nil, ""); close(release) })
	done := make(chan struct{})
	go func() { Write(Record{Op: "test", Result: Applied}); close(done) }()
	<-entered
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stalled sink blocked completed action")
	}
}

func TestFileSinkFailedOpenReportsAndCanRetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "actions.jsonl")
	if err := os.WriteFile(filepath.Dir(path), nil, 0600); err != nil {
		t.Fatal(err)
	}
	reports := 0
	s := NewFileSink(func() string { return path }, func(error) { reports++ })
	if err := s.Write(Record{Op: "test"}); err == nil || reports != 1 {
		t.Fatalf("error=%v reports=%d", err, reports)
	}
	if err := os.Remove(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(Record{Op: "test"}); err != nil {
		t.Fatal(err)
	}
}

func TestFileSinkConcurrentInstancesKeepEveryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	sinks := []*FileSink{NewFileSink(func() string { return path }, nil), NewFileSink(func() string { return path }, nil)}
	// Both processes can observe an oversized inode before one rotates it.
	if err := os.WriteFile(path, append([]byte(strings.Repeat(" ", maxFileSize)), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := sinks[i%2].Write(Record{Target: fmt.Sprint(i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, name := range []string{path + ".1", path} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var r Record
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatal(err)
			}
			if seen[r.Target] {
				t.Fatalf("duplicate %s", r.Target)
			}
			seen[r.Target] = true
		}
	}
	if len(seen) != 100 {
		t.Fatalf("records=%d, want 100", len(seen))
	}
}

func TestFileSinkRejectsNonRegularTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// O_RDWR lets the buggy writer open without hanging the regression suite.
	reader, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := NewFileSink(func() string { return path }, nil).Write(Record{Op: "test"}); err == nil {
		t.Fatal("accepted FIFO as action log")
	}
}

func TestStatOmitsOversizeDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxDigestBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	st := Stat(path)
	if !st.Exists || st.Size != maxDigestBytes+1 || st.Digest != "" {
		t.Fatalf("oversize snapshot=%+v", st)
	}
}

func TestStatDoesNotFollowSymlinkParents(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "payload"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if st := Stat(filepath.Join(link, "payload")); st.Digest != "" {
		t.Fatalf("followed symlink parent: %+v", st)
	}
}

func TestDescribeToleratesShortDigest(t *testing.T) {
	r := Record{Before: &FileState{Exists: true, Digest: "abc"}, After: &FileState{}}
	if got := r.Describe(); !strings.Contains(got, "abc -> absent") {
		t.Fatalf("description=%s", got)
	}
}

func TestFileSinkCreatesLogDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "actions.jsonl")
	if err := NewFileSink(func() string { return path }, nil).Write(Record{Op: "test"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"op":"test"`) {
		t.Fatalf("record=%s error=%v", data, err)
	}
}

func TestDescribeKeepsUntrustedNamesOnOneLine(t *testing.T) {
	r := Record{Op: "respond.quarantine_file", Target: "evil\nforged action\x1b[2J", Error: "cannot unlink\rforged"}
	line := r.Describe()
	if strings.ContainsAny(line, "\n\r\x1b") {
		t.Fatalf("unsafe terminal output: %q", line)
	}
}

func TestReadPinsBothFilesWithoutHoldingUpWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	prior := "previous"
	current := "current" + strings.Repeat(" ", maxFileSize)
	for name, content := range map[string]string{path + ".1": prior, path: current} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	lock, openErr := os.Create(path + ".lock")
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	sink := NewFileSink(func() string { return path }, nil)
	var contents []string
	err := Read(path, func(reader io.Reader) error {
		if len(contents) == 0 {
			done := make(chan error, 1)
			go func() { done <- sink.Write(Record{Target: "next"}) }()
			select {
			case writeErr := <-done:
				if writeErr != nil {
					return writeErr
				}
			case <-time.After(time.Second):
				return errors.New("reading held up the writer")
			}
		}
		data, readErr := io.ReadAll(reader)
		contents = append(contents, string(data))
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 2 || contents[0] != prior || contents[1] != current {
		t.Fatal("rotation changed the pinned history snapshot")
	}
}

func TestReadDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actions.jsonl")
	for _, file := range []string{path, filepath.Join(dir, "missing", "actions.jsonl")} {
		if err := Read(file, func(io.Reader) error { return errors.New("unexpected record") }); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read created files: entries=%v error=%v", entries, err)
	}
}
