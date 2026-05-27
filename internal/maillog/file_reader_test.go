package maillog

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadBoundedLine_TruncatesOversizedLine: a single line larger
// than maxBytes must yield exactly maxBytes of content with the
// truncated flag set, and the reader must skip to the next line so
// framing stays intact. Without this cap an attacker-controlled log
// source could ship a multi-GB line and OOM the daemon.
func TestReadBoundedLine_TruncatesOversizedLine(t *testing.T) {
	max := 16
	huge := strings.Repeat("a", max*4) + "\nnext\n"
	r := bufio.NewReader(strings.NewReader(huge))

	got, truncated, err := readBoundedLine(r, max)
	if err != nil {
		t.Fatalf("err on first line: %v", err)
	}
	if !truncated {
		t.Error("truncated flag should be true for oversized line")
	}
	if len(got) != max {
		t.Errorf("returned %d bytes, want %d", len(got), max)
	}
	if got != strings.Repeat("a", max) {
		t.Errorf("got %q, want capped prefix", got)
	}
	next, _, err := readBoundedLine(r, max)
	if err != nil {
		t.Fatalf("err on second line: %v", err)
	}
	if next != "next\n" {
		t.Errorf("next line = %q, want %q (reader frame misaligned)", next, "next\n")
	}
}

// TestReadBoundedLine_PassesNormalLine: a normal-size line passes
// through unchanged with truncated=false.
func TestReadBoundedLine_PassesNormalLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("hello world\n"))
	got, truncated, err := readBoundedLine(r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("normal line should not be marked truncated")
	}
	if got != "hello world\n" {
		t.Errorf("got %q, want %q", got, "hello world\n")
	}
}

// TestReadBoundedLine_EOFWithoutNewline: a final line that lacks a
// terminating newline returns io.EOF with the data so far.
func TestReadBoundedLine_EOFWithoutNewline(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("trailing"))
	got, truncated, err := readBoundedLine(r, 1024)
	if err != io.EOF {
		t.Errorf("err = %v, want EOF", err)
	}
	if truncated {
		t.Error("under-cap trailing data should not be truncated")
	}
	if got != "trailing" {
		t.Errorf("got %q, want %q", got, "trailing")
	}
}

func TestFileReader_StreamsLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maillog")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewFileReader(path)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		// Give the file reader time to seek and start polling.
		time.Sleep(150 * time.Millisecond)
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		defer f.Close()
		_, _ = f.WriteString("Jan  2 10:00:00 host postfix: hello\n")
	}()

	select {
	case line, ok := <-out:
		if !ok {
			t.Fatal("channel closed before line received")
		}
		if line.Message == "" {
			t.Fatalf("expected non-empty line, got %+v", line)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for line")
	}
}

func TestFileReader_SkipsOversizedLineAndContinues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maillog")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewFileReader(path)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Errorf("open append: %v", err)
			return
		}
		defer f.Close()
		_, _ = f.WriteString(strings.Repeat("A", maxLogLineBytes+32) + "\n")
		_, _ = f.WriteString("Jan  2 10:00:01 host dovecot: after\n")
	}()

	select {
	case line, ok := <-out:
		if !ok {
			t.Fatal("channel closed before line received")
		}
		if strings.HasPrefix(line.Message, "A") {
			t.Fatalf("oversized line was emitted instead of skipped: len=%d", len(line.Message))
		}
		if line.Message != "Jan  2 10:00:01 host dovecot: after\n" {
			t.Fatalf("line = %q, want post-oversize line", line.Message)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for post-oversize line")
	}
}

func TestFileReader_MissingFileReturnsError(t *testing.T) {
	r := NewFileReader(filepath.Join(t.TempDir(), "missing"))
	out, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected missing file error")
	}
	if out != nil {
		t.Fatalf("expected nil output channel on startup error, got %v", out)
	}
}

func TestFileReader_ContextCancelClosesChannel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maillog")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewFileReader(path)
	ctx, cancel := context.WithCancel(context.Background())
	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	// Channel must close after cancel.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-out:
			if !ok {
				return // channel closed - success
			}
		case <-deadline:
			t.Fatal("channel did not close after context cancel")
		}
	}
}
