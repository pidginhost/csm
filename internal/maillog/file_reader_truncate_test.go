package maillog

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func expectMailLine(t *testing.T, out <-chan Line, want string) {
	t.Helper()
	select {
	case got, ok := <-out:
		if !ok || got.Source != "file" || got.Message != want {
			t.Fatalf("mail line = %+v (open=%v), want %q", got, ok, want)
		}
		got.Process(func(Line) bool { return true })
	case <-time.After(6 * time.Second):
		t.Fatalf("mail line %q was not delivered", want)
	}
}

func TestFileReaderCopytruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(path, []byte(strings.Repeat("old log\n", 1024)), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewFileReader(path, NewQueue())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"dovecot: user=<first@example.test> authentication failed\n", "postfix: second\n"} {
		if writeErr := os.WriteFile(path, []byte(message), 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
		expectMailLine(t, out, message)
	}
	if truncateErr := os.Truncate(path, 0); truncateErr != nil {
		t.Fatal(truncateErr)
	}
	// Leave the file empty through a poll before appending the next record.
	time.Sleep(2500 * time.Millisecond)
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.WriteString("third\n"); err != nil {
		t.Fatal(err)
	}
	expectMailLine(t, out, "third\n")
	cancel()
	select {
	case got, ok := <-out:
		if ok {
			t.Fatalf("duplicate mail line after rotations: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not stop after cancellation")
	}
}

func TestFileReaderRotationDrainsOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(path, []byte("historical line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := NewFileReader(path, NewQueue()).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.WriteString("original before rotate\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expectMailLine(t, out, "original before rotate\n")
	expectMailLine(t, out, "replacement\n")
}

func TestRewindTruncatedFileDiscardsReadAhead(t *testing.T) {
	for _, replacement := range []string{"", "new generation\n"} {
		t.Run(replacement, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "maillog")
			if err := os.WriteFile(path, []byte(strings.Repeat("old\n", 256)), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			reader := bufio.NewReader(f)
			if _, err := reader.ReadByte(); err != nil {
				t.Fatal(err)
			}
			if reset, err := rewindTruncatedFile(f, reader); reset || err != nil {
				t.Fatalf("unchanged file: reset=%v, error=%v", reset, err)
			}
			if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
				t.Fatal(err)
			}
			if reset, err := rewindTruncatedFile(f, reader); !reset || err != nil {
				t.Fatalf("truncated file: reset=%v, error=%v", reset, err)
			}
			if reader.Buffered() != 0 {
				t.Fatal("old read-ahead bytes survived truncation")
			}
			if replacement != "" {
				got, err := reader.ReadString('\n')
				if err != nil || got != replacement {
					t.Fatalf("replacement = %q, error=%v", got, err)
				}
			}
		})
	}
}
