package maillog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func processMailLine(t *testing.T, out <-chan Line) Line {
	t.Helper()
	line, ok := <-out
	if !ok {
		t.Fatal("mail reader stopped")
	}
	line.Process(func(Line) bool { return true })
	return line
}

// A file line names one generation of the file as its stream and its start
// offset as its cursor; a file truncated in place starts a new stream.
func TestFileReaderLinePositions(t *testing.T) {
	withPollingMailFile(t, func(t *testing.T, path string, w *os.File, out <-chan Line) {
		appendMailAndPoll(t, w, "first line\nsecond\n")
		a, b := processMailLine(t, out), processMailLine(t, out)
		if a.Position.Cursor != "0" || b.Position.Cursor != "11" || !strings.HasPrefix(a.Position.Stream, "m:") ||
			a.Position.Stream != b.Position.Stream || a.Position.ObservedAt.IsZero() {
			t.Fatalf("positions %+v and %+v, want offsets 0 and 11 in one file stream", a.Position, b.Position)
		}
		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
		appendMailAndPoll(t, w, "third\n")
		c := processMailLine(t, out)
		if c.Message != "third\n" || c.Position.Cursor != "0" || c.Position.Stream == a.Position.Stream {
			t.Fatalf("after truncation %+v, want offset 0 in a new stream", c)
		}
	})
}

// A rotated file can return to an earlier inode with a new line at offset zero.
func TestFileReaderLinePositionsAfterRotationBack(t *testing.T) {
	withPollingMailFile(t, func(t *testing.T, path string, w *os.File, out <-chan Line) {
		appendMailAndPoll(t, w, "first\n")
		a := processMailLine(t, out)
		if err := os.Rename(path, path+".first"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		_ = processMailLine(t, out)
		if err := os.Rename(path, path+".second"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".first", path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("third\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		b := processMailLine(t, out)
		if b.Position.Cursor != "0" || b.Position.Stream == a.Position.Stream {
			t.Fatalf("rotation reused %+v as %+v", a.Position, b.Position)
		}
	})
}

// The supervisor can reattach the same inode after a fault without a process
// restart. Reused offsets must still belong to a new reader stream.
func TestFileReaderLinePositionsAfterReattachment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var previous Position
		for i := 0; i < 2; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			out, err := NewFileReader(path, NewQueue()).Run(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			synctest.Wait()
			if writeErr := os.WriteFile(path, []byte("line\n"), 0o600); writeErr != nil {
				cancel()
				t.Fatal(writeErr)
			}
			time.Sleep(2 * time.Second)
			synctest.Wait()
			line := processMailLine(t, out)
			cancel()
			synctest.Wait()
			if extra, ok := <-out; ok {
				t.Fatalf("unexpected line at shutdown: %+v", extra)
			}
			if line.Position.Cursor != "0" || line.Position.Stream == "" || (i > 0 && line.Position.Stream == previous.Stream) {
				t.Fatalf("reattachment reused %+v as %+v", previous, line.Position)
			}
			previous = line.Position
			if truncateErr := os.Truncate(path, 0); truncateErr != nil {
				t.Fatal(truncateErr)
			}
		}
	})
}
