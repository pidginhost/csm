package maillog

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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

// mailRef is the reference every reader gives a line of path: the file by
// device and inode, the line by offset and bytes.
func mailRef(t *testing.T, path string, offset int64, text string) Position {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino := fileIdentity(info)
	return Position{Stream: alert.FileStream(dev, ino), Cursor: alert.RecordCursor(offset, text)}
}

func sameMailRef(a, b Position) bool { return a.Stream == b.Stream && a.Cursor == b.Cursor }

// A file line names its file as the stream and its offset and bytes as the
// cursor; a line written after the file was truncated in place is another
// record at the reused offset.
func TestFileReaderLinePositions(t *testing.T) {
	withPollingMailFile(t, func(t *testing.T, path string, w *os.File, out <-chan Line) {
		appendMailAndPoll(t, w, "first line\nsecond\r\n")
		a, b := processMailLine(t, out), processMailLine(t, out)
		if !sameMailRef(a.Position, mailRef(t, path, 0, "first line")) || !sameMailRef(b.Position, mailRef(t, path, 11, "second")) ||
			a.Position.ObservedAt.IsZero() {
			t.Fatalf("positions %+v and %+v, want offsets 0 and 11 of the file", a.Position, b.Position)
		}
		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
		appendMailAndPoll(t, w, "third\n")
		c := processMailLine(t, out)
		if c.Message != "third\n" || !sameMailRef(c.Position, mailRef(t, path, 0, "third")) || sameMailRef(c.Position, a.Position) {
			t.Fatalf("after truncation %+v, want the new line named anew", c)
		}
	})
}

// A rotated file can return to an earlier inode with a new line at offset
// zero; that line is another record than the one first read there.
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
		if !sameMailRef(b.Position, mailRef(t, path, 0, "third")) || sameMailRef(a.Position, b.Position) {
			t.Fatalf("rotation named %+v as %+v", a.Position, b.Position)
		}
	})
}

// The supervisor can reattach the same inode after a fault without a process
// restart. A new line at a reused offset is still another record.
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
			text := "line " + strconv.Itoa(i)
			if writeErr := os.WriteFile(path, []byte(text+"\n"), 0o600); writeErr != nil {
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
			if !sameMailRef(line.Position, mailRef(t, path, 0, text)) || (i > 0 && sameMailRef(line.Position, previous)) {
				t.Fatalf("reattachment named %+v as %+v", previous, line.Position)
			}
			previous = line.Position
			if truncateErr := os.Truncate(path, 0); truncateErr != nil {
				t.Fatal(truncateErr)
			}
		}
	})
}

// startMailReaderAt runs a file reader at the end of the log at path, which
// already holds content, and checks that it delivers nothing more at shutdown.
func startMailReaderAt(t *testing.T, content string, test func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		q := NewQueue()
		out, err := NewFileReader(path, q).Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		test(t, path, w, q, out)
		cancel()
		synctest.Wait()
		if got, ok := <-out; ok {
			t.Fatalf("unexpected extra line before shutdown: %+v", got)
		}
	})
}

// settledEveryByte fails unless the file source holds no backlog and the
// reader lost no line.
func settledEveryByte(t *testing.T, q *Queue) {
	t.Helper()
	row := fileSourceRow(t, q)
	if row.Depth != 0 || row.DepthUnavailable || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 0 {
		t.Fatalf("file source %+v, delivery %+v: want every delivered byte settled and nothing lost", row, q.QueueStatuses(time.Now())["delivery"])
	}
}

// A reader started inside a line delivers the rest of that line, but the
// record began before the reader did: the remainder names no position. The
// next line is named as every reader names it.
func TestFileReaderDoesNotNameAStartupFragment(t *testing.T) {
	unnamedThenNamed := func(t *testing.T, path string, a, b Line, fragment string, next int64) {
		t.Helper()
		if a.Message != fragment || b.Message != "hit next\n" {
			t.Fatalf("lines %q then %q, want %q then the next line", a.Message, b.Message, fragment)
		}
		if a.Position != (Position{}) {
			t.Fatalf("startup fragment %q named %+v", fragment, a.Position)
		}
		if want := mailRef(t, path, next, "hit next"); !sameMailRef(b.Position, want) || b.Position.ObservedAt.IsZero() {
			t.Fatalf("next line named %+v, want %+v", b.Position, want)
		}
	}
	firstNamed := func(t *testing.T, path string, line Line, offset int64) {
		t.Helper()
		if want := mailRef(t, path, offset, "hit fresh"); line.Message != "hit fresh\n" || !sameMailRef(line.Position, want) {
			t.Fatalf("first complete record %+v, want it named %+v", line, want)
		}
	}
	t.Run("one poll", func(t *testing.T) {
		startMailReaderAt(t, "before ", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit suffix\nhit next\n")
			a, b := processMailLine(t, out), processMailLine(t, out)
			unnamedThenNamed(t, path, a, b, "hit suffix\n", 18)
			settledEveryByte(t, q)
		})
	})
	t.Run("split polls", func(t *testing.T) {
		startMailReaderAt(t, "before ", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit suf")
			expectNoMailLine(t, out)
			appendMailAndPoll(t, w, "fix\nhit next\n")
			a, b := processMailLine(t, out), processMailLine(t, out)
			unnamedThenNamed(t, path, a, b, "hit suffix\n", 18)
			settledEveryByte(t, q)
		})
	})
	t.Run("new reader", func(t *testing.T) {
		// A reader restarted after another stopped inside the same line.
		startMailReaderAt(t, "before hit suf", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit\nhit next\n")
			a, b := processMailLine(t, out), processMailLine(t, out)
			unnamedThenNamed(t, path, a, b, "hit\n", 18)
			settledEveryByte(t, q)
		})
	})
	t.Run("empty", func(t *testing.T) {
		startMailReaderAt(t, "", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit fresh\n")
			firstNamed(t, path, processMailLine(t, out), 0)
			settledEveryByte(t, q)
		})
	})
	t.Run("terminated", func(t *testing.T) {
		startMailReaderAt(t, "before\n", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit fresh\n")
			firstNamed(t, path, processMailLine(t, out), 7)
			settledEveryByte(t, q)
		})
	})
	t.Run("copytruncate", func(t *testing.T) {
		startMailReaderAt(t, "before before ", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit suf")
			expectNoMailLine(t, out)
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
			appendMailAndPoll(t, w, "hit fresh\n")
			firstNamed(t, path, processMailLine(t, out), 0)
			settledEveryByte(t, q)
		})
	})
	t.Run("rotation", func(t *testing.T) {
		startMailReaderAt(t, "before ", func(t *testing.T, path string, w *os.File, q *Queue, out <-chan Line) {
			appendMailAndPoll(t, w, "hit suf")
			expectNoMailLine(t, out)
			if err := os.Rename(path, path+".1"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("hit fresh\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(4 * time.Second)
			synctest.Wait()
			firstNamed(t, path, processMailLine(t, out), 0)
			settledEveryByte(t, q)
		})
	})
}

// The mail reader passes the raw line and names it as the shared helper does:
// one LF, CRLF or repeated CR before LF ends it, and leading and trailing
// spaces are content. The same bytes at the same offset of the same file keep
// their ref in a reattached reader.
func TestFileReaderLinePositionsMatchTheSharedRef(t *testing.T) {
	raw := []string{"hit x\n", "hit x\r\n", "hit x\r\r\n", " hit x \n", "hit x  \r\n", "hit y\n"}
	var first Position
	withPollingMailFile(t, func(t *testing.T, path string, w *os.File, out <-chan Line) {
		appendMailAndPoll(t, w, strings.Join(raw, ""))
		seen := map[string]int{}
		var offset int64
		for i, record := range raw {
			line := processMailLine(t, out)
			if want := mailRef(t, path, offset, record); line.Message != record || !sameMailRef(line.Position, want) {
				t.Errorf("record %d %q delivered as %q named %+v, want %+v", i, record, line.Message, line.Position, want)
			}
			if j, dup := seen[line.Position.Cursor]; dup {
				t.Errorf("records %d and %d share cursor %q", j, i, line.Position.Cursor)
			}
			seen[line.Position.Cursor] = i
			if i == 0 {
				first = line.Position
			}
			offset += int64(len(record))
		}
		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
		appendMailAndPoll(t, w, raw[0])
		if again := processMailLine(t, out); !sameMailRef(again.Position, first) {
			t.Fatalf("the same bytes at offset 0 named %+v, first %+v", again.Position, first)
		}
	})
}

// A truncation between SeekEnd and the boundary read leaves the saved
// position past EOF. Starting there must recover and deliver the new file.
func TestFileReaderStartsAfterBoundaryDisappears(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		if err := os.WriteFile(path, []byte("fresh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		q := NewQueue()
		r := NewFileReader(path, q)
		// Reproduce the stale result of SeekEnd after the file shrank.
		input, err := r.openAt(128, io.SeekStart)
		if err != nil {
			t.Fatalf("open after truncation: %v", err)
		}
		// Regrowth before the first poll must not hide the lost boundary.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			_ = input.file.Close()
			t.Fatal(err)
		}
		_, err = f.WriteString(strings.Repeat("later\n", 32))
		_ = f.Close()
		if err != nil {
			_ = input.file.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := q.channel()
		go r.loop(ctx, out, input)
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		line := processMailLine(t, out)
		want := mailRef(t, path, 0, "fresh\n")
		if line.Message != "fresh\n" || !sameMailRef(line.Position, want) || line.Position.ObservedAt.IsZero() {
			t.Fatalf("recovered line %+v, want fresh record named %+v", line, want)
		}
		for i := range 32 {
			line := processMailLine(t, out)
			want := mailRef(t, path, int64(len("fresh\n")+i*len("later\n")), "later\n")
			if line.Message != "later\n" || !sameMailRef(line.Position, want) {
				t.Fatalf("regrown line %d: %+v, want %+v", i, line, want)
			}
		}
		settledEveryByte(t, q)
		cancel()
		synctest.Wait()
		if extra, ok := <-out; ok {
			t.Fatalf("unexpected extra line: %+v", extra)
		}
	})
}
