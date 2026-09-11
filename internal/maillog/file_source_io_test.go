package maillog

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type sourceFileProbe struct {
	mailLogFile
	stat  func() (os.FileInfo, error)
	seek  func(int64, int) (int64, error)
	close func() error
}

func (f sourceFileProbe) Stat() (os.FileInfo, error) {
	if f.stat != nil {
		return f.stat()
	}
	return f.mailLogFile.Stat()
}

func (f sourceFileProbe) Seek(offset int64, whence int) (int64, error) {
	if f.seek != nil {
		return f.seek(offset, whence)
	}
	return f.mailLogFile.Seek(offset, whence)
}

func (f sourceFileProbe) Close() error {
	if f.close != nil {
		return f.close()
	}
	return f.mailLogFile.Close()
}

func startFileSourceProbe(t *testing.T, path string, q *Queue, wrap func(mailLogFile) mailLogFile) (context.CancelFunc, <-chan Line) {
	t.Helper()
	r := NewFileReader(path, q)
	input, err := r.open()
	if err != nil {
		t.Fatal(err)
	}
	input.file = wrap(input.file)
	input.reader = bufio.NewReader(input.file)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := q.channel()
	go r.loop(ctx, out, input)
	synctest.Wait()
	return cancel, out
}

func TestFileSourceCursorFailureSurvivesSuccessfulRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mail.log")
		w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		var failSeek atomic.Bool
		failSeek.Store(true)
		q := NewQueue()
		cancel, out := startFileSourceProbe(t, path, q, func(base mailLogFile) mailLogFile {
			return sourceFileProbe{mailLogFile: base, seek: func(offset int64, whence int) (int64, error) {
				if failSeek.Load() {
					return 0, errors.New("synthetic cursor failure")
				}
				return base.Seek(offset, whence)
			}}
		})
		appendMailAndPoll(t, w, strings.Repeat("queued\n", 100))
		row := fileSourceRow(t, q)
		if row.Reason != "source_io" || !row.DroppedLowerBound || q.QueueStatuses(time.Now())["delivery"].Depth != 65 {
			t.Errorf("successful reads or metadata samples hid failed rewind: %+v", row)
		}
		failSeek.Store(false)
		for range 100 {
			expectMailLine(t, out, "queued\n")
		}
		synctest.Wait()
		row = fileSourceRow(t, q)
		if row.Status != "ok" || row.Depth != 0 || !row.DroppedLowerBound || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 0 {
			t.Errorf("successful cursor recovery lost evidence or invented loss: %+v", row)
		}
		cancel()
		for line := range out {
			line.reject()
			t.Error("unexpected extra record")
		}
	})
}

func TestFileSourceMetadataFailureMakesDepthUnknown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mail.log")
		w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		var failStat atomic.Bool
		q := NewQueue()
		cancel, out := startFileSourceProbe(t, path, q, func(base mailLogFile) mailLogFile {
			return sourceFileProbe{mailLogFile: base, stat: func() (os.FileInfo, error) {
				if failStat.Load() {
					return nil, errors.New("synthetic metadata failure")
				}
				return base.Stat()
			}}
		})
		appendMailAndPoll(t, w, strings.Repeat("queued\n", 100))
		failStat.Store(true)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		row := fileSourceRow(t, q)
		if row.Reason != "source_io" || !row.DepthUnavailable || row.Depth != 0 || !row.DroppedLowerBound {
			t.Errorf("failed metadata presented stale bytes as measured depth: %+v", row)
		}
		failStat.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		row = fileSourceRow(t, q)
		if row.Status != "ok" || row.DepthUnavailable || row.Depth != 35*len("queued\n") || !row.DroppedLowerBound {
			t.Errorf("metadata recovery lost byte ownership or history: %+v", row)
		}
		cancel()
		for line := range out {
			line.reject()
		}
		if got := q.QueueStatuses(time.Now())["delivery"].DroppedTotal; got != 100 {
			t.Errorf("metadata failure altered known record loss: %d", got)
		}
	})
}

func TestFileSourceLateSampleCannotRestoreOldGeneration(t *testing.T) {
	for _, mode := range []string{"rotate", "copytruncate"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "mail.log")
				w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				var hold atomic.Bool
				q := NewQueue()
				cancel, out := startFileSourceProbe(t, path, q, func(base mailLogFile) mailLogFile {
					return sourceFileProbe{mailLogFile: base, stat: func() (os.FileInfo, error) {
						info, err := base.Stat()
						if hold.CompareAndSwap(true, false) {
							close(entered)
							<-release
						}
						return info, err
					}}
				})
				appendMailAndPoll(t, w, strings.Repeat("old\n", 100))
				hold.Store(true)
				time.Sleep(2 * time.Second)
				<-entered
				if mode == "rotate" {
					if err := os.Rename(path, path+".1"); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, []byte("fresh"), 0600); err != nil {
					t.Fatal(err)
				}
				for range 100 {
					expectMailLine(t, out, "old\n")
				}
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if row := fileSourceRow(t, q); row.DepthUnavailable || row.Depth != len("fresh") {
					t.Errorf("new generation bytes were not published during old sample: %+v", row)
				}
				unblock()
				synctest.Wait()
				row := fileSourceRow(t, q)
				if row.DepthUnavailable || row.Depth != len("fresh") || row.Status != "ok" || !row.DroppedLowerBound {
					t.Errorf("late old sample corrupted replacement: %+v", row)
				}
				cancel()
				for line := range out {
					line.reject()
					t.Error("partial replacement was emitted")
				}
				if got := q.QueueStatuses(time.Now())["delivery"].DroppedTotal; got != 0 {
					t.Errorf("generation change invented complete record loss: %d", got)
				}
			})
		})
	}
}
