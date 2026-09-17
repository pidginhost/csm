package maillog

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestFileSourceJoinsSamplerBeforeClosingDescriptor(t *testing.T) {
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
		var hold, closed atomic.Bool
		q := NewQueue()
		cancel, out := startFileSourceProbe(t, path, q, func(base mailLogFile) mailLogFile {
			return sourceFileProbe{mailLogFile: base, stat: func() (os.FileInfo, error) {
				if hold.CompareAndSwap(true, false) {
					close(entered)
					<-release
				}
				return base.Stat()
			}, close: func() error {
				closed.Store(true)
				return base.Close()
			}}
		})
		appendMailAndPoll(t, w, strings.Repeat("queued\n", 100))
		hold.Store(true)
		time.Sleep(2 * time.Second)
		<-entered
		cancel()
		synctest.Wait()
		if closed.Load() {
			t.Error("descriptor closed while its sampler still owned an I/O call")
		}
		time.Sleep(time.Minute)
		row := fileSourceRow(t, q)
		if row.Reason != "processing_lag" || row.ProcessingSeconds < 60 || row.Depth != 35*len("queued\n") || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 1 {
			t.Errorf("blocked cleanup hid progress or settled known records early: %+v", row)
		}
		unblock()
		for line := range out {
			line.reject()
		}
		row = fileSourceRow(t, q)
		if !closed.Load() || row.Status != "ok" || row.Depth != 0 || row.ProcessingSeconds != 0 || !row.DroppedLowerBound || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 100 {
			t.Errorf("normal shutdown manufactured a source failure or lost known records: %+v", row)
		}
	})
}

func TestFileSourceOwnsKnownReadAheadThroughActualClose(t *testing.T) {
	for _, mode := range []string{"normal", "error", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "mail.log")
				w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				q := NewQueue()
				r := NewFileReader(path, q)
				input, err := r.open()
				if err != nil {
					t.Fatal(err)
				}
				base := input.file
				entered, release := make(chan struct{}), make(chan struct{})
				exited := make(chan any, 1)
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				ctx, cancel := context.WithCancel(context.Background())
				joined := false
				defer func() {
					cancel()
					unblock()
					if !joined {
						<-exited
					}
				}()
				input.file = sourceFileProbe{mailLogFile: base, close: func() error {
					defer func() { close(entered); <-release }()
					if err := base.Close(); err != nil {
						t.Error(err)
					}
					switch mode {
					case "error":
						return errors.New("synthetic close failure")
					case "panic":
						panic("source close interruption")
					case "goexit":
						runtime.Goexit()
					}
					return nil
				}}
				input.reader = bufio.NewReader(input.file)
				out := q.channel()
				returned := false
				go func() {
					defer func() { exited <- recover() }()
					r.loop(ctx, out, input)
					returned = true
				}()
				synctest.Wait()
				appendMailAndPoll(t, w, strings.Repeat("queued\n", 100))
				cancel()
				<-entered
				time.Sleep(time.Minute)
				row := fileSourceRow(t, q)
				if row.Depth != 35*len("queued\n") || row.Reason != "processing_lag" || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 1 {
					t.Errorf("actual Close released known buffered work early: %+v", row)
				}
				unblock()
				caught := <-exited
				joined = true
				wantReturn := mode == "normal" || mode == "error"
				if returned != wantReturn || mode == "panic" && caught != "source close interruption" || mode != "panic" && caught != nil {
					t.Errorf("close outcome changed: returned=%v caught=%v", returned, caught)
				}
				for line := range out {
					line.reject()
				}
				row = fileSourceRow(t, q)
				wantReason := "source_io"
				if mode == "normal" {
					wantReason = ""
				}
				if row.Reason != wantReason || row.Depth != 0 || row.ProcessingSeconds != 0 || !row.DroppedLowerBound || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 100 {
					t.Errorf("final Close settlement lost or duplicated records: %+v", row)
				}
			})
		})
	}
}
