//go:build linux

package maillog

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

func TestFileSourceRecoversWhenOriginalReturnsAfterFailedRotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mail.log")
		w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		q := NewQueue()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out, err := NewFileReader(path, q).Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if renameErr := os.Rename(path, path+".old"); renameErr != nil {
			t.Fatal(renameErr)
		}
		// A socket has valid path metadata but cannot be opened as a log.
		// This drives the real rotation open failure even when tests run as root.
		socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		socket.SetUnlinkOnClose(false)
		defer func() {
			if closeErr := socket.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if row := fileSourceRow(t, q); row.Reason != "source_io" || !row.DroppedLowerBound {
			t.Errorf("actual rotation failure was hidden: %+v", row)
		}
		if renameErr := os.Rename(path, path+".socket"); renameErr != nil {
			t.Fatal(renameErr)
		}
		if renameErr := os.Rename(path+".old", path); renameErr != nil {
			t.Fatal(renameErr)
		}
		appendMailAndPoll(t, w, "returned\n")
		expectMailLine(t, out, "returned\n")
		row := fileSourceRow(t, q)
		if row.Status != "ok" || row.Depth != 0 || !row.DroppedLowerBound {
			t.Errorf("usable original source retained obsolete rotation error: %+v", row)
		}
		cancel()
		for line := range out {
			line.reject()
			t.Error("unexpected extra record")
		}
		if got := q.QueueStatuses(time.Now())["delivery"].DroppedTotal; got != 0 {
			t.Errorf("failed rotation invented known record loss: %d", got)
		}
	})
}
