package maillog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func fileSourceRow(t *testing.T, q *Queue) queuehealth.Status {
	t.Helper()
	row, ok := q.QueueStatuses(time.Now())["file_source"]
	if !ok {
		t.Fatal("file source queue missing")
	}
	if row.DepthUnit != "bytes" || !row.CapacityUnavailable || row.Capacity != 0 {
		t.Fatalf("file backlog has misleading units or capacity: %+v", row)
	}
	return row
}

func TestFileSourceMeasuresReadAheadAndBlockedAppends(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mail.log")
		if err := os.WriteFile(path, []byte("historical\n"), 0600); err != nil {
			t.Fatal(err)
		}
		w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
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
		if row := fileSourceRow(t, q); row.Depth != 0 || row.DepthUnavailable || row.Status != "ok" {
			t.Fatalf("initial tail included historical bytes: %+v", row)
		}
		appendMailAndPoll(t, w, strings.Repeat("queued\n", 100))
		row := fileSourceRow(t, q)
		if row.Depth != 35*len("queued\n") || row.DepthUnavailable || q.QueueStatuses(time.Now())["delivery"].Depth != 65 {
			t.Fatalf("read-ahead disappeared or admitted records were double-counted: %+v", row)
		}
		appendMailAndPoll(t, w, strings.Repeat("later\n", 50))
		row = fileSourceRow(t, q)
		wantBytes := 35*len("queued\n") + 50*len("later\n")
		if row.Depth != wantBytes || row.DepthUnavailable {
			t.Fatalf("blocked delivery concealed new on-disk backlog: %+v want=%d", row, wantBytes)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		row = fileSourceRow(t, q)
		if row.Status != "degraded" || row.LagBasis != "consumer_progress" || row.LagSeconds < 60 {
			t.Fatalf("metadata sampling concealed the stalled consumer: %+v", row)
		}
		expectMailLine(t, out, "queued\n")
		synctest.Wait()
		if row = fileSourceRow(t, q); row.Depth != wantBytes-len("queued\n") || row.LagSeconds != 0 {
			t.Fatalf("actual delivery progress did not advance byte ownership: %+v", row)
		}
		cancel()
		count := 0
		for line := range out {
			count++
			line.reject()
		}
		row = fileSourceRow(t, q)
		delivery := q.QueueStatuses(time.Now())["delivery"]
		// The first read brought all 100 complete records into memory. The
		// later append stayed on disk, so its record count remains unknown.
		if count != 64 || delivery.DroppedTotal != 99 || delivery.Depth != 0 || row.Depth != 0 || !row.DroppedLowerBound || row.ProcessingSeconds != 0 {
			t.Fatalf("shutdown lost known read-ahead evidence or invented unread records: buffered=%d source=%+v delivery=%+v", count, row, delivery)
		}
	})
}

func TestFileSourcePartialRecordWaitsForInput(t *testing.T) {
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
		partial := strings.Repeat("P", maxLogLineBytes*3+7)
		appendMailAndPoll(t, w, partial)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		row := fileSourceRow(t, q)
		if row.Depth != len(partial) || row.DepthUnavailable || row.Status != "ok" || row.LagSeconds != 0 || row.ProcessingSeconds != 0 || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 0 {
			t.Fatalf("partial framing lost raw bytes or became a false stalled record: %+v", row)
		}
		appendMailAndPoll(t, w, "\nvalid\n")
		expectMailLine(t, out, "valid\n")
		cancel()
		for line := range out {
			line.reject()
			t.Error("unexpected extra record")
		}
		row = fileSourceRow(t, q)
		if row.Depth != 0 || q.QueueStatuses(time.Now())["delivery"].DroppedTotal != 1 {
			t.Fatalf("oversized completion duplicated losses or retained bytes: %+v", row)
		}
	})
}
