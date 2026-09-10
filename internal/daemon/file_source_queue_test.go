//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/maillog"
)

func TestDaemonPublishesActualFileSourceBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.log")
	if err := os.WriteFile(path, []byte("historical record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	q := maillog.NewQueue()
	d.registerQueueSource("mail", q)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lines, err := maillog.NewFileReader(path, q).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for line := range lines {
		line.Process(func(maillog.Line) bool { return false })
		t.Error("canceled file source emitted historical work")
	}
	row, exists := d.QueueStatuses()["mail.file_source"]
	if !exists || row.Status != "ok" || row.Depth != 0 || row.DepthUnavailable || row.DepthUnit != "bytes" || !row.CapacityUnavailable || !row.DroppedLowerBound || row.ProcessingSeconds != 0 || row.LagBasis != "consumer_progress" {
		t.Fatalf("actual file source row missing or mislabeled: exists=%v row=%+v", exists, row)
	}
}
