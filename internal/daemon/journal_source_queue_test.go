//go:build linux && journal

package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/maillog"
)

func TestDaemonPublishesActualJournalSourceUncertainty(t *testing.T) {
	d := &Daemon{}
	queue := maillog.NewQueue()
	d.registerQueueSource("mail", queue)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := maillog.NewJournalReader([]string{"csm-queue-regression.service"}, queue)
	lines, err := reader.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for line := range lines {
		line.Process(func(maillog.Line) bool { return false })
		t.Error("canceled journal source emitted an entry")
	}
	// The cursor exposes no unread count and no waiting age, so the row marks
	// the missing backlog age instead of reporting a wait of zero.
	row, exists := d.QueueStatuses()["mail.journal_source"]
	if !exists || row.Depth != 0 || !row.DepthUnavailable || !row.CapacityUnavailable || row.InFlight != 0 || !row.DroppedLowerBound || row.Status != "ok" || row.LagBasis != "unavailable" {
		t.Fatalf("journal source uncertainty was not published: exists=%v row=%+v", exists, row)
	}
}
