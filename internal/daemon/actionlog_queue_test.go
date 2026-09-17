package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestActionLogQueuePublishedBeforeAnyWrite(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	got, exists := d.QueueStatuses()["actionlog.writes"]
	if !exists || got.Capacity != 64 {
		t.Fatalf("action log write slots missing: exists=%v status=%+v", exists, got)
	}
}
