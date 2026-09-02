package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
	"github.com/pidginhost/csm/internal/config"
)

// Shutdown used to set the package-level alert.FindingBus to nil after
// closing it. Control-socket and web UI goroutines are not tracked by the
// daemon's wait group and can still be inside alert.Dispatch, which reads
// that global unsynchronised: a torn interface read there is a nil-receiver
// panic during an otherwise clean stop. Close already turns Publish into a
// no-op, so the bus stays installed.
func TestShutdownKeepsClosedFindingBusInstalled(t *testing.T) {
	prev := alert.FindingBus
	t.Cleanup(func() { alert.FindingBus = prev })

	bus := broadcast.NewBus(8)
	alert.FindingBus = bus
	d := New(&config.Config{}, nil, nil, "")
	d.findingBus = bus

	d.closeFindingBus()

	if alert.FindingBus == nil {
		t.Fatal("shutdown cleared alert.FindingBus; late publishers now race a nil interface")
	}
	// Publishing after close must be silently dropped, never delivered or panic.
	alert.FindingBus.Publish(alert.Finding{Check: "late", Message: "after close"})
}
