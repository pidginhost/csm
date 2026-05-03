package alert

import (
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

type stubBus struct {
	publishCount atomic.Int32
}

func (s *stubBus) Publish(_ Finding) {
	s.publishCount.Add(1)
}

func TestDispatch_PublishesEachFindingToBus(t *testing.T) {
	bus := &stubBus{}
	prev := FindingBus
	FindingBus = bus
	t.Cleanup(func() { FindingBus = prev })

	findings := []Finding{
		{Check: "a", Severity: High},
		{Check: "b", Severity: Critical},
	}

	// Zero-value Config: email and webhook both disabled, so Dispatch returns
	// after publishing to the bus without attempting any delivery.
	cfg := &config.Config{}
	_ = Dispatch(cfg, findings)

	if got := bus.publishCount.Load(); got != int32(len(findings)) {
		t.Fatalf("expected %d publishes, got %d", len(findings), got)
	}
}
