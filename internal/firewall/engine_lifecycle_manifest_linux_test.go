//go:build linux

package firewall

import (
	"errors"
	"testing"
)

func TestReplayRefusesABatchWithTheSameHeader(t *testing.T) {
	batch := manifestBatch()
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, lifecycle: &Lifecycle{Store: manifestReadStore{action: batch}}}
	replayed, err := e.replayActionLocked(batch.Request)
	if !replayed || !errors.Is(err, ErrStateConflict) {
		t.Fatalf("replay of a batch header = %v, %v; want conflict", replayed, err)
	}
}
