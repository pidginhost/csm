package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// An operator unblock that removes the firewall row after the consumer read
// it must not leave the applied block's threat row behind, or reputation
// would re-flag the address until the block's expiry.
func TestAdmissionAppliedBlockYieldsToAConcurrentUnblock(t *testing.T) {
	dir := t.TempDir()
	sdb, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	t.Cleanup(checks.SetGlobalThreatDBForTest(dir))
	const ip = "203.0.113.48"
	row := appliedRow(t, "8", ip, time.Now().Add(time.Hour).UTC())
	path := filepath.Join(dir, "firewall", "state.json")
	writeState := func(s firewall.FirewallState) {
		data, err := json.Marshal(s)
		if err == nil {
			err = os.WriteFile(path, data, 0o600)
		}
		if err != nil {
			t.Error(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeState(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
		IP: ip, Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
		ActionID: string(row.Attempt.ID), ExpiresAt: row.ExpiresAt,
	}}})
	unblocked := make(chan struct{})
	previous := loadAppliedState
	t.Cleanup(func() { loadAppliedState = previous })
	loadAppliedState = func(statePath string) (*firewall.FirewallState, error) {
		state, err := previous(statePath)
		// The unblock lands right after the read: the engine drops the
		// row, then the handler drops the threat row.
		go func() {
			writeState(firewall.FirewallState{})
			dropAutoBlockThreatRow(ip)
			close(unblocked)
		}()
		select {
		case <-unblocked:
		case <-time.After(100 * time.Millisecond):
		}
		return state, err
	}
	d := New(&config.Config{StatePath: dir}, nil, nil, "")
	if err := d.consumeAppliedBlocks([]admission.AuditRow{row}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-unblocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the unblock never finished")
	}
	if _, found := sdb.GetPermanentBlock(ip); found {
		t.Error("an unblock during delivery left a stored threat row")
	}
	if match, ok := checks.GetThreatDB().LookupMatch(ip); ok {
		t.Errorf("an unblock during delivery left threat evidence %+v", match)
	}
}
