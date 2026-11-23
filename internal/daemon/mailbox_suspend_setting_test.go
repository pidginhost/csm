package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// With auto_response.suspend_mailboxes off, every finding and incident is
// still raised but no mailbox is suspended, by evidence or by sending abuse.
func TestSuspendMailboxesOffSuspendsNothing(t *testing.T) {
	db, calls := evidenceCase(t)
	holds := stubAccountHold(t, true)
	cfg := eximAutoHoldConfig()
	off := false
	cfg.AutoResponse.SuspendMailboxes = &off

	observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", time.Now()))
	f := onlyIncident(t, stolenLoginResponses(cfg, []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}))
	if !strings.HasPrefix(f.Message, "Would suspend mailbox real@victim.example") || !strings.Contains(f.Details, "suspend_mailboxes") {
		t.Fatalf("incident = %+v, want a would-suspend naming the setting", f)
	}
	if stopped := respondToCompromise(cfg, sendingCompromise("real@victim.example", time.Now())); stopped {
		t.Fatal("sending abuse suspended a mailbox with suspension off")
	}
	if len(*calls) != 0 || len(*holds) != 0 {
		t.Fatalf("uapi %v, holds %v; want nothing with suspension off", *calls, *holds)
	}
	if rows, err := db.ListMailboxSuspensions(); err != nil || len(rows) != 0 {
		t.Fatalf("rows = %+v (err %v), want none", rows, err)
	}
	// An account-wide outgoing hold for a domain is not a mailbox suspension.
	if stopped := respondToCompromise(cfg, sendingCompromise("victim.example", time.Now())); !stopped || len(*holds) != 1 {
		t.Fatalf("stopped = %v, holds = %v; the domain hold must still apply", stopped, *holds)
	}
}
