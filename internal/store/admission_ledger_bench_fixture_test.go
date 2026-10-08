package store

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// A bounded sample checks the synthetic records under race detection.
// The benchmark gate separately checks the full allowances and rings.
func TestAdmissionLedgerFullHistoryFixtureRecords(t *testing.T) {
	f := historyFixture(t, false, 1)
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("history fixture open: %v", err)
	}
	s := f.storageState()
	if s.General.Used == 0 || s.General.Used > admission.MaxHistoryBytes ||
		s.Reserved.Used == 0 || s.Reserved.Used > admission.MaxHistoryBytes ||
		s.Ended.Count != 1 || s.Loose.Count != 1 {
		t.Fatalf("sample allowances and rings: %+v", s)
	}
	u := f.l.Status().Unresolved
	intents := f.intents()
	if u.Error != "" || u.Running != 0 || u.Unknown != 1 || s.AuditSlots != 1 || len(intents) != 1 {
		t.Fatalf("sample recovery: %+v, slots %d, intents %d", u, s.AuditSlots, len(intents))
	}
	for id := range intents {
		a, err := f.l.Attempt(id)
		if err != nil {
			t.Fatal(err)
		}
		h, found := f.historyEntry(a.Attempt.Candidate)
		if !found || !h.Pinned || s.Recovery != uint64(h.General)+uint64(h.Reserved)+admission.MaxIntentBytes {
			t.Fatalf("sample recovery bytes: %+v %+v", s, h)
		}
	}
}

func (f *ledgerFixture) assertFullHistoryFixture(withOutbox bool) {
	f.t.Helper()
	s := f.storageState()
	general, reserved := admission.HistoryLanes()
	used := s.Recovery + s.OutboxBytes()
	slack := uint64(admission.MaxHistoryBytes + admission.UnknownHoldBytes)
	if withOutbox {
		// The audit fixture writes complete groups of outcome rows.
		slack += (admission.AuditStepsPerAttempt - 1) * admission.AuditSlotBytes
	}
	if s.General.Used > general || general-s.General.Used >= admission.MaxHistoryBytes ||
		s.Reserved.Used > reserved || reserved-s.Reserved.Used >= admission.MaxHistoryBytes ||
		used > admission.RecoveryReserveBytes || admission.RecoveryReserveBytes-used >= slack ||
		s.Ended.Count != admission.MaxEndedCandidates || s.Loose.Count != admission.MaxLooseEvidence {
		f.t.Fatalf("full-history allowances and rings: %+v", s)
	}
	u := f.l.Status().Unresolved
	if u.Error != "" || u.Running != 0 || u.Unknown == 0 || len(f.intents()) != u.Unknown ||
		(!withOutbox && s.AuditSlots != uint64(u.Unknown)) || (withOutbox && s.AuditSlots < uint64(u.Unknown)) {
		f.t.Fatalf("full-history recovery: %+v, slots %d", u, s.AuditSlots)
	}
}
