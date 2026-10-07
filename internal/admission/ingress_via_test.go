package admission

import (
	"errors"
	"testing"
	"time"
)

// One observation can ask for several responses: a challenge and later the
// block of its timeout, or the scan's block and central intel's. Each
// response kind and entry is its own held item; only an equal one merges.
func TestIngressHoldsOneItemPerKindAndEntry(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	block := f.sub(subSpec{})
	challenge, viaIncident := block, block
	challenge.Kind = KindChallenge
	viaIncident.Via = EntryIncident
	for _, s := range []Submission{block, challenge, viaIncident, block} {
		if err := f.in.Submit(s); err != nil {
			t.Fatal(err)
		}
	}
	if f.in.Len() != 3 || f.in.Stats().Duplicates != 1 {
		t.Fatalf("held %d, duplicates %d", f.in.Len(), f.in.Stats().Duplicates)
	}
	taken := f.in.Take(3)
	if taken[2].Submission.Via != EntryIncident || taken[0].Submission.Via != 0 || taken[1].Submission.Kind != KindChallenge {
		t.Fatalf("taken = %+v", taken)
	}
}

func TestIngressCoalescesImplicitAndExplicitRootEntries(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	first := f.sub(subSpec{})
	if err := f.in.Submit(first); err != nil {
		t.Fatal(err)
	}
	explicit := first
	explicit.Via = first.Evidence.Entry()
	if err := f.in.Submit(explicit); err != nil {
		t.Fatal(err)
	}
	if f.in.Len() != 1 || f.in.Stats().Accepted != 1 || f.in.Stats().Duplicates != 1 {
		t.Fatalf("held %d, stats %+v", f.in.Len(), f.in.Stats())
	}
	taken := f.in.Take(1)
	snap := *f.in.snap
	snap.Revision = f.rev + 1
	f.in.Complete(taken, snap.Revision, &snap)
	if err := f.in.Submit(explicit); err != nil {
		t.Fatal(err)
	}
	if f.in.Len() != 1 || f.in.Stats().Accepted != 2 || f.in.Stats().Duplicates != 1 {
		t.Fatalf("after acknowledgement: held %d, stats %+v", f.in.Len(), f.in.Stats())
	}
}

// A derived entry carries the root it answers; the registry binds it to a
// producer of that entry that wraps the root's check, so a caller cannot
// name an entry the check was never registered for.
func TestIngressBindsADerivedEntryToItsProducer(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	for name, via := range map[string]Entry{"unregistered entry": EntryCentral, "invalid entry": entryEnd} {
		s := f.sub(subSpec{})
		s.Via = via
		wantReason(t, name, f.in.Submit(s), ReasonPolicy)
	}
	wrapped := f.sub(subSpec{p: f.tp.mail, check: "mail_brute"})
	wrapped.Via = EntryIncident
	wantReason(t, "a check the entry does not wrap", f.in.Submit(wrapped), ReasonPolicy)
	if n := f.in.Stats().Counters.Count(CountKey{Event: EventRefused, Reason: ReasonPolicy}); n != 3 {
		t.Fatalf("policy refusals = %d", n)
	}
}

// A response whose evidence could not be minted is refused visibly: it is
// counted as a refusal of its reason, unassessed, and a Critical one is a
// Critical loss.
func TestIngressCountsAResponseThatCouldNotBeMinted(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	before := f.in.Checkpoint().Sequence
	f.in.Refuse(refuse(ReasonInvalid, "finding has no observation"), SeverityCritical)
	f.in.Refuse(errors.New("not an admission refusal"), SeverityHigh)
	st := f.in.Stats()
	if st.Counters.Count(CountKey{Event: EventRefused, Reason: ReasonInvalid}) != 2 || st.CriticalLost != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if got := f.in.Checkpoint().Sequence; got != before+2 {
		t.Fatalf("sequence %d, want %d", got, before+2)
	}
}

func TestIngressCountsUnmintedCriticalResponsesWhileStopped(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	f.in.Refuse(refuse(ReasonAttribution, "finding has no observation"), SeverityCritical)
	if h := f.in.Health(); h.CriticalRefused != 0 {
		t.Fatalf("open ingress health = %+v", h)
	}
	f.in.Publish(nil)
	stopped := f.in.Health().StoppedSince
	f.in.Refuse(refuse(ReasonAttribution, "finding has no observation"), SeverityCritical)
	f.in.Refuse(refuse(ReasonPolicy, "no retained root"), SeverityHigh)
	if h := f.in.Health(); h.Admitting || h.CriticalRefused != 1 || !h.StoppedSince.Equal(stopped) {
		t.Fatalf("stopped ingress health = %+v", h)
	}
	f.publish()
	if h := f.in.Health(); h != (IngressHealth{Admitting: true}) {
		t.Fatalf("recovered ingress health = %+v", h)
	}
}

// Incident escalation can answer the same attesting root with a longer
// lifetime before a drain. Valid later selections coalesce while the first
// selected lifetime stays fixed; a negative lifetime is still invalid.
func TestIngressCoalescesSelectedLifetimesAndRefusesNegative(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	s := f.sub(subSpec{target: "192.0.2.10", cursor: "incident-root"})
	s.Via, s.PreviewTTL = EntryIncident, time.Hour
	if err := f.in.Submit(s); err != nil {
		t.Fatal(err)
	}
	for i, duration := range []time.Duration{7 * 24 * time.Hour, 30 * time.Minute} {
		changed := f.sub(subSpec{target: "192.0.2.10", cursor: "incident-root", finding: []string{"1111111111111111", "2222222222222222"}[i]})
		changed.Via, changed.PreviewTTL = EntryIncident, duration
		if changed.Evidence.ID() != s.Evidence.ID() {
			t.Fatal("later report changed the attesting root")
		}
		if err := f.in.Submit(changed); err != nil {
			t.Fatalf("valid later lifetime %v: %v", duration, err)
		}
	}
	if f.in.Len() != 1 || f.in.Stats().Duplicates != 2 || f.in.Stats().Counters.Count(CountKey{Event: EventRefused, Reason: ReasonInvalid}) != 0 {
		t.Fatalf("held %d, stats %+v", f.in.Len(), f.in.Stats())
	}
	taken := f.in.Take(1)
	if len(taken) != 1 || taken[0].Submission.PreviewTTL != s.PreviewTTL || len(taken[0].Reports) != 2 {
		t.Fatalf("taken = %+v", taken)
	}
	negative := s
	negative.PreviewTTL = -time.Second
	wantReason(t, "negative lifetime", f.in.Submit(negative), ReasonInvalid)
	if f.in.Len() != 1 || f.in.Stats().Duplicates != 2 || f.in.Stats().Counters.Count(CountKey{Event: EventRefused, Reason: ReasonInvalid}) != 1 || f.held(s).item.Submission.PreviewTTL != s.PreviewTTL {
		t.Fatalf("negative lifetime changed held work: %d, stats %+v", f.in.Len(), f.in.Stats())
	}
}

// A closed ingress refuses every later submission and no snapshot reopens
// it, so a stop drains a bounded set of held work even while a producer
// still submits; what it holds can still be taken and completed.
func TestIngressStaysClosedOnceClosed(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	held := f.sub(subSpec{})
	if err := f.in.Submit(held); err != nil {
		t.Fatal(err)
	}
	f.in.Close()
	wantReason(t, "after close", f.in.Submit(f.sub(subSpec{sev: SeverityCritical})), ReasonEngineUnavailable)
	f.publish()
	if f.in.Health().Admitting {
		t.Fatal("a snapshot reopened a closed ingress")
	}
	taken := f.in.Take(5)
	if len(taken) != 1 || !taken[0].Submission.Evidence.Equal(held.Evidence) {
		t.Fatalf("taken = %+v", taken)
	}
	f.in.Complete(taken, f.rev+1, f.in.snap)
	if f.in.Len() != 0 || f.in.Health().Admitting {
		t.Fatalf("after completion: %d held, admitting %v", f.in.Len(), f.in.Health().Admitting)
	}
}
