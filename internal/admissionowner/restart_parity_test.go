package admissionowner

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// The incident correlator reads its selectors once, when the process
// starts. An incident or spray block queued by an earlier process may no
// longer be one this process selects, so an owner with an engine ends it
// as disabled when it starts, in dry run too; a scan block queued beside
// it waits for its turn. An owner without an engine leaves the queue as
// it was.
func TestOwnerStartEndsIncidentBlocksQueuedBeforeIt(t *testing.T) {
	for _, mode := range []string{"no engine", "dry run", "live"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			start := func() *Owner {
				switch mode {
				case "no engine":
					return f.start(previewOptions(f))
				case "dry run":
					o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
					return o
				}
				o, _, _ := policyOwner(t, f, blocks, validPolicy(1))
				return o
			}
			o := start()
			through := func(addr string, via admission.Entry) admission.CandidateID {
				target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
				if err != nil {
					t.Fatal(err)
				}
				id, _ := queuedThrough(t, o, p, f.host, admission.SeverityCritical, addr, admission.KindBlockIP, target, via)
				return id
			}
			scan := through("192.0.2.10", 0)
			incident := through("192.0.2.11", admission.EntryIncident)
			spray := through("192.0.2.12", admission.EntryIncidentSpray)
			o.Stop()
			o = start()
			if c := candidate(t, o, scan); c.State != admission.StateQueued {
				t.Fatalf("scan block after restart = %s/%s, want queued", c.State, c.Reason)
			}
			want := mode != "no engine"
			for name, id := range map[string]admission.CandidateID{"incident": incident, "spray": spray} {
				c := candidate(t, o, id)
				ended := c.State == admission.StateRefused && c.Reason == admission.ReasonDisabled && c.Attempts == 0
				if ended != want {
					t.Errorf("%s block after restart = %s/%s, ended %v, want ended %v", name, c.State, c.Reason, ended, want)
				}
				if !want && (c.State != admission.StateQueued || c.Reason != 0 || c.Attempts != 0) {
					t.Errorf("an owner without an engine changed the %s block: %+v", name, c)
				}
			}
		})
	}
}

// An owner without an engine provider never executes blocks, whatever its
// last policy reading recorded.
func TestOwnerWithoutAnEngineProviderExecutesNoBlocks(t *testing.T) {
	o := &Owner{}
	o.executesBlocks.Store(true)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ExecutesBlocks without an engine provider panicked: %v", r)
		}
	}()
	if o.ExecutesBlocks() {
		t.Fatal("an owner without an engine provider executes blocks")
	}
}

// queueEarlier queues a scan, an incident and a spray block on o, as an
// earlier process would leave them, and returns their ids in that order.
func queueEarlier(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture) [3]admission.CandidateID {
	t.Helper()
	var ids [3]admission.CandidateID
	for i, via := range []admission.Entry{0, admission.EntryIncident, admission.EntryIncidentSpray} {
		addr := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}[i]
		target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
		if err != nil {
			t.Fatal(err)
		}
		ids[i], _ = queuedThrough(t, o, p, f.host, admission.SeverityCritical, addr, admission.KindBlockIP, target, via)
	}
	return ids
}

// A failed start is retried on the same handle, and no new work can enter
// between the sweep and the retry: the ingress admits nothing until the
// start completes. The retry ends each earlier incident block once, and
// work that arrives after the start is never swept as earlier work.
func TestOwnerStartRetryKeepsIngressClosed(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	first, _, _ := policyOwner(t, f, blocks, validPolicy(1))
	ids := queueEarlier(t, first, p, f)
	before := [3]admission.Candidate{candidate(t, first, ids[0]), candidate(t, first, ids[1]), candidate(t, first, ids[2])}
	first.Stop()
	previous := readSnapshot
	failed := false
	readSnapshot = func(l *store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		if !failed {
			failed = true
			return nil, errors.New("snapshot unavailable")
		}
		return previous(l)
	}
	// Restored after the owner below stops: cleanups run last first.
	t.Cleanup(func() { readSnapshot = previous })
	o, _, _ := policyOwner(t, f, blocks, validPolicy(1))
	var handle *store.AdmissionLedger
	if err := o.do(func() error {
		if o.started || o.ingress.Health().Admitting || !failed {
			return errors.New("the failed start admits work")
		}
		handle = o.ledger
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	root, err := o.Mint(sshFinding(f.host.now(), "offset=retry-new", alert.Critical))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Respond(admission.KindBlockIP, targetOf(root), root, admission.EntryIncident); err == nil {
		t.Fatal("an owner whose start failed accepted an incident block")
	}
	if err := o.do(func() error {
		o.startErr = o.start()
		if o.startErr != nil {
			return o.startErr
		}
		if !o.started || o.ledger != handle {
			return errors.New("the retry did not start on the same handle")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, ids[0]); c.State != admission.StateQueued {
		t.Fatalf("earlier scan block = %s/%s, want queued", c.State, c.Reason)
	}
	for i := 1; i < 3; i++ {
		c := candidate(t, o, ids[i])
		if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Transitions != before[i].Transitions+1 || c.Attempts != 0 {
			t.Fatalf("earlier block %d = %+v, want one disabled ending", i, c)
		}
	}
	if used := liveUsed(t, o); used != 0 {
		t.Fatalf("the restart charged %d units", used)
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("the restart applied %d blocks", len(applies))
	}
	incident, _ := queuedThrough(t, o, p, f.host, admission.SeverityCritical, "192.0.2.14", admission.KindBlockIP, mustTarget(t, "192.0.2.14"), admission.EntryIncident)
	spray, _ := queuedThrough(t, o, p, f.host, admission.SeverityCritical, "192.0.2.15", admission.KindBlockIP, mustTarget(t, "192.0.2.15"), admission.EntryIncidentSpray)
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []admission.CandidateID{incident, spray} {
		if c := candidate(t, o, id); c.Reason == admission.ReasonDisabled {
			t.Fatalf("work queued after the start was swept as earlier work: %+v", c)
		}
	}
}

func mustTarget(t *testing.T, addr string) admission.Target {
	t.Helper()
	target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// Only an owner that may run blocks sweeps earlier incident work: a valid
// dry-run policy does (it follows the same opt-out gate as the rest of the
// queue), an owner without an engine provider or with a refused policy
// does not.
func TestOwnerStartIncidentSweepControls(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(t *testing.T, f *ownerFixture, blocks *fakeBlocks) *Owner
		ended bool
	}{
		{"dry-run policy", func(t *testing.T, f *ownerFixture, blocks *fakeBlocks) *Owner {
			dry := validPolicy(1)
			dry.DryRun = true
			o, _, _ := policyOwner(t, f, blocks, dry)
			return o
		}, true},
		{"no engine provider", func(t *testing.T, f *ownerFixture, _ *fakeBlocks) *Owner {
			return f.start(f.options())
		}, false},
		{"refused policy", func(t *testing.T, f *ownerFixture, blocks *fakeBlocks) *Owner {
			bad := validPolicy(1)
			bad.BlockExpiry = 0
			opts := executeOptions(f, blocks)
			opts.Policy = (&policyReader{p: bad}).read
			o := f.start(opts)
			o.Stop()
			// Read the queue through an owner that never sweeps.
			return f.start(f.options())
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			first, _, _ := policyOwner(t, f, blocks, validPolicy(1))
			ids := queueEarlier(t, first, p, f)
			first.Stop()
			o := tc.start(t, f, blocks)
			for i := 1; i < 3; i++ {
				c := candidate(t, o, ids[i])
				ended := c.State == admission.StateRefused && c.Reason == admission.ReasonDisabled
				if ended != tc.ended {
					t.Fatalf("earlier block %d = %s/%s, ended %v, want %v", i, c.State, c.Reason, ended, tc.ended)
				}
			}
		})
	}
}
