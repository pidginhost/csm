package admissionowner

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// sshFinding is a finding the sshd log reader stamped with its observation.
func sshFinding(at time.Time, cursor string, sev alert.Severity) alert.Finding {
	return alert.Finding{
		Check: "ssh_brute", Severity: sev, SourceIP: "192.0.2.10", Message: "brute force", Timestamp: at,
		Observation: alert.Observation{Producer: "sshd_log", Stream: "secure:dev=1,ino=2", Cursor: cursor, ObservedAt: at},
	}
}

func respondOptions(f *ownerFixture) Options {
	opts := previewOptions(f)
	opts.Caps = func() admission.Caps { return admission.Caps{} }
	return opts
}

// A funnel hands the owner a finding and the target it acts on: the owner
// mints the evidence the finding's observation supports with the producer
// that stamped it and hands the response to its ingress (spec 5.1, 5.5).
func TestOwnerMintsAndAnswersAFinding(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	finding := sshFinding(f.host.now(), "offset=1", alert.High)
	e, err := o.Mint(finding, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindBlockIP, e, 0); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 || queued[0].Roots[0] != e.ID() || queued[0].Check != "ssh_brute" || queued[0].FindingID != alert.FindingID(finding) || queued[0].Entry != admission.EntryScan {
		t.Fatalf("queued = %+v", queued)
	}
}

// A response the owner cannot mint is refused visibly: counted with its
// reason, and as a Critical loss when Critical. Minting alone counts
// nothing, since a path may mint a root it never answers.
func TestOwnerCountsAResponseItCannotMint(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	finding := sshFinding(f.host.now(), "offset=1", alert.Critical)
	finding.Observation = alert.Observation{}
	_, err := o.Mint(finding, "192.0.2.10")
	if err == nil {
		t.Fatal("a finding without an observation was minted")
	}
	key := admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonAttribution}
	if st := o.ingress.Stats(); st.Counters.Count(key) != 0 || st.CriticalLost != 0 {
		t.Fatalf("minting counted: %+v", st)
	}
	o.Refuse(admission.KindBlockIP, finding, 0, err)
	if st := o.ingress.Stats(); st.Counters.Count(key) != 1 || st.CriticalLost != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

// A derived entry answers a root the owner minted earlier as its own
// response: the candidate carries that entry, and a derived path with no
// root left is refused visibly.
func TestOwnerAnswersARootThroughADerivedEntry(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	e, err := o.Mint(sshFinding(f.host.now(), "offset=1", alert.High), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindBlockIP, e, admission.EntryIncident); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if queued := queuedCandidates(t, o); len(queued) != 1 || queued[0].Entry != admission.EntryIncident {
		t.Fatalf("queued = %+v", queued)
	}
	if err = o.Respond(admission.KindBlockIP, admission.Evidence{}, admission.EntryIncident); err == nil {
		t.Fatal("a derived response without its root was accepted")
	}
	if n := o.ingress.Stats().Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonPolicy}); n != 1 {
		t.Fatalf("policy refusals = %d", n)
	}
}

// A derived path re-mints the root of a finding the owner already stored.
// When the inventory recreated the finding's account between the two
// mints, the re-mint names another owner generation: the response is
// refused as a stale identity, not counted as an invalid record.
func TestOwnerCountsADerivedRemintAfterAnInventoryChangeAsAStaleIdentity(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := f.start(opts)
	finding := sshFinding(f.host.now(), "offset=1", alert.High)
	finding.Claims = []admission.Claim{{Kind: admission.ClaimAccount, Value: "alice"}}
	primary, err := o.Mint(finding, finding.SourceIP)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindBlockIP, primary, 0); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	f.host.set(func(h *fakeHost) { h.inv.Incarnations = map[string]string{"alice": "startdate:2"} })
	if err = o.do(func() error { o.refreshInventory(); return o.inventoryErr }); err != nil {
		t.Fatal(err)
	}
	root, err := o.Mint(finding, finding.SourceIP)
	if err != nil {
		t.Fatal(err)
	}
	if root.ID() != primary.ID() || root.Owner().IsHost() || root.Owner() == primary.Owner() {
		t.Fatalf("fixture does not remint the root under the recreated account: %s then %s", primary.Owner().Key(), root.Owner().Key())
	}
	if err = o.Respond(admission.KindBlockIP, root, admission.EntryIncident); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if err = o.do(func() error { o.writeComparison(true); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"2026-10-04T13:00:00Z block_ip unknown incident refused stale_identity 1",
		"2026-10-04T13:00:00Z block_ip unknown scan queued  1",
	}
	if got := sink.previews(); !equalStrings(got, want) {
		t.Fatalf("rows = %q, want %q", got, want)
	}
}

// Handoff O30 and review M4: a stop closes the ingress before its final
// drains, so it ends even while a producer that was not stopped keeps
// submitting; later submissions are refused.
func TestOwnerStopIsBoundedWhileAProducerSubmits(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	quit, stopped, producerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() { close(quit); <-producerDone }()
	go func() {
		defer close(producerDone)
		for i := 0; ; i++ {
			select {
			case <-quit:
				return
			default:
			}
			e, err := o.Mint(sshFinding(f.host.now(), "offset="+time.Duration(i).String(), alert.High), "192.0.2.10")
			if err == nil {
				_ = o.Respond(admission.KindBlockIP, e, 0)
			}
		}
	}()
	go func() { o.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not end while a producer kept submitting")
	}
	e, err := o.Mint(sshFinding(f.host.now(), "offset=last", alert.High), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindBlockIP, e, 0); err == nil {
		t.Fatal("a stopped owner accepted a response")
	}
}

// A producer still running while the owner stops cannot keep the final
// drains going: once the stop begins, every submission is refused, however
// many groups the stop drains.
func TestOwnerStopRefusesWorkSubmittedDuringItsDrain(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	e, err := o.Mint(sshFinding(f.host.now(), "offset=held", alert.High), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindBlockIP, e, 0); err != nil {
		t.Fatal(err)
	}
	var late, accepted int
	prev := drainGroupOf
	setOwnerHook(t, o, &drainGroupOf, func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		if o.stopping.Load() {
			late++
			if e, mintErr := o.Mint(sshFinding(f.host.now(), fmt.Sprintf("offset=late-%d", late), alert.High), "192.0.2.10"); mintErr == nil && o.Respond(admission.KindBlockIP, e, 0) == nil {
				accepted++
			}
		}
		return prev(in, l, items)
	})
	stopped := make(chan struct{})
	go func() { o.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the stop kept draining work submitted during it")
	}
	if late == 0 || accepted != 0 {
		t.Fatalf("%d submissions during the stop, %d accepted", late, accepted)
	}
}

// Evidence is independent of the response kind. The firewall's family
// capability applies to blocks when they are handed over, not to minting.
func TestOwnerAnswersOnlyBlocksTheFirewallContains(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	finding := sshFinding(f.host.now(), "offset=1", alert.High)
	finding.SourceIP = "2001:db8::10"
	root, err := o.Mint(finding, finding.SourceIP)
	if err != nil {
		t.Fatal(err)
	}
	err = o.Respond(admission.KindBlockIP, root, 0)
	if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonUnsupportedContainment {
		t.Fatalf("IPv6 without the capability: %v", err)
	}
	if stats := o.ingress.Stats(); stats.Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonUnsupportedContainment}) != 1 || o.ingress.Len() != 0 {
		t.Fatalf("unsupported block was not counted: %+v", stats)
	}
}

// HTTP and PHP challenges accept IPv6 independently of nft containment.
// A timeout answers the same root, but its block still needs that family.
func TestOwnerPreviewsAnIPv6ChallengeWithoutFirewallIPv6(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	finding := sshFinding(f.host.now(), "offset=1", alert.High)
	finding.SourceIP = "2001:db8::10"
	root, err := o.Mint(finding, finding.SourceIP)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindChallenge, root, 0); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 || queued[0].Key.Kind != admission.KindChallenge || queued[0].Roots[0] != root.ID() {
		t.Fatalf("challenge queue = %+v", queued)
	}
	if err = o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if remaining := queuedCandidates(t, o); len(remaining) != 0 {
		t.Fatalf("challenge was not observed: %+v", remaining)
	}
	id, err := queued[0].ID()
	if err != nil {
		t.Fatal(err)
	}
	if err = o.do(func() error {
		candidate, candidateErr := o.ledger.Candidate(id)
		if candidateErr != nil {
			return candidateErr
		}
		if candidate.State != admission.StateObserved || candidate.Disposition != admission.DispositionObserve {
			t.Errorf("challenge outcome = %+v", candidate)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err = o.Respond(admission.KindBlockIP, root, admission.EntryChallengeTimeout)
	if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonUnsupportedContainment {
		t.Fatalf("IPv6 timeout block without containment: %v", err)
	}
	if stats := o.ingress.Stats(); stats.Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonUnsupportedContainment}) != 1 || o.ingress.Len() != 0 {
		t.Fatalf("timeout refusal = %+v", stats)
	}
}

// R7: a derived path that kept no root (a netblock, a permanent block, an
// incident's last rung) hands over no evidence and is refused as policy, a
// designed refusal, never as invalid input.
func TestOwnerRefusesARootlessDerivedResponseAsPolicy(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	for via, kind := range map[admission.Entry]admission.Kind{
		admission.EntryNetblock: admission.KindBlockSubnet, admission.EntryPermblock: admission.KindBlockIP, admission.EntryIncident: admission.KindBlockIP,
	} {
		err := o.Respond(kind, admission.Evidence{}, via)
		if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonPolicy {
			t.Errorf("via %s: err = %v", via, err)
		}
	}
	key := admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonPolicy}
	if st := o.ingress.Stats(); st.Counters.Count(key) != 3 {
		t.Fatalf("stats = %+v", st)
	}
}

// A derived response retains its selected lifetime in durable queue state.
// Restarting with a different default still previews that lifetime; an
// ordinary submission with no selected lifetime uses the current default.
func TestOwnerPreviewKeepsASelectedLifetimeAcrossRestart(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := respondOptions(f)
	opts.ScheduleEvery = time.Hour
	o := f.start(opts)
	e, err := o.Mint(sshFinding(f.host.now(), "offset=selected", alert.High), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Respond(admission.KindBlockIP, e, admission.EntryIncident, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 || queued[0].PreviewTTL != 7*24*time.Hour {
		t.Fatalf("queued lifetime = %+v", queued)
	}
	o.Stop()
	opts.Expiry = func(admission.Candidate) time.Duration { return time.Hour }
	restarted := f.start(opts)
	queued = queuedCandidates(t, restarted)
	if len(queued) != 1 || queued[0].PreviewTTL != 7*24*time.Hour {
		t.Fatalf("restarted lifetime = %+v", queued)
	}
	finding := sshFinding(f.host.now(), "offset=default", alert.High)
	finding.SourceIP = "192.0.2.11"
	ordinary, err := restarted.Mint(finding, finding.SourceIP)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Respond(admission.KindBlockIP, ordinary, 0); err != nil {
		t.Fatal(err)
	}
	if err = restarted.do(restarted.drain); err != nil {
		t.Fatal(err)
	}
	if err = restarted.do(restarted.preview); err != nil {
		t.Fatal(err)
	}
	rows := pendingAudit(t, restarted)
	if len(rows) != 4 {
		t.Fatalf("audit rows = %d, want two previews", len(rows))
	}
	for _, row := range rows {
		duration := time.Hour
		if row.Target == e.Target() {
			duration = 7 * 24 * time.Hour
		}
		if !row.ExpiresAt.Equal(f.host.now().Add(duration)) {
			t.Fatalf("target %s expiry = %v, want %v", row.Target.Key(), row.ExpiresAt, f.host.now().Add(duration))
		}
	}
}

// Invalid selected lifetimes are counted refusals, never queue entries.
func TestOwnerRefusesMalformedSelectedLifetimes(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	e, err := o.Mint(sshFinding(f.host.now(), "offset=bad-ttl", alert.High), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	for _, ttls := range [][]time.Duration{{-time.Second}, {time.Hour, time.Hour}} {
		err = o.Respond(admission.KindBlockIP, e, admission.EntryIncident, ttls...)
		if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonInvalid {
			t.Fatalf("lifetimes %v: %v", ttls, err)
		}
	}
	if st := o.ingress.Stats(); o.ingress.Len() != 0 || st.Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonInvalid}) != 2 {
		t.Fatalf("held %d, stats %+v", o.ingress.Len(), st)
	}
}

// Holding the owner goroutine cannot delay a funnel's memory handoff:
// minting and submission complete while the owner remains blocked.
func TestOwnerHandoffDoesNotWaitForTheOwner(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(respondOptions(f))
	entered, release, ownerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		_ = o.do(func() error { close(entered); <-release; return nil })
		close(ownerDone)
	}()
	<-entered
	t.Cleanup(func() { close(release); <-ownerDone })
	returned := make(chan error, 1)
	go func() {
		e, err := o.Mint(sshFinding(f.host.now(), "offset=nonblocking", alert.High), "192.0.2.10")
		if err == nil {
			err = o.Respond(admission.KindBlockIP, e, 0)
		}
		returned <- err
	}()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff waited for the blocked owner")
	}
	if o.ingress.Len() != 1 || o.ingress.Stats().Accepted != 1 {
		t.Fatalf("held %d, accepted %d", o.ingress.Len(), o.ingress.Stats().Accepted)
	}
}
