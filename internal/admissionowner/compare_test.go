package admissionowner

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// actionSink captures the owner's durable action log writes.
type actionSink struct {
	mu   sync.Mutex
	recs []actionlog.Record
	fail error
}

func (s *actionSink) write(rs []actionlog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.recs = append(s.recs, rs...)
	return nil
}

func (s *actionSink) previews() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.recs {
		switch {
		case r.Count == 0:
		case r.Op != "respond.block_ip" || r.Target != "" || r.FindingID != "" || r.ActionID != "":
			out = append(out, "malformed summary "+r.Op+" "+r.Target)
		default:
			out = append(out, r.Timestamp.UTC().Format(time.RFC3339)+" "+r.Action+" "+r.Reason+" "+r.ActorDetail+" "+string(r.Result)+" "+r.Error+" "+strconv.FormatUint(r.Count, 10))
		}
	}
	sort.Strings(out)
	return out
}

// Ruling R11: the owner counts every decision the new path makes on a
// response by entry, check and kind, and writes one row per count each
// hour to the action log, so the operator can set them against
// the legacy path's actions.
func TestOwnerWritesHourlyDecisionCounts(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	previousNow := deliveryNow
	deliveryNow = f.host.now
	t.Cleanup(func() { deliveryNow = previousNow })
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := f.start(opts)
	for _, cursor := range []string{"offset=1", "offset=2"} {
		e, err := o.Mint(sshFinding(f.host.now(), cursor, alert.High), "192.0.2.10")
		if err != nil {
			t.Fatal(err)
		}
		if err = o.Respond(admission.KindBlockIP, e, 0); err != nil {
			t.Fatal(err)
		}
	}
	bad := sshFinding(f.host.now(), "offset=3", alert.Critical)
	bad.Observation = alert.Observation{}
	_, err := o.Mint(bad, "192.0.2.11")
	o.Refuse(admission.KindBlockIP, bad, admission.EntryIncident, err)
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if err = o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := sink.previews(); len(got) != 0 {
		t.Fatalf("counts written before the hour ended: %v", got)
	}
	f.host.advance(time.Hour)
	if err = o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"2026-10-04T13:00:00Z block_ip unknown incident refused attribution 1",
		"2026-10-04T13:00:00Z block_ip unknown scan coalesced  1",
		"2026-10-04T13:00:00Z block_ip unknown scan observe  1",
		"2026-10-04T13:00:00Z block_ip unknown scan queued  1",
	}
	if got := sink.previews(); !equalStrings(got, want) {
		t.Fatalf("rows = %q, want %q", got, want)
	}
}

// A failed write keeps the counts for the next tick, and a clean stop writes
// the hour in progress.
func TestOwnerKeepsDecisionCountsUntilWritten(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	previousNow := deliveryNow
	deliveryNow = f.host.now
	t.Cleanup(func() { deliveryNow = previousNow })
	sink := &actionSink{fail: errors.New("disk full")}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := Start(opts)
	bad := sshFinding(f.host.now(), "offset=1", alert.High)
	bad.Observation = alert.Observation{}
	_, mintErr := o.Mint(bad, "192.0.2.11")
	o.Refuse(admission.KindChallenge, bad, 0, mintErr)
	f.host.advance(time.Hour)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	sink.fail = nil
	sink.mu.Unlock()
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if got := sink.previews(); len(got) != 1 || got[0] != "2026-10-04T13:00:00Z challenge unknown scan refused attribution 1" {
		t.Fatalf("rows after a failed write = %q", got)
	}
	o.Refuse(admission.KindChallenge, bad, 0, mintErr)
	o.Stop()
	if got := sink.previews(); len(got) != 2 || got[1] != "2026-10-04T14:00:00Z challenge unknown scan refused attribution 1" {
		t.Fatalf("rows after a stop = %q", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A funnel can cross the hour before the owner ticks. Those decisions
// belong to their new hour, and malformed checks share one fixed key.
func TestDecisionCountsRollBeforeTheOwnerTick(t *testing.T) {
	var c comparison
	at := time.Date(2026, 9, 8, 10, 59, 59, 0, time.UTC)
	key := compareKey{entry: admission.EntryScan, check: "pam_bruteforce", kind: admission.KindBlockIP, decision: decisionRefused, reason: admission.ReasonAttribution}
	c.addAt(key, at)
	c.addAt(key, at.Add(time.Second))
	rows, through := c.take(at.Add(time.Second), false)
	if len(rows) != 1 || rows[0].Count != 1 || rows[0].Timestamp != at.Truncate(time.Hour).Add(time.Hour) || rows[0].Reason != "pam_bruteforce" {
		t.Fatalf("closed hour = %+v", rows)
	}
	c.written(through)
	for _, check := range []string{"", "not_registered", "other_unregistered"} {
		key.check = check
		c.addAt(key, at.Add(time.Second))
	}
	rows, _ = c.take(at.Add(2*time.Second), true)
	if len(rows) != 2 {
		t.Fatalf("unbounded or missing check keys: %+v", rows)
	}
	counts := map[string]uint64{}
	for _, r := range rows {
		counts[r.Reason] = r.Count
	}
	if counts["pam_bruteforce"] != 1 || counts["unknown"] != 3 {
		t.Fatalf("new hour counts = %v", counts)
	}
}

func TestDecisionCountsRetainTheNewestBoundedRows(t *testing.T) {
	var c comparison
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	key := compareKey{entry: admission.EntryScan, check: "pam_bruteforce", kind: admission.KindBlockIP, decision: decisionQueued}
	for i := range maxUnwrittenRows + 2 {
		c.addAt(key, at.Add(time.Duration(i)*time.Hour))
	}
	rows, _ := c.take(at.Add(time.Duration(maxUnwrittenRows+2)*time.Hour), true)
	if len(rows) != maxUnwrittenRows || rows[0].Timestamp != at.Add(3*time.Hour) || rows[len(rows)-1].Timestamp != at.Add(time.Duration(maxUnwrittenRows+2)*time.Hour) {
		t.Fatalf("retention: %d rows, first %v, last %v", len(rows), rows[0].Timestamp, rows[len(rows)-1].Timestamp)
	}
	// Closing an older ledger hour after a wall-time refusal cannot evict
	// the newer rows simply because it was appended last.
	c.start = at
	c.counts = map[compareKey]uint64{key: 1}
	rows, _ = c.take(at, true)
	if len(rows) != maxUnwrittenRows || rows[0].Timestamp != at.Add(3*time.Hour) {
		t.Fatalf("backdated batch displaced newer rows: %d %v", len(rows), rows[0].Timestamp)
	}
}

func TestDecisionCountsIncludeIsolatedCorruptArrivals(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &actionSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	bad, err := admission.CanonicalAddress("192.0.2.66", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	previousDrain := drainGroupOf
	t.Cleanup(func() { drainGroupOf = previousDrain })
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		return in.DrainTaken(&damagedTargetLedger{Ledger: l, bad: bad}, items, arrivalRequest)
	}
	for i := range 2 {
		submitObservation(t, o, p, "192.0.2.66", fmt.Sprintf("offset=%d", i+1), f.host.now())
		if err := o.do(o.drain); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := sink.previews(); len(got) != 1 || got[0] != "2026-10-04T13:00:00Z block_ip unknown scan refused invalid 2" {
		t.Fatalf("isolated damage is missing: %q", got)
	}
}

func TestDecisionCountsAtStopWithoutAnOpenLedger(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &actionSink{}
	opts := f.options()
	opts.DB, opts.WriteAudit = nil, sink.write
	o := Start(opts)
	previousNow := deliveryNow
	deliveryNow = f.host.now
	t.Cleanup(func() { deliveryNow = previousNow })
	o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=1", alert.High), 0, errors.New("ledger unavailable"))
	o.Stop()
	if got := sink.previews(); len(got) != 1 || got[0] != "2026-10-04T13:00:00Z block_ip unknown scan refused invalid 1" {
		t.Fatalf("startup failure lost the clean-stop hour: %q", got)
	}
}

func TestDecisionCountsIncludeLifetimeRefusals(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := f.start(opts)
	previousNow := deliveryNow
	deliveryNow = f.host.now
	t.Cleanup(func() { deliveryNow = previousNow })
	root, err := o.Mint(sshFinding(f.host.now(), "offset=1", alert.High), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Respond(admission.KindBlockIP, root, 0, time.Hour, 2*time.Hour); err == nil {
		t.Fatal("several lifetimes accepted")
	}
	if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := sink.previews(); len(got) != 1 || got[0] != "2026-10-04T13:00:00Z block_ip unknown scan refused invalid 1" {
		t.Fatalf("lifetime refusal missing: %q", got)
	}
}

func TestDecisionCountsNeverRetainAPartialOldHour(t *testing.T) {
	var c comparison
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	key := compareKey{entry: admission.EntryScan, check: "pam_bruteforce", kind: admission.KindBlockIP, decision: decisionQueued}
	for i := range maxUnwrittenRows / 2 {
		key.kind = admission.KindBlockIP
		c.addAt(key, at.Add(time.Duration(i)*time.Hour))
		key.kind = admission.KindChallenge
		c.addAt(key, at.Add(time.Duration(i)*time.Hour))
	}
	c.addAt(key, at.Add(time.Duration(maxUnwrittenRows/2)*time.Hour))
	rows, _ := c.take(at.Add(time.Duration(maxUnwrittenRows/2)*time.Hour), true)
	if len(rows) != maxUnwrittenRows-1 || rows[0].Timestamp != at.Add(2*time.Hour) || rows[1].Timestamp != rows[0].Timestamp {
		t.Fatalf("a partial old hour survived: %d %+v", len(rows), rows[:min(2, len(rows))])
	}
}

func TestDecisionCountsAcknowledgeOnlyTheWrittenBatch(t *testing.T) {
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	o := &Owner{now: at.Add(time.Duration(maxUnwrittenRows) * time.Hour)}
	o.opts.WriteAudit = func(rows []actionlog.Record) error {
		close(started)
		<-release
		return nil
	}
	key := compareKey{entry: admission.EntryScan, check: "pam_bruteforce", kind: admission.KindBlockIP, decision: decisionRefused, reason: admission.ReasonAttribution}
	for i := range maxUnwrittenRows {
		o.compare.addAt(key, at.Add(time.Duration(i)*time.Hour))
	}
	go func() {
		o.writeComparison(false)
		close(done)
	}()
	<-started
	// The bounded queue retires an old row and adds a row absent from the
	// in-flight write. Its acknowledgment must keep that new row.
	o.compare.addAt(key, o.now)
	o.compare.addAt(key, o.now.Add(time.Hour))
	close(release)
	<-done
	rows, _ := o.compare.take(o.now.Add(time.Hour), false)
	if len(rows) != 1 || rows[0].Timestamp != o.now.Add(time.Hour) || rows[0].Count != 1 {
		t.Fatalf("acknowledgment lost a newer unwritten row: %+v", rows)
	}
}

func TestDecisionCountsIncludeContainmentRefusals(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := f.start(opts)
	previousNow := deliveryNow
	deliveryNow = f.host.now
	t.Cleanup(func() { deliveryNow = previousNow })
	root, err := o.Mint(sshFinding(f.host.now(), "offset=1", alert.High), "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	err = o.Respond(admission.KindBlockIP, root, admission.EntryChallengeTimeout)
	if reason, ok := admission.ReasonOf(err); !ok || reason != admission.ReasonUnsupportedContainment {
		t.Fatalf("missing containment refusal: %v", err)
	}
	if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := sink.previews(); len(got) != 1 || got[0] != "2026-10-04T13:00:00Z block_ip unknown challenge_timeout refused unsupported_containment 1" {
		t.Fatalf("containment refusal missing: %q", got)
	}
}

func TestDecisionCountsIncludeMemoryMerges(t *testing.T) {
	for _, outcome := range []string{"queued", "refused", "damaged", "during commit", "same finding during commit"} {
		t.Run(outcome, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			sink := &actionSink{}
			opts := respondOptions(f)
			opts.WriteAudit = sink.write
			o := f.start(opts)
			finding := sshFinding(f.host.now(), "offset=one-observation", alert.High)
			finding.SourceIP = "192.0.2.66"
			first, err := o.Mint(finding, finding.SourceIP)
			if err != nil {
				t.Fatal(err)
			}
			finding.Message = "Another report of the same observation"
			second, err := o.Mint(finding, finding.SourceIP)
			if err != nil {
				t.Fatal(err)
			}
			if first.ID() != second.ID() || first.FindingID() == second.FindingID() || !first.SameExceptFinding(second) {
				t.Fatal("fixture does not remint one observation under another finding")
			}
			if err := o.Respond(admission.KindBlockIP, first, 0); err != nil {
				t.Fatal(err)
			}
			if err := o.Respond(admission.KindBlockIP, second, 0); err != nil {
				t.Fatal(err)
			}
			previous := drainGroupOf
			injected := false
			drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
				if !injected && (outcome == "during commit" || outcome == "same finding during commit" || outcome == "damaged") {
					injected = true
					third := second
					if outcome != "same finding during commit" {
						finding.Message = "A later report of the same observation"
						var err error
						third, err = o.Mint(finding, finding.SourceIP)
						if err != nil {
							return admission.DrainReport{}, err
						}
					}
					if err := o.Respond(admission.KindBlockIP, third, 0); err != nil {
						return admission.DrainReport{}, err
					}
				}
				switch outcome {
				case "refused":
					return in.DrainTaken(l, items, func(s admission.Submission) (admission.CandidateRequest, error) {
						r, err := arrivalRequest(s)
						r.Target, _ = admission.CanonicalAddress("192.0.2.67", admission.Caps{IPv6: true})
						return r, err
					})
				case "damaged":
					return in.DrainTaken(&damagedTargetLedger{Ledger: l, bad: first.Target()}, items, arrivalRequest)
				default:
					return previous(in, l, items)
				}
			}
			t.Cleanup(func() { drainGroupOf = previous })
			if err := o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			if err := o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			if o.ingress.Len() != 0 {
				t.Fatalf("unacknowledged selections remain: %d", o.ingress.Len())
			}
			if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
				t.Fatal(err)
			}
			want := []string{"2026-10-04T13:00:00Z block_ip unknown scan coalesced  1", "2026-10-04T13:00:00Z block_ip unknown scan queued  1"}
			if outcome == "during commit" || outcome == "same finding during commit" {
				want[0] = "2026-10-04T13:00:00Z block_ip unknown scan coalesced  2"
			}
			if outcome == "refused" {
				want = []string{"2026-10-04T13:00:00Z block_ip unknown scan refused invalid 2"}
			}
			if outcome == "damaged" {
				want = []string{"2026-10-04T13:00:00Z block_ip unknown scan refused invalid 3"}
			}
			if got := sink.previews(); !equalStrings(got, want) {
				t.Fatalf("%s: rows = %q, want %q", outcome, got, want)
			}
		})
	}
}
func TestDecisionCountsKeepTheAdmissionHourFloor(t *testing.T) {
	var c comparison
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	key := compareKey{entry: admission.EntryScan, check: "pam_bruteforce", kind: admission.KindBlockIP, decision: decisionRefused, reason: admission.ReasonAttribution}
	c.begin(at)
	c.addAt(key, at.Add(-2*time.Hour))
	rows, through := c.take(at.Add(-2*time.Hour), true)
	if len(rows) != 1 || rows[0].Timestamp != at.Add(time.Hour) || rows[0].Count != 1 {
		t.Fatalf("a backward wall step escaped the admission hour floor: %+v", rows)
	}
	c.written(through)
	c.addAt(key, at.Add(-time.Hour))
	rows, _ = c.take(at.Add(-time.Hour), true)
	if len(rows) != 1 || rows[0].Timestamp != at.Add(time.Hour) || rows[0].Count != 1 {
		t.Fatalf("a final flush rewound the summary clock: %+v", rows)
	}
}
