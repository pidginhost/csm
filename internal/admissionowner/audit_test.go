package admissionowner

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
)

// withTestRegistry makes the owner register one test producer, whose
// minting capability the test keeps.
func withTestRegistry(t *testing.T) *admission.Producer {
	t.Helper()
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		if check == "ssh_brute" {
			return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal}, true
		}
		return "", admission.Policy{}, false
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Seal()
	prev := buildRegistry
	buildRegistry = func() (*admission.Registry, error) { return reg, nil }
	t.Cleanup(func() { buildRegistry = prev })
	return p
}

// applied takes one candidate through a verified attempt, as the routing
// that 1.4c adds will: its reservation, execution and outcome each leave an
// audit row.
func applied(t *testing.T, o *Owner, p *admission.Producer, host *fakeHost) admission.CandidateID {
	t.Helper()
	var id admission.CandidateID
	if err := o.do(func() error {
		target, err := admission.CanonicalAddress("192.0.2.10", admission.Caps{IPv6: true})
		if err != nil {
			return err
		}
		host.mu.Lock()
		now := host.wall
		host.mu.Unlock()
		e, err := p.Mint(admission.EvidenceInput{
			Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
			Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: "offset=1", Version: 1},
			ObservedAt:  now, Parser: admission.ParserRef{Name: "sshd", Version: 1}, Target: target,
		})
		if err != nil {
			return err
		}
		if _, err = o.ledger.PublishEvidence(e); err != nil {
			return err
		}
		ep, err := admission.ParseEpisodeID("00000000000000000000000000000001")
		if err != nil {
			return err
		}
		c, _, err := o.ledger.Enqueue(admission.CandidateRequest{Kind: admission.KindBlockIP, Target: target, Episode: ep, Generation: 1, Primary: e.ID()})
		if err != nil {
			return err
		}
		if id, err = c.ID(); err != nil {
			return err
		}
		_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, now.Add(time.Hour))
		if err != nil {
			return err
		}
		if _, _, _, err = o.ledger.Execute(a.Attempt.ID); err != nil {
			return err
		}
		_, _, err = o.ledger.Finish(a.Attempt.ID, admission.DispositionApplied)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func pendingAudit(t *testing.T, o *Owner) []admission.AuditRow {
	t.Helper()
	var rows []admission.AuditRow
	if err := o.do(func() (err error) { rows, err = o.ledger.PendingAudit(100); return err }); err != nil {
		t.Fatal(err)
	}
	return rows
}

// auditSink records every batch the owner writes and fails as told.
type auditSink struct {
	mu      sync.Mutex
	batches [][]actionlog.Record
	err     error
}

func (s *auditSink) write(rs []actionlog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil || errors.Is(s.err, actionlog.ErrDurableUnacknowledged) {
		s.batches = append(s.batches, append([]actionlog.Record(nil), rs...))
	}
	return s.err
}

func (s *auditSink) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Spec 5.5, handoff O49 and ruling R1: the audit rows go to the action log
// in one durable write and are acknowledged only after it, each by its ID
// and time. A failed write acknowledges nothing; a write whose
// acknowledgement was lost is repeated with the same identity, so readers
// drop the copy. After acknowledgement the ended history retires at its
// target on the owner's ticks.
func TestOwnerDeliversAuditRowsDurably(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &auditSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	id := applied(t, o, p, f.host)
	rows := pendingAudit(t, o)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want reservation, execution and outcome", len(rows))
	}
	sink.set(errors.New("disk full"))
	if err := o.do(o.deliverAudit); err == nil {
		t.Fatal("a failed write reported delivery")
	}
	if got := pendingAudit(t, o); len(got) != 3 {
		t.Fatalf("a failed write acknowledged rows: %d left", len(got))
	}
	sink.set(actionlog.ErrDurableUnacknowledged)
	if err := o.do(o.deliverAudit); err == nil {
		t.Fatal("an unacknowledged write reported delivery")
	}
	sink.set(nil)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if got := pendingAudit(t, o); len(got) != 0 {
		t.Fatalf("delivered rows still pending: %+v", got)
	}
	if len(sink.batches) != 2 || !reflect.DeepEqual(sink.batches[0], sink.batches[1]) {
		t.Fatalf("batches = %+v, want the uncertain one repeated unchanged", sink.batches)
	}
	for i, r := range sink.batches[1] {
		row := rows[i]
		want := actionlog.Record{
			Timestamp: row.At, Op: "respond.block_ip", Action: "block_ip", Actor: actionlog.Daemon,
			FindingID: "0123456789abcdef", ActionID: string(row.Attempt.ID), ActionVersion: uint64(row.Transition),
			Target: "ip:192.0.2.10", Reason: "general lane, expires " + row.ExpiresAt.UTC().Format(time.RFC3339),
			Result: actionlog.Result([]string{"reserved", "executing", "applied"}[i]),
		}
		if !reflect.DeepEqual(r, want) {
			t.Errorf("record %d = %+v\nwant %+v", i, r, want)
		}
	}
	if err := o.do(o.deliverAudit); err != nil || len(sink.batches) != 2 {
		t.Fatalf("an empty outbox wrote a batch: %d batches, %v", len(sink.batches), err)
	}
	f.host.advance(admission.HistoryTarget + time.Hour)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { _, err := o.ledger.Candidate(id); return err }); err == nil {
		t.Fatal("acknowledged history did not retire at its target")
	}
}

// O51 for the outbox: a stalled delivery reports through queue health, and
// the next delivery clears it.
func TestOwnerReportsStalledAuditDelivery(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &auditSink{err: errors.New("disk full")}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	applied(t, o, p, f.host)
	_ = o.do(o.deliverAudit)
	later := time.Now().Add(10 * time.Minute)
	if s := o.QueueStatuses(later)["audit"]; s.Status != "degraded" || s.Depth == 0 {
		t.Fatalf("stalled audit delivery = %+v", s)
	}
	sink.set(nil)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if s := o.QueueStatuses(later)["audit"]; s.Status == "degraded" || s.Depth != 0 {
		t.Fatalf("recovered audit delivery = %+v", s)
	}
}

// A backlog that drains is not a stall: each acknowledged batch is
// progress, so a later failure is timed from the last progress made.
func TestOwnerDrainingAuditIsNotStalled(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	prevBatch, prevNow := auditBatch, deliveryNow
	t.Cleanup(func() { auditBatch, deliveryNow = prevBatch, prevNow })
	auditBatch = 1
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	deliveryNow = func() time.Time { return now }
	writes := 0
	opts := f.options()
	opts.WriteAudit = func([]actionlog.Record) error {
		writes++
		if writes == 1 || writes > 2 {
			return errors.New("disk full")
		}
		return nil
	}
	o := f.start(opts)
	applied(t, o, p, f.host)
	_ = o.do(o.deliverAudit)
	now = now.Add(5 * time.Minute)
	_ = o.do(o.deliverAudit)
	if got := len(pendingAudit(t, o)); got != 2 {
		t.Fatalf("pending = %d, want one row delivered", got)
	}
	if s := o.QueueStatuses(now.Add(30 * time.Second))["audit"]; s.Status == "degraded" {
		t.Fatalf("a draining backlog reported a stall: %+v", s)
	}
}

// A fresh ledger reading reaches the ingress after a tick and a reload.
func TestOwnerPublishesFreshSnapshots(t *testing.T) {
	for _, via := range []string{"tick", "reload", "inventory"} {
		t.Run(via, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			o := f.start(f.options())
			f.host.advance(10 * time.Minute)
			var err error
			switch via {
			case "tick":
				err = o.do(o.tick)
			case "reload":
				err = o.Reload()
			case "inventory":
				err = o.do(func() error {
					if _, e := o.readTick(); e != nil {
						return e
					}
					o.refreshInventory()
					return nil
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			target, err := admission.CanonicalAddress("192.0.2.10", admission.Caps{IPv6: true})
			if err != nil {
				t.Fatal(err)
			}
			e, err := p.Mint(admission.EvidenceInput{Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
				Observation: admission.ObservationRef{Stream: "fixture", Cursor: "1", Version: 1}, ObservedAt: f.host.wall,
				Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target})
			if err != nil {
				t.Fatal(err)
			}
			if err := o.ingress.Submit(admission.Submission{Kind: admission.KindBlockIP, Target: target, Evidence: e}); err != nil {
				t.Fatal("fresh evidence refused after publication:", err)
			}
			o.halt(false)
		})
	}
}
