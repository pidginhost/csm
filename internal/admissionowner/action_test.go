package admissionowner

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// `csm action show` reads one candidate and its attempts by either ID: the
// attempts in order with their outcomes, and for a pick refused as an
// existing effect, the block that already enforced it (1.5c-2c handoff).
func TestOwnerShowsAnAction(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	id := applied(t, o, p, f.host)
	c := candidate(t, o, id)
	view, err := o.Action(string(id))
	if err != nil {
		t.Fatal(err)
	}
	if view.Candidate != id || view.Kind != "block_ip" || view.Target != "ip:192.0.2.10" || view.Check != "ssh_brute" ||
		view.FindingID != "0123456789abcdef" || view.State != "verified" || view.Disposition != "applied" || view.Reason != "" ||
		!view.ExpiresAt.Equal(c.ExpiresAt) || view.Link != nil || len(view.Attempts) != 1 {
		t.Fatalf("view = %+v", view)
	}
	wire, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["candidate_id"]) != `"`+string(id)+`"` || fields["candidate"] != nil {
		t.Fatalf("candidate JSON keys = %s", wire)
	}
	var attempts []map[string]json.RawMessage
	if err = json.Unmarshal(fields["attempts"], &attempts); err != nil || len(attempts) != 1 {
		t.Fatalf("attempt JSON = %s, %v", wire, err)
	}
	if string(attempts[0]["action_id"]) != `"`+string(view.Attempts[0].Action)+`"` || attempts[0]["action"] != nil {
		t.Fatalf("attempt ID uses an operation field: %s", wire)
	}
	a := view.Attempts[0]
	if a.Seq != 1 || !strings.HasPrefix(string(a.Action), "act_") || a.State != "verified" || a.Disposition != "applied" ||
		a.Lane != "general" || a.Reserved.IsZero() || a.Finished.IsZero() || !a.ExpiresAt.Equal(c.ExpiresAt) || a.Retired {
		t.Fatalf("attempt = %+v", a)
	}
	byAction, err := o.Action(string(a.Action))
	if err != nil || !reflect.DeepEqual(byAction, view) {
		t.Fatalf("by action = %+v, %v; want %+v", byAction, err, view)
	}

	linked, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.21")
	link := admission.EffectLink{Effect: string(a.Action), ExpiresAt: now.Add(2 * time.Hour)}
	if err = o.do(func() error { _, termErr := o.ledger.TerminateExisting(linked, link); return termErr }); err != nil {
		t.Fatal(err)
	}
	lv, err := o.Action(string(linked))
	if err != nil || lv.State != "refused" || lv.Reason != "existing_effect" || lv.Attempts == nil || len(lv.Attempts) != 0 ||
		lv.Link == nil || lv.Link.Effect != link.Effect || !lv.Link.ExpiresAt.Equal(link.ExpiresAt) {
		t.Fatalf("linked view = %+v, %v", lv, err)
	}

	if _, err = o.Action("cand_" + strings.Repeat("0", 32)); err == nil || !strings.Contains(err.Error(), "has no record of") {
		t.Fatalf("missing candidate = %v", err)
	}
	if _, err = o.Action("act_" + strings.Repeat("0", 32)); err == nil || !strings.Contains(err.Error(), "has no record of") {
		t.Fatalf("missing action = %v", err)
	}
	if _, err = o.Action("192.0.2.10"); err == nil || !strings.Contains(err.Error(), "neither a candidate nor an action ID") {
		t.Fatalf("malformed ID = %v", err)
	}
}

func TestOwnerShowsRetiredAndMissingHistory(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.101")
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	if err := o.do(func() error {
		if err := o.tick(); err != nil {
			return err
		}
		return o.retire()
	}); err != nil {
		t.Fatal(err)
	}
	before := ledgerStatus(t, o)
	pending := pendingAudit(t, o)
	calls := len(blocks.retireCalls())
	for _, ref := range []string{string(a.Attempt.ID), string(a.Attempt.Candidate)} {
		v, err := o.Action(ref)
		if err != nil || len(v.Attempts) != 1 || !v.Attempts[0].Retired || v.Attempts[0].Disposition != "unknown" || v.Attempts[0].State != "unknown" {
			t.Fatalf("retained retirement = %+v, %v", v, err)
		}
	}
	if !reflect.DeepEqual(before, ledgerStatus(t, o)) || !reflect.DeepEqual(pending, pendingAudit(t, o)) || len(blocks.retireCalls()) != calls {
		t.Fatal("action show changed the ledger, outbox or engine")
	}
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	f.host.advance(admission.HistoryTarget + time.Hour)
	mono.advance(admission.HistoryTarget + time.Hour)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{string(a.Attempt.ID), string(a.Attempt.Candidate)} {
		if _, err := o.Action(ref); err == nil || !strings.Contains(err.Error(), "has no record of") {
			t.Fatalf("retired history %s = %v; candidate was %+v", ref, err, c)
		}
	}
}

func TestOwnerShowsEveryAttemptWithoutWriting(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	id, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.102")
	for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
		if err := o.do(func() error {
			_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, now.Add(time.Hour))
			if err != nil {
				return err
			}
			if _, _, _, err = o.ledger.Execute(a.Attempt.ID); err != nil {
				return err
			}
			_, _, err = o.ledger.Finish(a.Attempt.ID, admission.DispositionFailed)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.host.advance(admission.RetryBackoff(seq))
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	before, pending := ledgerStatus(t, o), pendingAudit(t, o)
	v, err := o.Action(string(id))
	if err != nil || len(v.Attempts) != admission.MaxAttempts {
		t.Fatalf("all attempts = %+v, %v", v, err)
	}
	for i, a := range v.Attempts {
		if a.Seq != uint32(i+1) || a.Disposition != "failed" {
			t.Fatalf("attempt order/outcome = %+v", v.Attempts)
		}
	}
	if !reflect.DeepEqual(before, ledgerStatus(t, o)) || !reflect.DeepEqual(pending, pendingAudit(t, o)) {
		t.Fatal("action show mutated ledger state")
	}
}

// Retention removes a candidate and its entire attempt chain atomically.
// A missing predecessor while the candidate remains is damage, not normal
// history retirement. A read failure must not become a truncated success.
func TestOwnerShowsMissingAttemptAsDamage(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	id, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.103")
	for seq := uint32(1); seq <= 2; seq++ {
		if err := o.do(func() error {
			_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, now.Add(time.Hour))
			if err != nil {
				return err
			}
			if _, _, _, err = o.ledger.Execute(a.Attempt.ID); err != nil {
				return err
			}
			outcome := admission.DispositionFailed
			if seq == 2 {
				outcome = admission.DispositionApplied
			}
			_, _, err = o.ledger.Finish(a.Attempt.ID, outcome)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.host.advance(admission.RetryBackoff(seq))
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := admission.NewAttempt(id, 1)
	last, _ := admission.NewAttempt(id, 2)
	before, pending := ledgerStatus(t, o), pendingAudit(t, o)
	missing := admission.ActionID("act_" + strings.Repeat("0", 32))
	setOwnerHook(t, o, &readActionAttempt, func(l *store.AdmissionLedger, action admission.ActionID) (admission.AttemptRecord, error) {
		if action == first.ID {
			return l.Attempt(missing)
		}
		return l.Attempt(action)
	})
	for _, ref := range []string{string(id), string(last.ID)} {
		v, err := o.Action(ref)
		if !errors.Is(err, admission.ErrCorruptRecord) || !strings.Contains(err.Error(), string(first.ID)) || len(v.Attempts) != 0 {
			t.Fatalf("missing predecessor = %+v, %v", v, err)
		}
	}
	cause := errors.New("fixture read failure")
	setOwnerHook(t, o, &readActionAttempt, func(*store.AdmissionLedger, admission.ActionID) (admission.AttemptRecord, error) {
		return admission.AttemptRecord{}, cause
	})
	if _, err := o.Action(string(id)); !errors.Is(err, cause) {
		t.Fatalf("read failure was hidden: %v", err)
	}
	if !reflect.DeepEqual(before, ledgerStatus(t, o)) || !reflect.DeepEqual(pending, pendingAudit(t, o)) {
		t.Fatal("failed action lookup changed the ledger or outbox")
	}
}
