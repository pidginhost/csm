package daemon

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type actionShowSink func(actionlog.Record) error

func (s actionShowSink) Write(r actionlog.Record) error { return s(r) }

func TestControlActionShowAnswersDuringAuditFailure(t *testing.T) {
	d := New(&config.Config{StatePath: t.TempDir()}, nil, nil, "")
	db, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	opts := testAdmissionOptions(d, db)
	opts.DrainEvery, opts.ScheduleEvery, opts.DeliverEvery = time.Millisecond, time.Millisecond, time.Millisecond
	opts.Expiry = func(admission.Candidate) time.Duration { return time.Hour }
	observed := make(chan string, 1)
	opts.WriteAudit = func(rows []actionlog.Record) error {
		for _, row := range rows {
			if row.Result == "observe" {
				select {
				case observed <- row.ActionID:
				default:
				}
			}
		}
		return nil
	}
	d.startAdmissionWith(opts)
	t.Cleanup(d.stopAdmission)
	clock, err := opts.Clock()
	if err != nil {
		t.Fatal(err)
	}
	finding := alert.Finding{
		Check: "ssh_login_unknown_ip", Severity: alert.Critical, SourceIP: "192.0.2.107", Timestamp: clock.Wall,
		Observation: alert.Observation{Producer: "sshd_log", Stream: "secure:dev=1,ino=2", Cursor: "offset=1", ObservedAt: clock.Wall},
	}
	e, err := d.admission.Mint(finding, finding.SourceIP)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.admission.Respond(admission.KindBlockIP, e, 0); err != nil {
		t.Fatal(err)
	}
	var ref string
	select {
	case ref = <-observed:
	case <-time.After(5 * time.Second):
		t.Fatal("response did not reach its preview outcome")
	}
	reads := make(chan actionlog.Record, 1)
	ownerReads := make(chan error, 1)
	actionlog.SetSink(actionShowSink(func(r actionlog.Record) error {
		reads <- r
		// This would deadlock if the diagnostic audit ran on the owner.
		_, readErr := d.admission.Action(ref)
		ownerReads <- readErr
		return errors.New("fixture audit sink failure")
	}), "")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	cl := &ControlListener{d: d}
	resp := cl.dispatch([]byte(`{"cmd":"action.show","args":{"id":"` + ref + `"}}`))
	var view admission.ActionView
	if !resp.OK || resp.Error != "" || json.Unmarshal(resp.Result, &view) != nil || len(view.Attempts) != 1 ||
		string(view.Attempts[0].Action) != ref || view.Attempts[0].Disposition != "observe" {
		t.Fatalf("audit failure changed the read: %+v, %+v", resp, view)
	}
	select {
	case rec := <-reads:
		if rec.Result != "read" || rec.Target != ref || rec.Error != "" {
			t.Fatalf("read audit = %+v", rec)
		}
	default:
		t.Fatal("read did not attempt its audit")
	}
	select {
	case err := <-ownerReads:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("audit held the admission owner")
	}
}

// `csm action show` reaches the admission owner through the control
// socket; without a running owner it says so.
func TestControlActionShowReachesTheOwner(t *testing.T) {
	d := New(&config.Config{StatePath: t.TempDir()}, nil, nil, "")
	cl := &ControlListener{d: d}
	req := []byte(`{"cmd":"action.show","args":{"id":"cand_` + strings.Repeat("0", 32) + `"}}`)
	if resp := cl.dispatch(req); resp.OK || !strings.Contains(resp.Error, "admission is not running") {
		t.Fatalf("without an owner = %+v", resp)
	}
	db, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	d.startAdmissionWith(testAdmissionOptions(d, db))
	t.Cleanup(d.stopAdmission)
	if resp := cl.dispatch(req); resp.OK || !strings.Contains(resp.Error, "has no record of") {
		t.Fatalf("with an owner = %+v", resp)
	}
}

func TestControlActionShowRejectsMalformedAndMutationRequests(t *testing.T) {
	d := New(&config.Config{StatePath: t.TempDir()}, nil, nil, "")
	db, cleanup := openTestBoltStore(t, t.TempDir())
	t.Cleanup(cleanup)
	d.startAdmissionWith(testAdmissionOptions(d, db))
	t.Cleanup(d.stopAdmission)
	cl := &ControlListener{d: d}
	for _, req := range []string{
		`{"cmd":"action.show","args":{}}`,
		`{"cmd":"action.show","args":{"id":42}}`,
		`{"cmd":"action.show","args":{"id":"192.0.2.1"}}`,
		`{"cmd":"action.show","args":{"id":"act_bad"}}`,
		`{"cmd":"action.resolve","args":{"id":"act_bad"}}`,
		`{"cmd":"action.retry","args":{"id":"act_bad"}}`,
	} {
		if resp := cl.dispatch([]byte(req)); resp.OK || resp.Error == "" {
			t.Fatalf("invalid request %s succeeded: %+v", req, resp)
		}
	}
}

func TestControlActionShowAuditsReadsAndFailures(t *testing.T) {
	sink := captureActionRecords(t)
	cl := &ControlListener{}
	const ref = "act_11111111111111111111111111111111"
	for _, args := range []string{`{"id":"` + ref + `"}`, `{`} {
		if _, err := cl.handleActionShow([]byte(args)); err == nil {
			t.Fatal("unavailable owner or malformed arguments succeeded")
		}
	}
	// Successful owner reads use the same deferred recorder. The owner tests
	// prove that those reads preserve ledger, outbox and engine state.
	recordActionShow(ref, nil)
	if len(sink.records) != 3 {
		t.Fatalf("read audit records = %+v", sink.records)
	}
	for i, rec := range sink.records {
		if rec.Op != "respond.block_ip" || rec.Action != "show" || rec.Actor != actionlog.CLI || rec.ActorDetail != "csm action show" || rec.ActionID != "" {
			t.Fatalf("read audit %d = %+v", i, rec)
		}
		if i < 2 && (rec.Result != actionlog.Failed || rec.Error == "") {
			t.Fatalf("failed read audit = %+v", rec)
		}
		if i == 2 && (rec.Result != "read" || rec.Target != ref || rec.Error != "") {
			t.Fatalf("successful read audit = %+v", rec)
		}
	}
	if sink.records[0].Target != ref {
		t.Fatalf("failed lookup lost its reference: %+v", sink.records[0])
	}
}
