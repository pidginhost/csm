package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
)

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
