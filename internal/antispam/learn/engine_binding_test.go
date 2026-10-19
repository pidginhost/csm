package learn

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestEngineBindingWriteFailureDefersReport(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	fault := &failingKV{kv: f.ledger.db}
	f.ledger.db = fault
	fault.fail.Store(true)
	e := newTestEngine(t, f)
	c := Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)}
	out, err := e.SubmitReport(context.Background(), c)
	if err != nil || !out.Deferred || !errors.Is(out.Err, ErrStateIO) {
		t.Fatalf("binding write failure was not a deferred state error: %+v, %v", out, err)
	}
	if _, bodies, _, _ := f.storage.native(); bodies != 0 {
		t.Fatal("inspected a report before binding succeeded")
	}
	fault.fail.Store(false)
	engineTurn(t, e, func() { e.background(context.Background()) })
	out, err = e.SubmitReport(context.Background(), c)
	if err != nil || out.Err != nil || out.Deferred || !reflect.DeepEqual(out.Committed, []uint64{1}) {
		t.Fatalf("report did not resume after binding recovered: %+v, %v", out, err)
	}
}
