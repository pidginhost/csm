package learn

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestEngineFrozenAfterDeclaredRestore(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	if err := f.ledger.MarkDeclaredRestore(t0); err != nil {
		t.Fatal(err)
	}
	if held, err := f.ledger.DeclaredRestore(); err != nil || !held {
		t.Fatalf("mark not recorded: %v, %v", held, err)
	}
	e := newTestEngine(t, f)
	snapshot := f.report("tenant report", digest('a'), digest('a'), 1)
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 2003, Snapshot: snapshot})
	if len(out.Committed)+len(out.Duplicates)+len(out.Pending) != 0 {
		t.Fatalf("a declared restore admitted a report: %+v, %v", out, err)
	}
	if _, _, adds, deletes := f.storage.native(); adds != 0 || deletes != 0 {
		t.Fatal("a declared restore mutated storage")
	}
	mismatch := false
	for _, p := range e.Problems() {
		mismatch = mismatch || p.Key == antispam.ReasonStateMismatch
	}
	if !mismatch {
		t.Fatalf("problems %+v", e.Problems())
	}
	if err = f.ledger.ClearDeclaredRestore(); err != nil {
		t.Fatal(err)
	}
	if held, _ := f.ledger.DeclaredRestore(); held {
		t.Fatal("mark not cleared")
	}
}
