package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

type lifecycleResolver interface {
	lifecycleRunner
	Resolve(string, string, string, firewall.ActionKernel) (firewall.FirewallAction, error)
}

func resolverFor(t *testing.T, db *DB, audit func(firewall.FirewallAction) error) lifecycleResolver {
	t.Helper()
	l := &firewall.Lifecycle{Store: actionStore(t, db), Audit: audit}
	r, ok := any(l).(lifecycleResolver)
	if !ok {
		t.Fatal("firewall lifecycle has no operator resolution boundary")
	}
	return r
}

// strandedAction leaves one action in the uncertain phase, which is the state
// that blocks every later firewall mutation until somebody resolves it.
func strandedAction(t *testing.T, db *DB, l lifecycleResolver) (firewall.FirewallAction, *observedKernel) {
	t.Helper()
	a := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
		t.Fatal(err)
	}
	k := &observedKernel{state: a.Before}
	k.afterWrite = func() { k.observeFail = errors.New("kernel inspection unavailable") }
	if _, err := l.Execute(a, k); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("execute = %v, want an uncertain outcome", err)
	}
	stored, err := db.ReadFirewallAction(a.Request.ID)
	if err != nil || stored.Phase != "unknown" {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	return a, k
}

func TestFirewallLifecycleOperatorResolvesStrandedAction(t *testing.T) {
	db := openSnapshotDB(t)
	var delivered []firewall.FirewallAction
	l := resolverFor(t, db, func(a firewall.FirewallAction) error { delivered = append(delivered, a); return nil })
	a, k := strandedAction(t, db, l)
	// The kernel still cannot answer, which is why an operator has to.
	resolved, err := l.Resolve(a.Request.ID, "verified", "operator cli: rule confirmed on the host", k)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Phase != "verified" || !strings.Contains(resolved.Detail, "operator cli") {
		t.Fatalf("resolved = %#v", resolved)
	}
	assertFirewallSnapshot(t, db, a.After, 2)
	pending, err := db.PendingFirewallActions()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after resolve = %#v, %v", pending, err)
	}
	outstanding, err := db.FirewallAuditPending()
	if err != nil || len(outstanding) != 0 {
		t.Fatalf("audit after resolve = %#v, %v", outstanding, err)
	}
	last := delivered[len(delivered)-1]
	if last.Phase != "verified" || last.Request.ID != a.Request.ID {
		t.Fatalf("audit record = %#v", last)
	}
	if k.writes != 1 {
		t.Fatal("resolution replayed the kernel mutation")
	}
}

func TestFirewallLifecycleOperatorCannotOverrideProvenOutcome(t *testing.T) {
	db := openSnapshotDB(t)
	l := resolverFor(t, db, func(firewall.FirewallAction) error { return nil })
	a, k := strandedAction(t, db, l)
	// The kernel can answer again, and it proves the mutation did land.
	k.observeFail = nil
	resolved, err := l.Resolve(a.Request.ID, "failed", "operator cli: assumed rejected", k)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Phase != "verified" {
		t.Fatalf("resolved = %q, want the proven outcome", resolved.Phase)
	}
	if strings.Contains(resolved.Detail, "assumed rejected") {
		t.Fatal("an operator assertion overwrote kernel evidence")
	}
	assertFirewallSnapshot(t, db, a.After, 2)
}

func TestFirewallLifecycleResolveRejectsUnsupportedRequests(t *testing.T) {
	db := openSnapshotDB(t)
	l := resolverFor(t, db, func(firewall.FirewallAction) error { return nil })
	a, k := strandedAction(t, db, l)
	for _, outcome := range []string{"", "planned", "applied", "unknown", "nonsense"} {
		if _, err := l.Resolve(a.Request.ID, outcome, "operator cli", k); err == nil {
			t.Fatalf("resolve accepted outcome %q", outcome)
		}
	}
	if _, err := l.Resolve(a.Request.ID, "verified", "", k); err == nil {
		t.Fatal("resolve accepted an unattributed decision")
	}
	if _, err := l.Resolve("missing", "verified", "operator cli", k); !errors.Is(err, firewall.ErrActionMissing) {
		t.Fatal("resolve accepted an unknown request ID")
	}
	if _, err := l.Resolve(a.Request.ID, "verified", "operator cli", k); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// A proven outcome is final: it is not an operator decision any more.
	if _, err := l.Resolve(a.Request.ID, "failed", "operator cli", k); err == nil {
		t.Fatal("resolve rewrote a settled outcome")
	}
}
