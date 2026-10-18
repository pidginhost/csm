package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/checks"
)

func TestAntispamReconcilerKeepsLearningState(t *testing.T) {
	r := antispamReconciler()
	if r.Learning == nil {
		t.Fatal("daemon reconciler has no memory of failed learning generations")
	}
	if other := antispamReconciler(); other.Learning == r.Learning {
		t.Fatal("independent reconcile loops share learning holds")
	}
}

// Findings with an unregistered check name have no correlation policy; the
// registry scanner cannot see the reconcile constants, so list them here.
func TestAntispamChecksRegistered(t *testing.T) {
	for _, name := range []string{
		reconcile.CheckPrecondition, reconcile.CheckApplyFailed, reconcile.CheckRspamdDown,
		reconcile.CheckRspamdRecovered, reconcile.CheckScanError, reconcile.CheckFeed,
		reconcile.CheckIPMap, reconcile.CheckControllerOpen, reconcile.CheckLearning,
	} {
		if _, ok := checks.LookupCheck(name); !ok {
			t.Errorf("check %s is not registered", name)
		}
	}
}

func TestAntispamReconcilerWiresLearning(t *testing.T) {
	r := antispamReconciler()
	if r.EnsureKeys == nil || r.LoadKeys == nil || r.CollectLearning == nil {
		t.Fatal("daemon reconciler cannot create keys or collect learning facts")
	}
}
