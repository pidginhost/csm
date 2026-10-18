package daemon

import "testing"

func TestAntispamReconcilerKeepsLearningState(t *testing.T) {
	r := antispamReconciler()
	if r.Learning == nil {
		t.Fatal("daemon reconciler has no memory of failed learning generations")
	}
	if other := antispamReconciler(); other.Learning == r.Learning {
		t.Fatal("independent reconcile loops share learning holds")
	}
}
