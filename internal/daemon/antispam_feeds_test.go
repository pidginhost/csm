package daemon

import "testing"

// Feeds need the daemon to read the DQS key, probe lists and remember
// holds; a missing hook silently disables that part.
func TestAntispamReconcilerWiresFeedHooks(t *testing.T) {
	r := antispamReconciler()
	if r.ReadKey == nil || r.Probe == nil || r.Feeds == nil {
		t.Fatalf("feed hooks: ReadKey %t, Probe %t, Feeds %t", r.ReadKey != nil, r.Probe != nil, r.Feeds != nil)
	}
}
