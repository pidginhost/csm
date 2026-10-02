package alert

import "testing"

// Epochs distinguish restarted readers even when the wall clock repeats.
func TestObservationEpochIsDistinctAndBounded(t *testing.T) {
	a, b := NewObservationEpoch(), NewObservationEpoch()
	if a == b || len(a) == 0 || len(a) > 32 || len(b) == 0 || len(b) > 32 {
		t.Fatalf("epochs %q and %q are not distinct bounded tokens", a, b)
	}
	for _, token := range []string{a, b} {
		for i := range token {
			if token[i] < 0x21 || token[i] > 0x7e {
				t.Fatalf("epoch %q contains a non-token byte", token)
			}
		}
	}
}
