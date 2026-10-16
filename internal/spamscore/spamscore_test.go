package spamscore

import (
	"testing"
	"time"
)

func TestRecencyHalvesPerWeek(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want float64
	}{
		{0, 1}, {-time.Hour, 1}, {HalfLife, 0.5}, {2 * HalfLife, 0.25},
	} {
		if got := Recency(tc.age); got != tc.want {
			t.Errorf("Recency(%v) = %v, want %v", tc.age, got, tc.want)
		}
	}
}

// Two recent spam verdicts and no ham reach 50, the CSM_IP_SPAM listing
// threshold (feeds spec 7.4); one alone does not.
func TestScore(t *testing.T) {
	for _, tc := range []struct {
		spam, total float64
		want        int
	}{
		{1, 1, 33}, {2, 2, 50}, {2, 3, 40}, {0, 5, 0}, {0, 0, 0}, {10, 10, 83},
	} {
		if got := Score(tc.spam, tc.total); got != tc.want {
			t.Errorf("Score(%v, %v) = %d, want %d", tc.spam, tc.total, got, tc.want)
		}
	}
}
