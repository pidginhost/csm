// Package spamscore is the spam score shared by CSM's spam evidence and the
// rspamd reputation source: verdict masses decay with a 7-day half-life and
// a prior mass keeps a few verdicts from saturating the score.
package spamscore

import (
	"math"
	"time"
)

const (
	// PriorMass is smoothing added to the total so one verdict alone scores
	// 33 and two fresh spam verdicts with no ham reach 50.
	PriorMass = 2.0
	// HalfLife halves a verdict's weight per week.
	HalfLife = 7 * 24 * time.Hour
)

// Recency is the weight left after age; a zero or negative age counts in
// full.
func Recency(age time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	return math.Exp2(-age.Hours() / HalfLife.Hours())
}

// Score is 100 * spam / (total + PriorMass), rounded; 0 without spam.
func Score(spam, total float64) int {
	if spam <= 0 || total <= 0 {
		return 0
	}
	return int(math.Round(100 * spam / (total + PriorMass)))
}
