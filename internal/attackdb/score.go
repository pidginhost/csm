package attackdb

import "sort"

// ComputeScore returns a 0-100 local threat score from an IPRecord.
//
// Scoring logic:
//   - Volume: min(event_count * 2, 30)
//   - Attack type bonuses (non-cumulative per type)
//   - Multi-account targeting: +10
//   - Auto-blocked floor: 50
//   - Hard cap: 100
func ComputeScore(r *IPRecord) int {
	score := 0

	// Volume component - caps at 30
	vol := r.EventCount * 2
	if vol > 30 {
		vol = 30
	}
	score += vol

	// Attack type bonuses
	if r.AttackCounts[AttackC2] > 0 {
		score += 35
	}
	if r.AttackCounts[AttackWebshell] > 0 {
		score += 30
	}
	if r.AttackCounts[AttackPhishing] > 0 {
		score += 25
	}
	if r.AttackCounts[AttackBruteForce] > 0 {
		score += 15
	}
	if r.AttackCounts[AttackWAFBlock] > 5 {
		score += 10
	}
	if r.AttackCounts[AttackFileUpload] > 0 {
		score += 20
	}

	// Multi-account targeting
	if len(r.Accounts) > 1 {
		score += 10
	}

	// Auto-blocked floor
	if r.AutoBlocked && score < 50 {
		score = 50
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// sortRecords sorts by threat score descending, then event count descending.
func sortRecords(recs []*IPRecord) {
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].ThreatScore != recs[j].ThreatScore {
			return recs[i].ThreatScore > recs[j].ThreatScore
		}
		return recs[i].EventCount > recs[j].EventCount
	})
}
