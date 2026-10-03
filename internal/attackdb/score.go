package attackdb

import "sort"

// ComputeScore returns a 0-100 local threat score from an IPRecord.
//
// Scoring logic:
//   - Volume: min(attack event count * 2, 30); authenticated activity excluded
//   - Attack type bonuses (non-cumulative per type)
//   - Multi-account targeting: +10
//   - Auto-blocked floor: 50
//   - Hard cap: 100
func ComputeScore(r *IPRecord) int {
	score := 0

	// Audit events stay in the record and history, but cannot increase the
	// volume score or turn successful access into multi-account targeting.
	attackEvents := max(0, r.EventCount-r.AttackCounts[AttackAuthSuccess])
	vol := attackEvents * 2
	if vol > 30 {
		vol = 30
	}
	score += vol

	// Attack type bonuses
	if r.AttackCounts[AttackBruteForce] > 0 {
		score += 15
	}
	if r.AttackCounts[AttackWAFBlock] > 5 {
		score += 10
	}
	if r.AttackCounts[AttackFileUpload] > 0 {
		score += 20
	}

	// Count accounts with attack evidence, including accounts that also
	// have successful activity from this address.
	targetedAccounts := 0
	for account, count := range r.Accounts {
		if count > r.AuthSuccessAccounts[account] {
			targetedAccounts++
		}
	}
	if targetedAccounts > 1 && attackEvents > 0 {
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
