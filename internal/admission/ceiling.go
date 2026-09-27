package admission

import "time"

// MaxCeiling bounds the hourly ceiling the ledger accepts. Every charge
// retained in the window is one stored record, so it also bounds them.
const MaxCeiling = 20000

// CeilingWindow is the rolling window the ceiling counts charges over.
const CeilingWindow = time.Hour

// CeilingLanes splits the hourly ceiling L into the general allowance
// G = L-R and the reserved allowance R = ceil(L/5), which only direct
// compromise and independently corroborated work may spend (spec 5.6). For
// L=1 only the reserved lane exists.
func CeilingLanes(limit uint32) (general, reserved uint32) {
	reserved = limit / 5
	if limit%5 != 0 {
		reserved++
	}
	return limit - reserved, reserved
}

// BucketCap is the most credit a lane of size units per hour may save: ten
// minutes of its rate, and at least one unit so a small lane can run. An
// empty lane never runs.
func BucketCap(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	return max(1, size/6)
}

// CeilingCost is what one attempt of kind k charges the ceiling. Each new
// address, prefix, promotion or service tuple costs one unit. Challenge
// work has its own bound (spec 5.12) and is never charged: it cannot
// create a block.
func (k Kind) CeilingCost() uint32 {
	if k == KindChallenge {
		return 0
	}
	return 1
}
