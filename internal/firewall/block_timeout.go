package firewall

import "time"

// blockTimeout is the kernel timeout that keeps a timed element no longer
// than its absolute expiry: the time left at now, truncated to the
// kernel's millisecond precision. It reports false when less than a
// millisecond is left: nftables would send a zero timeout, which the
// kernel takes as no timeout at all, and a negative one wraps.
func blockTimeout(expiresAt, now time.Time) (time.Duration, bool) {
	left := expiresAt.Sub(now)
	if !now.Add(left).Equal(expiresAt) {
		return 0, false
	}
	left = left.Truncate(time.Millisecond)
	if left < time.Millisecond {
		return 0, false
	}
	return left, true
}
