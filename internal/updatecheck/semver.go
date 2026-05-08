package updatecheck

import (
	"strconv"
	"strings"
)

// isNewer returns true when a is strictly greater than b under
// dot-separated numeric ordering. "dev" or empty current always
// loses (a real release is always newer than "dev"). Trailing
// non-numeric segments compare lexically. The function intentionally
// avoids pulling golang.org/x/mod/semver to keep the dependency
// graph small.
func isNewer(a, b string) bool {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == "" {
		return false
	}
	if b == "" || b == "dev" {
		return true
	}
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	for i := 0; i < len(ap) || i < len(bp); i++ {
		var av, bv string
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		ai, aErr := strconv.Atoi(av)
		bi, bErr := strconv.Atoi(bv)
		switch {
		case aErr == nil && bErr == nil:
			if ai != bi {
				return ai > bi
			}
		case aErr == nil && bErr != nil:
			return true
		case aErr != nil && bErr == nil:
			return false
		default:
			if av != bv {
				return av > bv
			}
		}
	}
	return false
}
