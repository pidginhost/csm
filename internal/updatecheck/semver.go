package updatecheck

import (
	"strconv"
	"strings"
)

// isNewer returns true when a is strictly greater than b under
// dot-separated numeric ordering. "dev" or empty current always
// loses (a real release is always newer than "dev"). Current-version
// strings produced by git describe, such as 3.0.0-12-gabcdef0, compare
// as newer than their base tag but older than the next tagged release.
func isNewer(a, b string) bool {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == "" {
		return false
	}
	if b == "" || b == "dev" {
		return true
	}
	if base, ok := gitDescribeBase(b); ok {
		return isNewer(a, base)
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

func gitDescribeBase(v string) (string, bool) {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", false
	}
	if !strings.HasPrefix(parts[2], "g") || !isNumericDotted(parts[0]) {
		return "", false
	}
	return parts[0], true
}

func isNumericDotted(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}
