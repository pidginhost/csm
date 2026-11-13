package firewall

import "regexp"

// setElementCount matches the live element count that nft prints beside a
// set's size on newer kernels. It moves with traffic; the size is structure.
var setElementCount = regexp.MustCompile(`(?m)^([ \t]*size [0-9]+)[ \t]*# count [0-9]+$`)

// StableRuleset removes set element counts from a terse nft listing, so two
// listings of unchanged rules compare equal.
func StableRuleset(listing string) string {
	return setElementCount.ReplaceAllString(listing, "$1")
}
