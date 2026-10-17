package ipmap

import (
	"net/netip"
	"slices"
)

// Verdict is what one scan says about its sender.
type Verdict int

const (
	NoVerdict Verdict = iota
	SpamVerdict
	HamVerdict
)

// Judge turns one scan into a verdict about its sender (spec 7.2): the
// score, in Exim tenths, less the weight CSM's own map gave the sender; spam
// at or above the reject score, ham below the tag score, nothing between or
// on a failed scan. Dry run, enforce and an opted-out recipient judge the
// same way: the verdict is about the sender.
func Judge(scanOK bool, score, mapTenths, rejectScore, tagScore int) Verdict {
	if !scanOK {
		return NoVerdict
	}
	adjusted := score - mapTenths
	switch {
	case adjusted >= rejectScore*10:
		return SpamVerdict
	case adjusted < tagScore*10:
		return HamVerdict
	}
	return NoVerdict
}

// Recordable reports whether evidence about a may be recorded: only
// addresses the map could ever list (spec 7.2).
func Recordable(a netip.Addr, never []netip.Addr) bool {
	if a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	return listable(a) && !slices.ContainsFunc(never, func(excluded netip.Addr) bool {
		return excluded.Unmap() == a
	})
}
