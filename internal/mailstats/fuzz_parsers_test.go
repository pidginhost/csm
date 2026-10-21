package mailstats

import (
	"net"
	"slices"
	"testing"
)

func FuzzParseReject(f *testing.F) {
	for _, c := range rejectClassCases {
		f.Add(c.line)
	}
	for _, c := range rejectSpoofCases {
		f.Add(c.line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := ParseReject(line, rejectLoc, rejectFallback)
		if n := len([]rune(r.Detail)); n > 120 {
			t.Fatalf("detail has %d runes", n)
		}
		if !ok {
			return
		}
		if !slices.Contains(Classes, r.Class) {
			t.Fatalf("class %q not in Classes", r.Class)
		}
		if r.IP != "" && net.ParseIP(r.IP) == nil {
			t.Fatalf("ip %q is not an address", r.IP)
		}
	})
}
