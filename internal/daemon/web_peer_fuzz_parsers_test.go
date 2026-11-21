package daemon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// Any prefix appended without a newline either preserves the forged request
// or causes a loss. It must not let earlier direct evidence vouch for it.
func FuzzWebPeerLogJoinedLine(f *testing.F) {
	for _, prefix := range []string{"", "0", "+000", " \t", "9", "922337203", "+922337203", "000922337203", "-", "1 ", "\r", "\x00"} {
		f.Add(prefix)
	}
	f.Fuzz(func(t *testing.T, prefix string) {
		t.Cleanup(checks.ResetWebPeersForTest())
		now := time.Unix(1795200000, 0)
		victim := netip.MustParseAddr("203.0.113.81")
		p := newWebPeerLog()
		p.now = func() time.Time { return now }
		p.handle(peerLine(now.Add(-time.Minute), "site.example", victim.String(), victim.String()), nil)
		p.handle(prefix+peerLine(now, "site.example", "192.0.2.10", victim.String()), nil)
		if got := checks.WebPeerVerdict(victim, now); got != checks.PeerForged && got != checks.PeerUnknown {
			t.Fatalf("joined prefix %q left verdict %v", prefix, got)
		}
	})
}
