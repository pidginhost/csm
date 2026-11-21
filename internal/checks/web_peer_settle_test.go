package checks

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestSettledPeerReadMustStartAfterDeadline(t *testing.T) {
	withWebPeers(t, 500000)
	now := time.Unix(1795200000, 0)
	at := now
	client := netip.MustParseAddr("203.0.113.80")
	cfg := &config.Config{}
	ObserveWebPeer(at.Add(-time.Minute), client, client, cfg)
	webPeerClock = func() time.Time { return now }
	webPeerSleep = func(d time.Duration) { t.Fatalf("unexpected sleep %v after slow read", d) }
	reads := 0
	SetWebPeerDrain(func(time.Duration) bool {
		reads++
		if reads == 1 {
			// The reader reached EOF before the flush, but returned after the deadline.
			now = now.Add(webPeerSettle)
		} else {
			ObserveWebPeer(at, netip.MustParseAddr("192.0.2.80"), client, cfg)
		}
		return true
	})
	if got := settledWebPeerVerdict(client, at, at); got != PeerForged || reads != 2 {
		t.Fatalf("verdict %v after %d reads, want forged after two reads", got, reads)
	}
}

func TestSettledPeerInvalidReadTimeCannotProveDirect(t *testing.T) {
	for _, seen := range []time.Time{{}, time.Unix(1795200000, 0).Add(24 * time.Hour)} {
		t.Run(seen.String(), func(t *testing.T) {
			withWebPeers(t, 500000)
			now := time.Unix(1795200000, 0)
			client := netip.MustParseAddr("203.0.113.81")
			ObserveWebPeer(now, client, client, &config.Config{})
			webPeerClock = func() time.Time { return now }
			webPeerSleep = func(d time.Duration) { t.Errorf("invalid time caused a wait of %v", d) }
			if got := settledWebPeerVerdict(client, now, seen); got != PeerUnknown {
				t.Fatalf("verdict = %v, want unknown for an invalid read time", got)
			}
		})
	}
}

func TestSettledPeerBatchSharesDeadline(t *testing.T) {
	withWebPeers(t, 500000)
	now := time.Unix(1795200000, 0)
	at := now
	client := netip.MustParseAddr("203.0.113.82")
	ObserveWebPeer(at, client, client, &config.Config{})
	webPeerClock = func() time.Time { return now }
	var waited time.Duration
	webPeerSleep = func(d time.Duration) { waited += d; now = now.Add(d) }
	reads := 0
	SetWebPeerDrain(func(time.Duration) bool { reads++; return true })
	for i := 0; i < 10; i++ {
		if got := settledWebPeerVerdict(client, at, at); got != PeerDirect {
			t.Fatalf("finding %d: %v, want direct", i, got)
		}
	}
	if waited != webPeerSettle || reads != 11 {
		t.Fatalf("batch waited %v over %d reads, want %v over 11 reads", waited, reads, webPeerSettle)
	}
}

func TestSettledPeerRejectsReplacedReader(t *testing.T) {
	withWebPeers(t, 500000)
	now := time.Unix(1795200000, 0)
	client := netip.MustParseAddr("203.0.113.83")
	ObserveWebPeer(now, client, client, &config.Config{})
	webPeerClock = func() time.Time { return now }
	reads := 0
	SetWebPeerDrain(func(time.Duration) bool { reads++; return true })
	webPeerSleep = func(time.Duration) { SetWebPeerDrain(func(time.Duration) bool { return false }) }
	if got := settledWebPeerVerdict(client, now, now); got != PeerUnknown {
		t.Fatalf("verdict = %v from replaced reader after %d reads, want unknown", got, reads)
	}
}

func TestWebPeerDrainConcurrentRegistration(t *testing.T) {
	withWebPeers(t, 500000)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				SetWebPeerDrain(func(time.Duration) bool { return false })
				if got := settledWebPeerVerdict(netip.MustParseAddr("203.0.113.91"), time.Now(), time.Now()); got != PeerUnknown {
					t.Errorf("verdict = %v, want unknown", got)
				}
			}
		}()
	}
	wg.Wait()
}

func TestSettledPeerFinalRefusalsDoNotDrain(t *testing.T) {
	for _, class := range []PeerVerdict{PeerUnknown, PeerProxied, PeerForged} {
		t.Run(class.String(), func(t *testing.T) {
			withWebPeers(t, 500000)
			withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: platform.WSLiteSpeed})
			at := time.Unix(1795200000, 0)
			client := netip.MustParseAddr("203.0.113.94")
			if class != PeerUnknown {
				webPeers.observe(at, client, class)
			}
			reads, waits := 0, 0
			SetWebPeerDrain(func(time.Duration) bool { reads++; return true })
			webPeerSleep = func(time.Duration) { waits++ }
			if got := settledWebPeerVerdict(client, at, at); got != class {
				t.Fatalf("got %v, want %v", got, class)
			}
			// A forged or proxied verdict needs no read. An unknown one reads
			// the log once, since the request's own line may be waiting, and
			// never sits out the settle period for a final refusal.
			wantReads := 0
			if class == PeerUnknown {
				wantReads = 1
			}
			if reads != wantReads || waits != 0 {
				t.Fatalf("%v: %d reads and %d waits, want %d reads and no wait", class, reads, waits, wantReads)
			}
		})
	}
}
