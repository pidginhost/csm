package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

func lossWatcher(t *testing.T) (*LogWatcher, string, *int) {
	t.Helper()
	t.Cleanup(checks.ResetWebPeersForTest())
	path := filepath.Join(t.TempDir(), "peer.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	resets := new(int)
	spec := newWebPeerLog().spec(path)
	spec.reset = func() {
		*resets++
		checks.MarkWebPeerLoss(time.Now())
	}
	w, err := newObservedLogWatcher(spec, &config.Config{}, make(chan alert.Finding, 16))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	// Model a watcher that has already been running through a full window.
	checks.ResetWebPeersForTest()
	*resets = 0
	return w, path, resets
}

func TestWebPeerUnreadableLinesMarkLoss(t *testing.T) {
	for name, line := range map[string]string{
		"malformed":     "not a peer line",
		"parser bound":  strings.Repeat("x", 513),
		"watcher bound": strings.Repeat("x", logWatcherMaxLineBytes+1),
		"blank":         "",
	} {
		t.Run(name, func(t *testing.T) {
			w, path, _ := lossWatcher(t)
			client := netip.MustParseAddr("192.0.2.10")
			at := time.Now().Add(-time.Minute)
			checks.ObserveWebPeer(at, client, client, &config.Config{})
			appendLine(t, path, line)
			w.readNewLines()
			if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
				t.Fatalf("after unreadable line: %v, want unknown", got)
			}
		})
	}
}

func TestWebPeerResetOnlyOnChangedFile(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(fmt.Sprint(populated), func(t *testing.T) {
			w, path, resets := lossWatcher(t)
			if populated {
				for range 10 {
					appendLine(t, path, peerLine(time.Now(), "site.example", "192.0.2.10", "192.0.2.10"))
					w.readNewLines()
				}
			}
			for range 3 {
				w.reopen()
				w.readNewLines()
			}
			if *resets != 0 {
				t.Fatalf("unchanged file reset %d times", *resets)
			}
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			w.readNewLines()
			if *resets != 2 {
				t.Fatalf("rotation reset %d times, want detection and reopen resets", *resets)
			}
			w.reopen()
			if *resets != 2 {
				t.Fatalf("unchanged replacement reset again: %d", *resets)
			}
		})
	}
}

func TestWebPeerTruncateDoesNotEmptyReplacement(t *testing.T) {
	w, path, _ := lossWatcher(t)
	appendLine(t, path, peerLine(time.Now(), "site.example", "192.0.2.10", "192.0.2.10"))
	w.readNewLines()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	replacement := peerLine(time.Now(), "site.example", "192.0.2.11", "192.0.2.10") + "\n"
	if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	w.truncateAt = 1
	w.truncateIfFull()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != replacement {
		t.Fatalf("replacement lost: %q, %v", got, err)
	}
	if got := checks.WebPeerVerdict(netip.MustParseAddr("192.0.2.10"), time.Now()); got != checks.PeerUnknown {
		t.Fatalf("replacement detected during truncation left verdict %v", got)
	}
}

func TestWebPeerRewriteDuringReadMarksLoss(t *testing.T) {
	w, path, resets := lossWatcher(t)
	at := time.Now().Add(-time.Minute)
	client := netip.MustParseAddr("192.0.2.10")
	direct := peerLine(at, "site.example", client.String(), client.String())
	forged := peerLine(at, "site.example", "192.0.2.11", client.String())
	handler := w.handler
	w.handler = func(line string, cfg *config.Config) []alert.Finding {
		got := handler(line, cfg)
		// The old bytes are already buffered. The writer truncates and appends
		// a different record at the same position before the marker is saved.
		if err := os.WriteFile(path, []byte(forged+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return got
	}
	appendLine(t, path, direct)
	w.readNewLines()
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown || *resets == 0 {
		t.Fatalf("rewrite during read: verdict %v, resets %d", got, *resets)
	}
}

func TestWebPeerAlertDedupUsesEmissionTime(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	p := newWebPeerLog()
	at := time.Now()
	for i, stamp := range []time.Time{at.Add(-2 * time.Hour), at} {
		got := p.handle(peerLine(stamp, "site.example", "192.0.2.11", "192.0.2.10"), &config.Config{})
		want := 0
		if i == 0 {
			want = 1
		}
		if len(got) != want {
			t.Fatalf("line %d emitted %d alerts, want %d", i, len(got), want)
		}
	}
}

func TestWebPeerAlertDedupBound(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	p := newWebPeerLog()
	at := time.Now()
	p.now = func() time.Time { return at }
	for i := range webPeerAlertMaxVhosts + 1 {
		if got := p.due(fmt.Sprintf("site%d.example", i), at); got != (i < webPeerAlertMaxVhosts) {
			t.Fatalf("host %d: due = %v", i, got)
		}
	}
	if len(p.alertedAt) != webPeerAlertMaxVhosts {
		t.Fatalf("dedup retained %d hosts, want %d", len(p.alertedAt), webPeerAlertMaxVhosts)
	}
	client := netip.MustParseAddr("192.0.2.10")
	if got := p.handle(peerLine(at, "overflow.example", "192.0.2.11", client.String()), &config.Config{}); len(got) != 0 {
		t.Fatalf("saturated dedup emitted %+v", got)
	}
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerForged {
		t.Fatalf("saturated dedup suppressed classification: %v", got)
	}
	if p.due("site0.example", at.Add(time.Minute)) {
		t.Fatal("overflow evicted a live dedup entry")
	}
	if !p.due("new.example", at.Add(time.Hour)) {
		t.Fatal("expired dedup entries did not release capacity")
	}
}

// The reset brackets destructive writes, including appends by an O_APPEND
// writer after the size check. Lost records may only cost unknown verdicts.
func TestWebPeerTruncationMarksLossBeforeDiscard(t *testing.T) {
	w, path, _ := lossWatcher(t)
	at := time.Now().Add(-time.Minute)
	client := netip.MustParseAddr("192.0.2.10")
	appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
	w.readNewLines()
	resets := 0
	w.onReset = func() {
		resets++
		checks.MarkWebPeerLoss(time.Now())
		if resets == 1 {
			info, err := os.Stat(path)
			if err != nil || info.Size() == 0 {
				t.Errorf("loss was marked after truncating: %v, %v", info, err)
			}
			appendLine(t, path, peerLine(at, "site.example", "192.0.2.11", client.String()))
		}
	}
	w.truncateAt = 1
	w.truncateIfFull()
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
		t.Fatalf("lost append left verdict %v", got)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("log after truncation: %v, %v", info, err)
	}
	w.truncateAt = 0
	appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
	w.readNewLines()
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
		t.Fatalf("append after truncation left verdict %v", got)
	}
}

func TestWebPeerShrinkThenRegrowDuringReopenMarksLoss(t *testing.T) {
	w, path, resets := lossWatcher(t)
	at := time.Now().Add(-time.Minute)
	client := netip.MustParseAddr("192.0.2.10")
	line := peerLine(at, "site.example", client.String(), client.String())
	appendLine(t, path, line)
	w.readNewLines()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	w.open = func(path string) (*os.File, error) {
		// A new request can regenerate exactly the old marker. The initial
		// observation of a smaller file must still invalidate the window.
		appendLine(t, path, line)
		return os.Open(path)
	}
	w.readNewLines()
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown || *resets == 0 {
		t.Fatalf("shrink/regrow: verdict %v, resets %d", got, *resets)
	}
}

func TestWebPeerMissingPathAndPartialLineMarkLoss(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			w, path, _ := lossWatcher(t)
			at := time.Now().Add(-time.Minute)
			client := netip.MustParseAddr("192.0.2.10")
			appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
			w.readNewLines()
			if missing {
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
			} else {
				appendLog(t, path, "incomplete record")
			}
			w.readNewLines()
			if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
				t.Fatalf("unreadable log left verdict %v", got)
			}
		})
	}
}

// A complete-looking suffix of the startup line must not enter the index.
func TestWebPeerUnframedSuffixDoesNotBecomeEvidence(t *testing.T) {
	w, path, _ := lossWatcher(t)
	w.unframed = true
	handled := 0
	handler := w.handler
	w.handler = func(line string, cfg *config.Config) []alert.Finding {
		handled++
		return handler(line, cfg)
	}
	at := time.Now()
	line := peerLine(at, "site.example", "192.0.2.10", "192.0.2.10")
	appendLine(t, path, line)
	w.readNewLines()
	if handled != 0 {
		t.Fatalf("unframed suffix reached handler %d times", handled)
	}
	appendLine(t, path, line)
	w.readNewLines()
	if handled != 1 {
		t.Fatalf("next complete record reached handler %d times, want one", handled)
	}
}

func TestWebPeerRotationBackDuringReopenMarksLoss(t *testing.T) {
	w, path, resets := lossWatcher(t)
	at := time.Now().Add(-time.Minute)
	client := netip.MustParseAddr("192.0.2.10")
	appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
	w.readNewLines()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	line := peerLine(at, "site.example", "192.0.2.11", client.String())
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.open = func(path string) (*os.File, error) {
		if err := os.Rename(path, path+".replacement"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".old", path); err != nil {
			t.Fatal(err)
		}
		return os.Open(path)
	}
	w.readNewLines()
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown || *resets == 0 {
		t.Fatalf("rotation back: verdict %v, resets %d", got, *resets)
	}
}

func TestWebPeerShrinkDuringCapCheckMarksLoss(t *testing.T) {
	w, path, _ := lossWatcher(t)
	at := time.Now().Add(-time.Minute)
	client := netip.MustParseAddr("192.0.2.10")
	appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
	w.readNewLines()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	w.truncateAt = 1
	w.truncateIfFull()
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
		t.Fatalf("cap check saw shrink but kept verdict %v", got)
	}
}
