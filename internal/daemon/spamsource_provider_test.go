package daemon

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/sharedsenders"
	"github.com/pidginhost/csm/internal/store"
)

// forget drops one sender's history, mapped form included, and cancels its
// check in flight without touching any other sender.
func TestSpamSourceTrackerForget(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	other := netip.MustParseAddr("203.0.113.10")
	base := spamSourceBase
	tr := newSpamSourceTracker(2)
	tr.observe(ip, true, false, base)
	if !tr.observe(ip, true, false, base.Add(time.Hour)) {
		t.Fatal("sender did not qualify for a check")
	}
	tr.observe(other, true, false, base)
	tr.forget(netip.MustParseAddr("::ffff:203.0.113.9"))
	tr.forget(netip.MustParseAddr("198.51.100.7"))
	if tr.finish(ip, base.Add(time.Hour), func() bool {
		t.Fatal("a forgotten sender's pending check emitted")
		return true
	}) {
		t.Fatal("pending check finished after forget")
	}
	want := map[string]store.SpamSource{other.String(): {Occasions: []time.Time{base}, Seen: base}}
	if got := tr.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("history = %+v, want %+v", got, want)
	}
	// The cancelled check no longer blocks a new one.
	tr.observe(ip, true, false, base.Add(2*time.Hour))
	if !tr.observe(ip, true, false, base.Add(3*time.Hour)) {
		t.Fatal("a forgotten sender could not qualify again")
	}
}

// spamSourcePendingDNS holds the first PTR lookup until release closes.
type spamSourcePendingDNS struct {
	*spamDNS
	first            sync.Once
	started, release chan struct{}
}

func (r *spamSourcePendingDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	pause := false
	r.first.Do(func() { pause = true })
	if pause {
		close(r.started)
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.spamDNS.LookupAddr(ctx, addr)
}

// A sender forgotten while its check waits on DNS keeps that check until it
// ends, as an evicted sender does, and the check raises nothing. A refresh
// that drops the sender's prefix lets new rejects count again, and the first
// reject after the old check ends starts a new one.
func TestSpamSourceProviderForgetPendingCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := spamSourceConfig(t)
		base := time.Now()
		const ip = "203.0.113.9"
		dns := &spamSourcePendingDNS{
			spamDNS: &spamDNS{txt: make(map[string][]string)},
			started: make(chan struct{}), release: make(chan struct{}),
		}
		for name, root := range sharedSenderRoots {
			dns.txt[root] = []string{"v=spf1 ptr:" + name + ".example.net -all"}
		}
		r := &spamSourceRunner{
			tracker:    newSpamSourceTracker(2),
			guard:      sharedsenders.New(filepath.Join(cfg.StatePath, sharedSendersCacheFile)),
			resolver:   dns,
			candidates: make(chan spamCandidate, spamSourceCandidates),
		}
		d := New(cfg, nil, nil, "")
		d.spamSources.Store(r)
		if err := r.guard.Refresh(context.Background(), dns, base); err != nil {
			t.Fatal(err)
		}
		reject := func(at time.Time) { d.recordSpamSource(scanOf(rejectMarker(ip)), at, cfg) }
		reject(base)
		reject(base.Add(time.Hour))
		old := <-r.candidates
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.check(context.Background(), d.alertCh, old)
		}()
		<-dns.started

		writeSharedSenders(t, cfg.StatePath, base)
		if err := r.guard.Load(base); err != nil {
			t.Fatal(err)
		}
		reject(base.Add(2 * time.Hour))
		if got := r.tracker.snapshot(); len(got) != 0 {
			t.Fatalf("provider history was not forgotten: %+v", got)
		}
		if err := r.guard.Refresh(context.Background(), dns, base); err != nil {
			t.Fatal(err)
		}
		reject(base.Add(3 * time.Hour))
		reject(base.Add(4 * time.Hour))
		if got := len(r.candidates); got != 0 {
			t.Fatalf("queued %d checks while the forgotten check runs", got)
		}

		close(dns.release)
		<-done
		if got := spamFindings(d); len(got) != 0 {
			t.Fatalf("forgotten check raised %+v", got)
		}
		reject(base.Add(5 * time.Hour))
		select {
		case next := <-r.candidates:
			r.check(context.Background(), d.alertCh, next)
		default:
			t.Fatal("the reject after the forgotten check ended started no check")
		}
		wantSpamFinding(t, spamFindings(d), ip, base.Add(5*time.Hour))
	})
}

// A provider sender is never reported, so history kept for it from before the
// guard knew its prefix is released at its next message instead of holding a
// tracker slot.
func TestSpamSourceProviderReleasesSavedHistory(t *testing.T) {
	const ip = "203.0.113.9"
	for name, line := range map[string]string{
		"clean":  scanMarker("enforce", "on", 20, "none", spamMsgA, ip),
		"reject": rejectMarker(ip),
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				db := useSpamStore(t)
				cfg := spamSourceConfig(t)
				base := time.Now()
				saved := base.Add(-2 * time.Hour)
				if err := db.SaveSpamSources(map[string]store.SpamSource{
					ip: {Occasions: []time.Time{saved}, Seen: saved, LastClean: saved},
				}); err != nil {
					t.Fatal(err)
				}
				d := startSpamDaemon(t, cfg, &spamDNS{})
				eximAt(d, cfg, line, base)
				if got := spamFindings(d); len(got) != 0 {
					t.Fatalf("provider sender raised %+v", got)
				}
				if got, ok := d.spamSources.Load().tracker.snapshot()[ip]; ok {
					t.Fatalf("provider sender still holds history %+v", got)
				}
			})
		})
	}
}

// Refresh can publish a policy resolved after a concurrent reader captured
// its time. Neither snapshot identifies this address as a provider sender.
func TestSpamSourceProviderUsesOneSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := time.Now()
		dir := t.TempDir()
		writeSharedSenders(t, dir, base)
		g := sharedsenders.New(filepath.Join(dir, sharedSendersCacheFile))
		if err := g.Load(base); err != nil {
			t.Fatal(err)
		}
		ip := netip.MustParseAddr("198.51.100.7")
		var skipped atomic.Bool
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					if g.ProviderPrefix(ip, time.Now()) {
						skipped.Store(true)
					}
					runtime.Gosched()
				}
			}
		}()
		defer func() {
			close(stop)
			<-done
		}()
		for range 500 {
			for _, at := range []time.Time{base.Add(time.Hour), base} {
				writeSharedSenders(t, dir, at)
				if err := g.Load(base); err != nil {
					t.Fatal(err)
				}
			}
		}
		if skipped.Load() {
			t.Fatal("a sender outside every provider prefix was skipped during refresh")
		}
	})
}

// Clean mail must still clear saved reject history while the sender is
// covered by a provider prefix. A later refresh can remove that prefix.
func TestSpamSourceProviderCleanClearsSavedRejects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := useSpamStore(t)
		cfg := spamSourceConfig(t)
		const ip, control = "203.0.113.9", "198.51.100.7"
		base := time.Now()
		if err := db.SaveSpamSources(map[string]store.SpamSource{
			ip: {Occasions: []time.Time{base.Add(-2 * time.Hour), base.Add(-time.Hour)}, Seen: base.Add(-time.Hour)},
		}); err != nil {
			t.Fatal(err)
		}
		dns := &spamDNS{txt: make(map[string][]string)}
		for name, root := range sharedSenderRoots {
			dns.txt[root] = []string{"v=spf1 ptr:" + name + ".example.net -all"}
		}
		d := startSpamDaemon(t, cfg, dns)
		r := d.spamSources.Load()
		eximAt(d, cfg, scanMarker("enforce", "on", 20, "none", spamMsgA, ip), base)
		if got := spamFindings(d); len(got) != 0 {
			t.Fatalf("provider clean mail raised %+v", got)
		}

		if err := r.guard.Refresh(context.Background(), dns, base); err != nil {
			t.Fatal(err)
		}
		if !r.guard.Ready(base) || r.guard.Covers(netip.MustParseAddr(ip), base) {
			t.Fatal("refreshed guard still covers the former provider sender")
		}
		later := base.Add(time.Hour)
		eximAt(d, cfg, rejectMarker(ip), later)
		eximAt(d, cfg, rejectMarker(control), base)
		eximAt(d, cfg, rejectMarker(control), later)
		wantSpamFinding(t, spamFindings(d), control, later)
		if got := r.tracker.snapshot()[ip].Occasions; !slices.Equal(got, []time.Time{later}) {
			t.Fatalf("former provider sender occasions = %v, want only %v", got, later)
		}
	})
}
