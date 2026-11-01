package daemon

import (
	"context"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/sharedsenders"
	"github.com/pidginhost/csm/internal/store"
)

const (
	sharedSendersCacheFile = "shared_senders.json"
	// spamSourceCandidates bounds the senders waiting for their DNS check.
	spamSourceCandidates    = 64
	spamSourceCheckBudget   = 5 * time.Second
	spamSourceRefreshBudget = time.Minute
	spamSourceSaveEvery     = 10 * time.Minute
	spamSourceRetryAfter    = 10 * time.Minute
)

// spamSourceObservation classifies one scan for the detector. It reads the
// marker's own decision and raw score: mail delivered with filtering off
// never counts as a reject, but its clean scans still clear the sender.
func spamSourceObservation(s antispam.Scan, as config.AntispamConfig) (reject, clean bool) {
	if !s.OK {
		return false, false
	}
	return s.Decision == "reject", s.Score < as.TagScore*10
}

type spamCandidate struct {
	IP netip.Addr
	At time.Time
}

// spamSourceRunner checks each sender the tracker qualifies against the
// shared mail services, off the log path, and raises mail_spam_source for the
// rest.
type spamSourceRunner struct {
	tracker    *spamSourceTracker
	guard      *sharedsenders.Guard
	resolver   sharedsenders.Resolver
	candidates chan spamCandidate
	db         *store.DB
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// newSpamSources prepares the detector when the spam class is enabled: it
// loads the saved tracker and the shared-sender cache. It returns nil when the
// detector stays off.
func (d *Daemon) newSpamSources(enabled map[reporting.Class]bool) *spamSourceRunner {
	if !enabled[reporting.ClassSpam] {
		return nil
	}
	if !d.cfg.EmailProtection.Antispam.Enabled {
		log.Printf("abuse-reporting: the spam class needs email_protection.antispam.enabled; spam source detection stays off")
		return nil
	}
	db := store.Global()
	if db == nil {
		log.Printf("abuse-reporting: no state database; spam source detection stays off")
		return nil
	}
	now := time.Now()
	saved, err := db.LoadSpamSources()
	if err != nil {
		// An empty tracker would forget recent clean mail and throttles.
		log.Printf("abuse-reporting: cannot load spam source state: %v; spam source detection stays off", err)
		return nil
	}
	guard := sharedsenders.New(filepath.Join(d.cfg.StatePath, sharedSendersCacheFile))
	if err := guard.Load(now); err != nil {
		log.Printf("abuse-reporting: %v", err)
	}
	if !guard.Ready(now) {
		log.Printf("abuse-reporting: shared mail services not loaded; spam reports wait for a refresh")
	}
	resolver := d.spamSourceDNS
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	r := &spamSourceRunner{
		tracker:    newSpamSourceTracker(spamSourceMaxIPs),
		guard:      guard,
		resolver:   resolver,
		candidates: make(chan spamCandidate, spamSourceCandidates),
		db:         db,
	}
	r.tracker.load(saved, now)
	return r
}

// startSpamSources runs r's loop under d.wg and starts feeding it log lines.
func (d *Daemon) startSpamSources(r *spamSourceRunner) {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	// Run waits for d.wg before stopAbuseReporting, so the daemon stop must
	// also cancel a DNS check in flight.
	go func() {
		select {
		case <-d.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	d.wg.Add(1)
	r.wg.Add(1)
	obs.Go("spam-sources", func() {
		defer d.wg.Done()
		defer r.wg.Done()
		r.run(ctx, d.alertCh)
	})
	d.spamSources.Store(r)
}

// covers is the report gate's shared-sender check. It asks no DNS, so it is
// true for a provider prefix and for every address while the guard is not
// ready.
func (r *spamSourceRunner) covers(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	return !ok || r.guard.Covers(a.Unmap(), time.Now())
}

func (r *spamSourceRunner) run(ctx context.Context, alertCh chan<- alert.Finding) {
	refresh := time.NewTimer(mailRangesStartupDelay)
	defer refresh.Stop()
	save := time.NewTicker(spamSourceSaveEvery)
	defer save.Stop()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case c := <-r.candidates:
			r.check(ctx, alertCh, c)
		case <-save.C:
			r.save()
		case <-refresh.C:
			refresh.Reset(r.refresh(ctx))
		}
	}
}

// check ends the tracker's check for c. A shared or unresolved sender, or a
// full alert queue, raises nothing and starts no throttle, so the sender's
// next reject is checked again.
func (r *spamSourceRunner) check(ctx context.Context, alertCh chan<- alert.Finding, c spamCandidate) {
	ctx, cancel := context.WithTimeout(ctx, spamSourceCheckBudget)
	defer cancel()
	shared := r.guard.Shared(ctx, r.resolver, c.IP, time.Now())
	r.tracker.finish(c.IP, c.At, func() bool {
		return !shared && alert.TryEnqueue(alertCh, spamSourceFinding(c))
	})
}

// refresh resolves the shared mail services again and returns when to run
// next.
func (r *spamSourceRunner) refresh(ctx context.Context) time.Duration {
	ctx, cancel := context.WithTimeout(ctx, spamSourceRefreshBudget)
	defer cancel()
	if err := r.guard.Refresh(ctx, r.resolver, time.Now()); err != nil {
		log.Printf("abuse-reporting: shared mail services refresh: %v", err)
		return spamSourceRetryAfter
	}
	return mailRangesRefreshInterval
}

func (r *spamSourceRunner) save() {
	if err := r.db.SaveSpamSources(r.tracker.snapshot()); err != nil {
		log.Printf("abuse-reporting: saving spam source state: %v", err)
	}
}

// stop ends the loop and saves the tracker. A candidate still queued needs no
// finish: in-flight marks are never saved.
func (r *spamSourceRunner) stop() {
	r.cancel()
	r.wg.Wait()
	r.save()
}

// recordSpamSource feeds one Exim main-log line to the tracker and hands a
// sender that qualifies to the DNS check. It never blocks the log path: with
// the queue full the check ends unreported, and the sender's next reject
// starts another.
func (d *Daemon) recordSpamSource(line string, at time.Time, cfg *config.Config) {
	r := d.spamSources.Load()
	if r == nil || !cfg.EmailProtection.Antispam.Enabled {
		return
	}
	s, ok := antispam.ParseScan(line)
	if !ok || !ipmap.Recordable(s.IP, nil) {
		return
	}
	reject, clean := spamSourceObservation(s, cfg.EmailProtection.Antispam)
	if (!reject && !clean) || d.spamSenderExcluded(s.IP, cfg) {
		return
	}
	if !r.tracker.observe(s.IP, reject, clean, at) {
		return
	}
	select {
	case r.candidates <- spamCandidate{IP: s.IP, At: at}:
	default:
		r.tracker.finish(s.IP, at, func() bool { return false })
	}
}

func spamSourceFinding(c spamCandidate) alert.Finding {
	ip := c.IP.String()
	return alert.Finding{
		Severity:  alert.High,
		Check:     "mail_spam_source",
		Message:   "Mail server repeatedly rejected as spam with no recent clean mail: " + ip,
		SourceIP:  ip,
		Timestamp: c.At,
	}
}
