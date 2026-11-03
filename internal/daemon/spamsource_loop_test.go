package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/store"
	bolt "go.etcd.io/bbolt"
)

const (
	spamMsgA = "1xF5ol-00000000SdK-2TMA"
	spamMsgB = "1xF5ol-00000000SdK-2TMB"
)

// scanMarker renders the marker CSM's scan hook logs for one delivery.
func scanMarker(mode, policy string, score int, decision, msgID, ip string) string {
	action := map[string]string{"reject": "reject", "tag": "add header"}[decision]
	if action == "" {
		action = "no action"
	}
	return fmt.Sprintf("2026-10-13 09:00:00 %s CSM-ANTISPAM event=scan mode=%s policy=%s result=ok score=%d action=%q decision=%s ip=%s",
		msgID, mode, policy, score, action, decision, ip)
}

func rejectMarker(ip string) string { return scanMarker("enforce", "on", 200, "reject", spamMsgA, ip) }

func TestSpamSourceObservation(t *testing.T) {
	as := config.AntispamConfig{Enabled: true, RejectScore: 15, TagScore: 6}
	const ip = "198.51.100.7"
	cases := []struct {
		name          string
		line          string
		reject, clean bool
	}{
		{"enforce reject", scanMarker("enforce", "on", 200, "reject", spamMsgA, ip), true, false},
		{"dry-run reject", scanMarker("dry-run", "on", 200, "reject", spamMsgA, ip), true, false},
		{"tagged", scanMarker("enforce", "on", 100, "tag", spamMsgA, ip), false, false},
		{"clean", scanMarker("enforce", "on", 50, "none", spamMsgA, ip), false, true},
		{"just below the tag score", scanMarker("enforce", "on", 59, "none", spamMsgA, ip), false, true},
		{"at the tag score", scanMarker("enforce", "on", 60, "none", spamMsgA, ip), false, false},
		{"clean with filtering off", scanMarker("enforce", "off", 50, "unfiltered", spamMsgA, ip), false, true},
		{"spam with filtering off", scanMarker("enforce", "off", 200, "unfiltered", spamMsgA, ip), false, false},
		{"failed scan", evidencePrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none ip=` + ip, false, false},
	}
	for _, tc := range cases {
		s, ok := antispam.ParseScan(tc.line)
		if !ok {
			t.Fatalf("%s: marker did not parse", tc.name)
		}
		if reject, clean := spamSourceObservation(s, as); reject != tc.reject || clean != tc.clean {
			t.Errorf("%s: reject=%v clean=%v, want %v %v", tc.name, reject, clean, tc.reject, tc.clean)
		}
	}
}

// sharedSenderRoots is every provider the shared-sender guard needs before it
// is ready, with the SPF root its cache must record.
var sharedSenderRoots = map[string]string{
	"amazonses": "amazonses.com",
	"brevo":     "spf.brevo.com",
	"google":    "_spf.google.com",
	"icloud":    "icloud.com",
	"mailgun":   "mailgun.org",
	"microsoft": "spf.protection.outlook.com",
	"sendgrid":  "sendgrid.net",
	"yahoo":     "yahoo.com",
}

// writeSharedSenders writes the shared-sender cache resolved at now: google
// sends from 203.0.113.0/24 and yahoo names its hosts under mail.example.net.
func writeSharedSenders(t *testing.T, statePath string, now time.Time) {
	t.Helper()
	type entry struct {
		Root       string   `json:"root"`
		ResolvedAt int64    `json:"resolved_at"`
		Nets       []string `json:"nets"`
		PTR        []string `json:"ptr"`
	}
	providers := make(map[string]entry, len(sharedSenderRoots))
	for name, root := range sharedSenderRoots {
		providers[name] = entry{Root: root, ResolvedAt: now.Unix(), Nets: []string{"192.0.2.254/32"}, PTR: []string{}}
	}
	providers["google"] = entry{Root: sharedSenderRoots["google"], ResolvedAt: now.Unix(), Nets: []string{"203.0.113.0/24"}, PTR: []string{}}
	providers["yahoo"] = entry{Root: sharedSenderRoots["yahoo"], ResolvedAt: now.Unix(), Nets: []string{}, PTR: []string{"mail.example.net"}}
	data, err := json.Marshal(map[string]any{"version": 1, "providers": providers})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, sharedSendersCacheFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dnsNotFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

var dnsServfail = &net.DNSError{Err: "server misbehaving", Name: "example.net", Server: "192.0.2.53:53", IsTemporary: true}

// spamDNS answers from its maps; a missing name is not found. The spam source
// loop queries it from its own goroutine, so tests change it under mu. fail,
// when set, fails every lookup. held, when set before the daemon starts,
// holds each PTR lookup until its context ends and reports why it ended.
type spamDNS struct {
	mu    sync.Mutex
	txt   map[string][]string
	ptr   map[string][]string
	fwd   map[string][]net.IP
	fail  error
	calls []string
	held  chan error
}

func (f *spamDNS) start(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	if f.fail != nil {
		return f.fail
	}
	return ctx.Err()
}

func (f *spamDNS) set(fn func(*spamDNS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *spamDNS) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *spamDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := f.start(ctx, "txt:"+name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, dnsNotFound(name)
}

func (f *spamDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := f.start(ctx, "ptr:"+addr); err != nil {
		return nil, err
	}
	if f.held != nil {
		<-ctx.Done()
		f.held <- ctx.Err()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.ptr[addr]; ok {
		return v, nil
	}
	return nil, dnsNotFound(addr)
}

func (f *spamDNS) LookupIP(ctx context.Context, _, host string) ([]net.IP, error) {
	if err := f.start(ctx, "ip:"+host); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.fwd[host]; ok {
		return v, nil
	}
	return nil, dnsNotFound(host)
}

// useSpamStore makes a fresh state database the global store until the test
// ends.
func useSpamStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

// spamSourceConfig opts a node into spam reports with a shared-sender list in
// its state path that is ready now.
func spamSourceConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("CSM_REPORT_HMAC", "shared-secret")
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.Report.Enabled = true
	cfg.Reputation.Report.Classes = []string{"spam"}
	cfg.Reputation.Report.SpoolPath = filepath.Join(t.TempDir(), "abuse.db")
	cfg.Reputation.Report.Targets = []reportTargetConfig{{
		Name: "priv", URL: "https://collector.example/report", Transport: "hmac",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_REPORT_HMAC",
	}}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, RejectScore: 15, TagScore: 6}
	writeSharedSenders(t, cfg.StatePath, time.Now())
	return cfg
}

// startSpamDaemon starts abuse reporting the way Run does and stops it when
// the test ends.
func startSpamDaemon(t *testing.T, cfg *config.Config, dns *spamDNS) *Daemon {
	t.Helper()
	reportEveryAddress(t)
	prevHook := alert.ReportHook
	t.Cleanup(func() { alert.SetReportHook(prevHook) })
	d := New(cfg, nil, nil, "")
	d.spamSourceDNS = dns
	if loop := d.startAbuseReporting(); loop != nil {
		go loop()
	}
	t.Cleanup(d.stopAbuseReporting)
	return d
}

func eximAt(d *Daemon, cfg *config.Config, line string, at time.Time) {
	d.handleEximLine(line, alert.Observation{ObservedAt: at}, cfg)
}

// spamFindings waits until every goroutine in the bubble is blocked, so the
// spam source loop has handled every candidate, and drains what it raised.
func spamFindings(d *Daemon) []alert.Finding {
	synctest.Wait()
	var out []alert.Finding
	for {
		select {
		case f := <-d.alertCh:
			out = append(out, f)
		default:
			return out
		}
	}
}

func wantSpamFinding(t *testing.T, got []alert.Finding, ip string, at time.Time) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want one for %s", got, ip)
	}
	f := got[0]
	if f.Check != "mail_spam_source" || f.Severity != alert.High || f.SourceIP != ip || !f.Timestamp.Equal(at) ||
		f.Message != "Mail server repeatedly rejected as spam with no recent clean mail: "+ip {
		t.Fatalf("finding = %+v, want High mail_spam_source for %s at %v", f, ip, at)
	}
}

// wgIdle reports whether nothing runs under the daemon's wait group.
func wgIdle(d *Daemon) bool {
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	synctest.Wait()
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func TestSpamSourceRaisedAfterTwoOccasions(t *testing.T) {
	for _, withADB := range []bool{true, false} {
		t.Run(fmt.Sprintf("attack DB %v", withADB), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				useSpamStore(t)
				prev := attackdb.Global()
				t.Cleanup(func() { attackdb.SetGlobal(prev) })
				attackdb.SetGlobal(nil)
				if withADB {
					attackdb.SetGlobal(attackdb.NewForTest(nil))
				}
				cfg := spamSourceConfig(t)
				// Spam evidence waits for the local IP map's first write; the
				// detector reads the raw marker and does not.
				cfg.EmailProtection.Antispam.Feeds.Enabled = []string{antispam.FeedCSMIPMap}
				d := startSpamDaemon(t, cfg, &spamDNS{})
				const ip = "198.51.100.7"
				base := time.Now()

				eximAt(d, cfg, rejectMarker(ip), base)
				if got := spamFindings(d); len(got) != 0 {
					t.Fatalf("one occasion raised %+v", got)
				}
				eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
				wantSpamFinding(t, spamFindings(d), ip, base.Add(2*time.Hour))
				eximAt(d, cfg, rejectMarker(ip), base.Add(4*time.Hour))
				if got := spamFindings(d); len(got) != 0 {
					t.Fatalf("a reject inside the throttle raised %+v", got)
				}
			})
		})
	}
}

// One message split into deliveries with different queue IDs is one
// occasion; the next occasion an hour later is the second.
func TestSpamSourceSplitDeliveryCountsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{})
		const ip = "198.51.100.8"
		base := time.Now()

		eximAt(d, cfg, scanMarker("enforce", "on", 200, "reject", spamMsgA, ip), base)
		eximAt(d, cfg, scanMarker("enforce", "on", 200, "reject", spamMsgB, ip), base.Add(2*time.Minute))
		if got := spamFindings(d); len(got) != 0 {
			t.Fatalf("one split message raised %+v", got)
		}
		eximAt(d, cfg, rejectMarker(ip), base.Add(time.Hour))
		wantSpamFinding(t, spamFindings(d), ip, base.Add(time.Hour))
	})
}

func TestSpamSourceOffWithoutPrerequisites(t *testing.T) {
	cases := []struct {
		name    string
		off     func(*config.Config)
		noStore bool
	}{
		{name: "no spam class", off: func(c *config.Config) { c.Reputation.Report.Classes = []string{"bruteforce"} }},
		{name: "reporting disabled", off: func(c *config.Config) { c.Reputation.Report.Enabled = false }},
		{name: "antispam disabled", off: func(c *config.Config) { c.EmailProtection.Antispam.Enabled = false }},
		{name: "no store", off: func(*config.Config) {}, noStore: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				if tc.noStore {
					prev := store.Global()
					store.SetGlobal(nil)
					t.Cleanup(func() { store.SetGlobal(prev) })
				} else {
					useSpamStore(t)
				}
				cfg := spamSourceConfig(t)
				tc.off(cfg)
				d := startSpamDaemon(t, cfg, &spamDNS{})
				if d.spamSources.Load() != nil {
					t.Fatal("spam source runner started")
				}
				if !wgIdle(d) {
					t.Fatal("a goroutine runs under the daemon wait group")
				}
				base := time.Now()
				eximAt(d, cfg, rejectMarker("198.51.100.9"), base)
				eximAt(d, cfg, rejectMarker("198.51.100.9"), base.Add(2*time.Hour))
				if got := spamFindings(d); len(got) != 0 {
					t.Fatalf("raised %+v", got)
				}
			})
		})
	}
}

// spooledReports reads every report queued in the spool at path.
func spooledReports(t *testing.T, path string) []reporting.Report {
	t.Helper()
	spool, err := reporting.NewSpool(path, "reports", 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spool.Close() }()
	var out []reporting.Report
	if _, err := spool.Drain(func(_ string, body []byte) error {
		var r reporting.Report
		if err := json.Unmarshal(body, &r); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSpamSourceSkipsSharedSenders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		dns := &spamDNS{
			ptr: map[string][]string{"198.51.100.20": {"mx1.mail.example.net."}},
			fwd: map[string][]net.IP{"mx1.mail.example.net.": {net.ParseIP("198.51.100.20")}},
		}
		d := startSpamDaemon(t, cfg, dns)
		base := time.Now()
		for _, ip := range []string{"203.0.113.9", "198.51.100.20"} {
			eximAt(d, cfg, rejectMarker(ip), base)
			eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
		}
		if got := spamFindings(d); len(got) != 0 {
			t.Fatalf("shared senders raised %+v", got)
		}
		// The prefix needs no DNS; the ptr host is confirmed forward.
		if got, want := dns.lookups(), []string{"ptr:198.51.100.20", "ip:mx1.mail.example.net."}; !slices.Equal(got, want) {
			t.Fatalf("lookups = %v, want %v", got, want)
		}

		for _, ip := range []string{"203.0.113.9", "198.51.100.7"} {
			alert.ReportHook(spamSourceFinding(spamCandidate{IP: netip.MustParseAddr(ip), At: base}))
		}
		d.stopAbuseReporting()
		got := spooledReports(t, cfg.Reputation.Report.SpoolPath)
		if len(got) != 1 || got[0].IP != "198.51.100.7" || got[0].Class != reporting.ClassSpam {
			t.Fatalf("spooled reports = %+v, want one spam report for 198.51.100.7", got)
		}
	})
}

// A shared-service sender takes no tracker slot once the guard is ready.
// While it is not ready no sender can be told apart, so every one is tracked.
// Neither case changes what is reported.
func TestSpamSourceTracksProviderSendersOnlyWhileGuardNotReady(t *testing.T) {
	const provider, other = "203.0.113.9", "198.51.100.7"
	for _, ready := range []bool{true, false} {
		t.Run(fmt.Sprintf("guard ready %v", ready), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				useSpamStore(t)
				cfg := spamSourceConfig(t)
				if !ready {
					if err := os.Remove(filepath.Join(cfg.StatePath, sharedSendersCacheFile)); err != nil {
						t.Fatal(err)
					}
				}
				dns := &spamDNS{}
				d := startSpamDaemon(t, cfg, dns)
				base := time.Now()
				for _, ip := range []string{provider, other} {
					eximAt(d, cfg, rejectMarker(ip), base)
					eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
				}
				got := spamFindings(d)

				tracked := d.spamSources.Load().tracker.snapshot()
				if _, ok := tracked[provider]; ok == ready {
					t.Errorf("provider sender tracked = %v, want %v", ok, !ready)
				}
				if _, ok := tracked[other]; !ok {
					t.Errorf("other sender not tracked: %v", tracked)
				}
				if !ready {
					if len(got) != 0 || len(dns.lookups()) != 0 {
						t.Fatalf("an unready guard raised %+v after lookups %v", got, dns.lookups())
					}
					return
				}
				wantSpamFinding(t, got, other, base.Add(2*time.Hour))
				if got, want := dns.lookups(), []string{"ptr:" + other}; !slices.Equal(got, want) {
					t.Fatalf("lookups = %v, want %v", got, want)
				}
			})
		})
	}
}

// The detector answers the reputation check about its shared mail service
// list: no answer before its first refresh attempt ends, stale after a failed
// one, current once the list is ready. Stopped, it gives no answer, so a scan
// during shutdown keeps a warning as it is.
func TestSpamSourceSharedSendersHealth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		if err := os.Remove(filepath.Join(cfg.StatePath, sharedSendersCacheFile)); err != nil {
			t.Fatal(err)
		}
		dns := &spamDNS{fail: dnsServfail}
		t.Cleanup(func() { checks.SetSharedSendersHealth(nil) })
		d := startSpamDaemon(t, cfg, dns)
		health := func() checks.SharedSendersHealth { return checks.SharedSendersHealthAt(time.Now()) }

		if got := health(); got != checks.SharedSendersUnknown {
			t.Fatalf("before the first refresh: health %v, want unknown", got)
		}
		time.Sleep(mailRangesStartupDelay)
		synctest.Wait()
		if got := health(); got != checks.SharedSendersStale {
			t.Fatalf("after a failed refresh: health %v, want stale", got)
		}
		dns.set(func(f *spamDNS) {
			f.fail = nil
			f.txt = make(map[string][]string, len(sharedSenderRoots))
			for name, root := range sharedSenderRoots {
				f.txt[root] = []string{"v=spf1 ptr:" + name + ".example.net -all"}
			}
		})
		time.Sleep(spamSourceRetryAfter)
		synctest.Wait()
		if got := health(); got != checks.SharedSendersOK {
			t.Fatalf("after a good refresh: health %v, want current", got)
		}
		d.stopAbuseReporting()
		if got := health(); got != checks.SharedSendersUnknown {
			t.Fatalf("after stop: health %v, want unknown", got)
		}
	})
}

// A list that is ready at start, or a node without spam source detection,
// answers current at once, so a warning left from an earlier run clears.
func TestSpamSourceSharedSendersHealthCurrent(t *testing.T) {
	for name, edit := range map[string]func(*config.Config){
		"ready list":     func(*config.Config) {},
		"spam class off": func(c *config.Config) { c.Reputation.Report.Classes = []string{"bruteforce"} },
		"reporting off":  func(c *config.Config) { c.Reputation.Report.Enabled = false },
		"antispam off":   func(c *config.Config) { c.EmailProtection.Antispam.Enabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				useSpamStore(t)
				cfg := spamSourceConfig(t)
				edit(cfg)
				t.Cleanup(func() { checks.SetSharedSendersHealth(nil) })
				startSpamDaemon(t, cfg, &spamDNS{})
				if got := checks.SharedSendersHealthAt(time.Now()); got != checks.SharedSendersOK {
					t.Fatalf("health %v, want current", got)
				}
			})
		})
	}
}

func TestSpamSourceFailsClosed(t *testing.T) {
	t.Run("PTR lookup fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			useSpamStore(t)
			cfg := spamSourceConfig(t)
			dns := &spamDNS{fail: dnsServfail}
			d := startSpamDaemon(t, cfg, dns)
			const ip = "198.51.100.30"
			base := time.Now()

			eximAt(d, cfg, rejectMarker(ip), base)
			eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
			if got := spamFindings(d); len(got) != 0 {
				t.Fatalf("a failed PTR lookup raised %+v", got)
			}
			if got := dns.lookups(); !slices.Equal(got, []string{"ptr:" + ip}) {
				t.Fatalf("lookups = %v, want the one failed PTR lookup", got)
			}
			dns.set(func(f *spamDNS) { f.fail = nil })
			eximAt(d, cfg, rejectMarker(ip), base.Add(3*time.Hour))
			wantSpamFinding(t, spamFindings(d), ip, base.Add(3*time.Hour))
		})
	})
	t.Run("guard not ready", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			useSpamStore(t)
			cfg := spamSourceConfig(t)
			if err := os.Remove(filepath.Join(cfg.StatePath, sharedSendersCacheFile)); err != nil {
				t.Fatal(err)
			}
			dns := &spamDNS{fail: dnsServfail}
			d := startSpamDaemon(t, cfg, dns)
			const ip = "198.51.100.31"
			base := time.Now()

			eximAt(d, cfg, rejectMarker(ip), base)
			eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
			if got := spamFindings(d); len(got) != 0 {
				t.Fatalf("an unready guard raised %+v", got)
			}
			if got := dns.lookups(); len(got) != 0 {
				t.Fatalf("an unready guard asked DNS: %v", got)
			}

			// The first refresh waits for the startup delay, then fails, so
			// the guard stays unready.
			time.Sleep(mailRangesStartupDelay - time.Nanosecond)
			synctest.Wait()
			if got := dns.lookups(); len(got) != 0 {
				t.Fatalf("refreshed before the startup delay: %v", got)
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if got := len(dns.lookups()); got != len(sharedSenderRoots) {
				t.Fatalf("first refresh made %d lookups, want one per provider", got)
			}
			eximAt(d, cfg, rejectMarker(ip), base.Add(3*time.Hour))
			if got := spamFindings(d); len(got) != 0 {
				t.Fatalf("a failed refresh raised %+v", got)
			}

			// The retry after the failure makes it ready.
			dns.set(func(f *spamDNS) {
				f.fail = nil
				f.txt = make(map[string][]string, len(sharedSenderRoots))
				for name, root := range sharedSenderRoots {
					f.txt[root] = []string{"v=spf1 ptr:" + name + ".example.net -all"}
				}
			})
			time.Sleep(spamSourceRetryAfter - time.Nanosecond)
			synctest.Wait()
			if got := len(dns.lookups()); got != len(sharedSenderRoots) {
				t.Fatalf("retried before the retry delay: %d lookups, want %d", got, len(sharedSenderRoots))
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			eximAt(d, cfg, rejectMarker(ip), base.Add(4*time.Hour))
			wantSpamFinding(t, spamFindings(d), ip, base.Add(4*time.Hour))
		})
	})
}

// Run waits for d.wg before stopAbuseReporting, so the loop must leave on
// d.stopCh alone, even in the middle of a DNS check.
func TestSpamSourceStopsOnDaemonStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		dns := &spamDNS{held: make(chan error, 1)}
		d := startSpamDaemon(t, cfg, dns)
		const ip = "198.51.100.40"
		base := time.Now()
		eximAt(d, cfg, rejectMarker(ip), base)
		eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
		synctest.Wait()
		if got := dns.lookups(); !slices.Equal(got, []string{"ptr:" + ip}) {
			t.Fatalf("lookups = %v, want the held PTR lookup", got)
		}

		close(d.stopCh)
		if !wgIdle(d) {
			t.Fatal("the spam source loop kept running after the daemon stopped")
		}
		if err := <-dns.held; !errors.Is(err, context.Canceled) {
			t.Fatalf("held lookup ended with %v, want cancellation", err)
		}
		if got := spamFindings(d); len(got) != 0 {
			t.Fatalf("a cancelled check raised %+v", got)
		}
	})
}

func TestSpamSourceSavesEveryTenMinutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := useSpamStore(t)
		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{})
		const ip = "198.51.100.50"
		base := time.Now()
		eximAt(d, cfg, scanMarker("enforce", "on", 20, "none", spamMsgA, ip), base)

		time.Sleep(spamSourceSaveEvery - time.Nanosecond)
		synctest.Wait()
		if got, err := db.LoadSpamSources(); err != nil || len(got) != 0 {
			t.Fatalf("saved before the interval: %v, %v", got, err)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		got, err := db.LoadSpamSources()
		if err != nil || len(got) != 1 || !got[ip].LastClean.Equal(base) {
			t.Fatalf("saved state = %+v, %v; want clean mail from %s at %v", got, err, ip, base)
		}
	})
}

func TestSpamSourceStatePersistsAcrossRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		const clean, throttled, control = "198.51.100.11", "198.51.100.12", "198.51.100.13"
		base := time.Now()

		d := startSpamDaemon(t, cfg, &spamDNS{})
		eximAt(d, cfg, rejectMarker(throttled), base)
		eximAt(d, cfg, rejectMarker(throttled), base.Add(2*time.Hour))
		wantSpamFinding(t, spamFindings(d), throttled, base.Add(2*time.Hour))
		eximAt(d, cfg, scanMarker("enforce", "on", 20, "none", spamMsgA, clean), base)
		d.stopAbuseReporting()

		d = startSpamDaemon(t, cfg, &spamDNS{})
		day := base.Add(24 * time.Hour)
		for _, ip := range []string{clean, control} {
			eximAt(d, cfg, rejectMarker(ip), day)
			eximAt(d, cfg, rejectMarker(ip), day.Add(2*time.Hour))
		}
		eximAt(d, cfg, rejectMarker(throttled), base.Add(4*time.Hour))
		eximAt(d, cfg, rejectMarker(throttled), base.Add(6*time.Hour))
		wantSpamFinding(t, spamFindings(d), control, day.Add(2*time.Hour))
	})
}

// Nothing rewrites the saved state while the detector is off, so a corrupt
// entry that failed the load would keep spam reports off on every restart.
func TestSpamSourceStartsWithCorruptSavedEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const valid, corrupt = "198.51.100.14", "198.51.100.15"
		base := time.Now()
		first := base.Add(-2 * time.Hour)
		saved, err := json.Marshal(store.SpamSource{Occasions: []time.Time{first}, Seen: first})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		raw, err := bolt.Open(filepath.Join(dir, "csm.db"), 0o600, &bolt.Options{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		err = raw.Update(func(tx *bolt.Tx) error {
			b, berr := tx.CreateBucketIfNotExists([]byte("mail:spam_source"))
			if berr != nil {
				return berr
			}
			if perr := b.Put([]byte(valid), saved); perr != nil {
				return perr
			}
			return b.Put([]byte(corrupt), []byte("{not json"))
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = raw.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		prev := store.Global()
		store.SetGlobal(db)
		t.Cleanup(func() {
			store.SetGlobal(prev)
			_ = db.Close()
		})

		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{})
		if d.spamSources.Load() == nil {
			t.Fatal("one corrupt saved entry switched spam source detection off")
		}
		// The saved occasion is the first; this reject is the second.
		eximAt(d, cfg, rejectMarker(valid), base)
		wantSpamFinding(t, spamFindings(d), valid, base)
	})
}

// The detector skips the senders spam evidence skips: whitelisted, the host's
// own, infra_ips and addresses the IP map could never list.
func TestSpamSourceSkipsExcludedSenders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
		checks.GetThreatDB().AddWhitelist("198.51.100.60")
		t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.61")}, nil }))
		cfg := spamSourceConfig(t)
		cfg.InfraIPs = []string{"198.51.100.62/32"}
		d := startSpamDaemon(t, cfg, &spamDNS{})
		base := time.Now()
		for _, ip := range []string{"198.51.100.60", "198.51.100.61", "198.51.100.62", "10.1.2.3", "198.51.100.63"} {
			eximAt(d, cfg, rejectMarker(ip), base)
			eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
		}
		wantSpamFinding(t, spamFindings(d), "198.51.100.63", base.Add(2*time.Hour))
	})
}

// A sender that finds the check queue full ends its check unreported, so its
// next reject is checked again instead of waiting on a check that never runs.
func TestSpamSourceQueueFullEndsTheCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{held: make(chan error, 1)})
		base := time.Now()
		qualify := func(ip string) {
			eximAt(d, cfg, rejectMarker(ip), base)
			eximAt(d, cfg, rejectMarker(ip), base.Add(2*time.Hour))
		}
		// The loop holds this sender's PTR lookup while the queue fills.
		qualify("198.51.100.99")
		synctest.Wait()
		for i := range spamSourceCandidates {
			qualify(fmt.Sprintf("198.51.100.%d", 100+i))
		}
		qualify("198.51.100.200")

		r := d.spamSources.Load()
		inFlight := func(ip string) bool {
			r.tracker.mu.Lock()
			defer r.tracker.mu.Unlock()
			return r.tracker.checking[netip.MustParseAddr(ip)] != nil
		}
		if !inFlight("198.51.100.163") {
			t.Fatal("the last queued sender is not in flight")
		}
		if inFlight("198.51.100.200") {
			t.Fatal("the sender that found the queue full stayed in flight")
		}
	})
}
