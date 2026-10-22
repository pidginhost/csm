//go:build linux

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSpoolWatcher_DetectsNewHFile(t *testing.T) {
	// inotify works for non-root on tmpfs and the user's own dirs;
	// CI runs as a regular user. Keep the test enabled regardless of euid.
	_ = os.Geteuid()
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	received := make(chan string, 4)
	w, err := newSpoolWatcher(spoolRoot, func(path string) {
		received <- path
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond) // let watcher arm

	target := filepath.Join(sub, "1abc-H")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if got != target {
			t.Errorf("watcher saw %q, want %q", got, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for inotify event")
	}
}

func TestSpoolPipeline_FlowAOnRealFixture(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 2 // tight for test
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)

	udir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(udir, "exampleuser"), 0o755)
	_ = os.WriteFile(filepath.Join(udir, "exampleuser", "main"),
		[]byte("main_domain: example.com\n"), 0o644)
	domains := newUserDomainsResolverWithRoot(udir, time.Minute)

	pol := newTestPolicies(t)

	var findings []alert.Finding
	var fmu sync.Mutex
	pipeline := newSpoolPipeline(eng, domains, pol, nil, nil, func(f alert.Finding) {
		fmu.Lock()
		findings = append(findings, f)
		fmu.Unlock()
	})

	w, err := newSpoolWatcher(spoolRoot, pipeline.OnFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	// Write two attack-shape -H files.
	for i, mid := range []string{"1aaa-H", "1bbb-H"} {
		body := `id-H
exampleuser 1168 982
<exampleuser@cpanel.example.test>
1777409086 0
-local
1
info@example.com

233P Received: from exampleuser by cpanel.example.test
037  Subject: x` + string(rune('0'+i)) + `
132  X-PHP-Script: spoof.example.com/wp-admin/admin-ajax.php for 192.0.2.10
048F From: Spoof <attacker@spoofed.example>
031R Reply-To: attacker@gmail.example
067  X-Mailer: PHPMailer 7.0.0
`
		if err := os.WriteFile(filepath.Join(sub, mid), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fmu.Lock()
		n := len(findings)
		fmu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmu.Lock()
	defer fmu.Unlock()
	if len(findings) == 0 {
		t.Fatal("expected Path 1 finding from two attack -H files")
	}
	if findings[0].Path != "header" {
		t.Errorf("Path = %q, want header", findings[0].Path)
	}
	if findings[0].RelayTotal != 2 {
		t.Errorf("RelayTotal = %d, want 2", findings[0].RelayTotal)
	}
	if len(findings[0].RelayBreakdown) != 1 || findings[0].RelayBreakdown[0].Hits != 2 {
		t.Fatalf("RelayBreakdown = %+v, want one 2-hit script", findings[0].RelayBreakdown)
	}
	if findings[0].RelayBreakdown[0].SampleSubject == "" {
		t.Fatal("RelayBreakdown must carry a sample subject from parsed spool headers")
	}
}

func TestStartupSpoolWalker_DefersFindings(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 1
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)

	udir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(udir, "u"), 0o755)
	_ = os.WriteFile(filepath.Join(udir, "u", "main"), []byte("main_domain: example.com\n"), 0o644)
	domains := newUserDomainsResolverWithRoot(udir, time.Minute)
	pol := newTestPolicies(t)

	var findings []alert.Finding
	var fmu sync.Mutex
	pipeline := newSpoolPipeline(eng, domains, pol, nil, nil, func(f alert.Finding) {
		fmu.Lock()
		findings = append(findings, f)
		fmu.Unlock()
	})

	// Write attack-shape -H file BEFORE the walker runs.
	body := "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: bad.example.com/x.php for 192.0.2.10\n048F From: <attacker@spoofed.example>\n031R Reply-To: attacker@gmail.example\n067  X-Mailer: PHPMailer 7.0.0\n"
	_ = os.WriteFile(filepath.Join(sub, "1zzz-H"), []byte(body), 0o644)

	runStartupSpoolWalker(spoolRoot, pipeline)

	fmu.Lock()
	defer fmu.Unlock()
	if len(findings) == 0 {
		t.Fatal("expected re-evaluation pass to fire after rebuild")
	}
	if pipeline.rebuilding.Load() {
		t.Error("rebuilding flag must be cleared after walker returns")
	}
}

// REL-02: mail queued longer ago than any detection window must not be replayed
// at startup. The old walker stamped every queued -H file time.Now(), so a
// days-old legit queue collapsed into one instant and fabricated a burst.
func TestStartupSpoolWalker_SkipsStaleQueuedMail(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 1
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)

	udir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(udir, "u"), 0o755)
	_ = os.WriteFile(filepath.Join(udir, "u", "main"), []byte("main_domain: example.com\n"), 0o644)
	domains := newUserDomainsResolverWithRoot(udir, time.Minute)
	pol := newTestPolicies(t)

	var findings []alert.Finding
	var fmu sync.Mutex
	pipeline := newSpoolPipeline(eng, domains, pol, nil, nil, func(f alert.Finding) {
		fmu.Lock()
		findings = append(findings, f)
		fmu.Unlock()
	})

	body := "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: bad.example.com/x.php for 192.0.2.10\n048F From: <attacker@spoofed.example>\n031R Reply-To: attacker@gmail.example\n067  X-Mailer: PHPMailer 7.0.0\n"
	f := filepath.Join(sub, "1zzz-H")
	_ = os.WriteFile(f, []byte(body), 0o644)
	// Age the queued message well past any detection window.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(f, old, old); err != nil {
		t.Fatal(err)
	}

	runStartupSpoolWalker(spoolRoot, pipeline)

	fmu.Lock()
	defer fmu.Unlock()
	if len(findings) != 0 {
		t.Fatalf("stale queued mail (mtime 2h ago) must not fire startup findings, got %+v", findings)
	}
}

func TestStartupSpoolWalker_ReplaysCappedFilesChronologically(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)

	udir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(udir, "u"), 0o755)
	_ = os.WriteFile(filepath.Join(udir, "u", "main"), []byte("main_domain: example.com\n"), 0o644)
	domains := newUserDomainsResolverWithRoot(udir, time.Minute)
	pipeline := newSpoolPipeline(eng, domains, newTestPolicies(t), nil, nil, func(alert.Finding) {})

	const extra = 4
	total := phpRelayMaxEventsPerScript + extra
	base := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	body := "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: bad.example.com/x.php for 192.0.2.10\n"
	for i := 0; i < total; i++ {
		f := filepath.Join(sub, fmt.Sprintf("msg%03d-H", i))
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		ts := base.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(f, ts, ts); err != nil {
			t.Fatal(err)
		}
	}

	runStartupSpoolWalker(spoolRoot, pipeline)

	s := psw.getOrCreate(scriptKey("bad.example.com:/x.php"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) != phpRelayMaxEventsPerScript {
		t.Fatalf("recorded events = %d, want %d", len(s.events), phpRelayMaxEventsPerScript)
	}
	wantMin := base.Add(extra * time.Second)
	wantMax := base.Add(time.Duration(total-1) * time.Second)
	gotMin, gotMax := s.events[0].At, s.events[0].At
	for _, ev := range s.events[1:] {
		if ev.At.Before(gotMin) {
			gotMin = ev.At
		}
		if ev.At.After(gotMax) {
			gotMax = ev.At
		}
	}
	if !gotMin.Equal(wantMin) || !gotMax.Equal(wantMax) {
		t.Fatalf("startup replay retained wrong capped window: min=%v max=%v, want min=%v max=%v", gotMin, gotMax, wantMin, wantMax)
	}
}

// REL-02 (unit): a message is attributed to its -H ModTime, not time.Now().
func TestOnFileAt_UsesModTimeAsEventTime(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)

	udir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(udir, "u"), 0o755)
	_ = os.WriteFile(filepath.Join(udir, "u", "main"), []byte("main_domain: example.com\n"), 0o644)
	domains := newUserDomainsResolverWithRoot(udir, time.Minute)
	pol := newTestPolicies(t)

	pipeline := newSpoolPipeline(eng, domains, pol, nil, nil, func(alert.Finding) {})
	pipeline.SetRebuilding(true) // update state only, don't emit

	body := "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: bad.example.com/x.php for 192.0.2.10\n"
	f := filepath.Join(sub, "1yyy-H")
	_ = os.WriteFile(f, []byte(body), 0o644)

	eventTime := time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)
	pipeline.onFileAt(f, eventTime)

	s := psw.getOrCreate(scriptKey("bad.example.com:/x.php"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(s.events))
	}
	if !s.events[0].At.Equal(eventTime) {
		t.Errorf("event stamped at %v, want mtime %v", s.events[0].At, eventTime)
	}
}

func TestOnFileAt_RecordsDistinctScriptRecipientsWithoutSourceIP(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, newPerAccountWindow(5000), cfg, nil)

	userdataRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(userdataRoot, "u"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userdataRoot, "u", "main"), []byte("main_domain: example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	domains := newUserDomainsResolverWithRoot(userdataRoot, time.Minute)
	pipeline := newSpoolPipeline(eng, domains, newTestPolicies(t), newMsgIDIndex(nil, 64), nil, func(alert.Finding) {})
	pipeline.SetRebuilding(true)

	body := "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nadmin@example.com\n\n037T To: admin@example.com\n132  X-PHP-Script: example.com/wp-cron.php\n"
	eventTime := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	for _, msgID := range []string{"1aaa", "1bbb"} {
		path := filepath.Join(sub, msgID+"-H")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		pipeline.onFileAt(path, eventTime)
	}

	state := psw.getOrCreate("example.com:/wp-cron.php")
	if got := state.volumeCount(eventTime.Add(-time.Minute)); got != 2 {
		t.Fatalf("script volume = %d, want 2", got)
	}
	count, known := state.distinctRecipientsSince(eventTime.Add(-time.Minute))
	if count != 1 || !known {
		t.Fatalf("script recipients = (%d,%v), want (1,true)", count, known)
	}
	ipStates := 0
	pip.states.Range(func(_, _ any) bool {
		ipStates++
		return true
	})
	if ipStates != 0 {
		t.Fatalf("per-IP states = %d, want 0 for cron-driven mail", ipStates)
	}
}

func TestRecoveryScan_BoundedAndDedupes(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	// Write 5 -H files; cap recovery at 3.
	for i := 0; i < 5; i++ {
		body := "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: x.example.com/y.php for 192.0.2.1\n"
		_ = os.WriteFile(filepath.Join(sub, fmt.Sprintf("id%d-H", i)), []byte(body), 0o644)
		time.Sleep(5 * time.Millisecond) // ensure distinct mtimes
	}

	var seen []string
	n, truncated := runRecoveryScan(spoolRoot, 3, func(path string) {
		seen = append(seen, path)
	})
	if n != 3 {
		t.Errorf("scanned = %d, want 3", n)
	}
	if !truncated {
		t.Errorf("truncated should be true (5 files, cap 3)")
	}
	if len(seen) != 3 {
		t.Errorf("callbacks = %d, want 3", len(seen))
	}
}

func TestSupervisor_RestartsOnPanic(t *testing.T) {
	var attempts atomic.Int32
	sup := newSpoolSupervisor(func(ctx context.Context) {
		attempts.Add(1)
		if attempts.Load() < 3 {
			panic("simulated")
		}
	}, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("supervisor did not restart enough times: %d", attempts.Load())
}

func TestSupervisor_StopsAfterMaxRestarts(t *testing.T) {
	var attempts atomic.Int32
	var failed atomic.Bool
	sup := newSpoolSupervisor(func(ctx context.Context) {
		attempts.Add(1)
		panic("always fails")
	}, 3)
	sup.OnFailed = func() { failed.Store(true) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.Run(ctx)

	if attempts.Load() > 4 {
		t.Errorf("attempts = %d, want <= 4 (3 restarts + 1 initial)", attempts.Load())
	}
	if !failed.Load() {
		t.Error("OnFailed callback should have fired")
	}
}

// fanoutPipeline wires an evaluator to a spool pipeline whose domain resolver
// knows one cPanel account per site: user<x> owns site-<x>.example.
func fanoutPipeline(t *testing.T, sites ...string) (*spoolPipeline, *[]alert.Finding) {
	t.Helper()
	cfg := defaultPHPRelayCfg()
	eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), newPerAccountWindow(5000), cfg, nil)
	udir := t.TempDir()
	for _, s := range sites {
		dir := filepath.Join(udir, "user"+s)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main"), []byte("main_domain: site-"+s+".example\nsub_domains:\n  - news.site-"+s+".example\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var findings []alert.Finding
	p := newSpoolPipeline(eng, newUserDomainsResolverWithRoot(udir, time.Minute), newTestPolicies(t), nil, nil,
		func(f alert.Finding) { findings = append(findings, f) })
	return p, &findings
}

// feedSiteMail writes one -H file for a script on site-<site>.example reached
// from ip and runs it through the pipeline at the given time.
func feedSiteMail(t *testing.T, p *spoolPipeline, msgID, site, ip string, at time.Time, rcpts ...string) {
	t.Helper()
	body := fmt.Sprintf("id-H\nuser%s 1 1\n<user%s@host.example.test>\n0 0\n-local\n%d\n", site, site, len(rcpts))
	for _, r := range rcpts {
		body += r + "\n"
	}
	body += fmt.Sprintf("\n040  Subject: [Site] Please moderate a comment\n"+
		"070  X-PHP-Script: site-%s.example/wp-comments-post.php for %s\n"+
		"045F From: WordPress <wordpress@site-%s.example>\n", site, ip, site)
	f := filepath.Join(t.TempDir(), msgID+"-H")
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p.onFileAt(f, at)
}

// FP: one client posts comments on several hosted sites; each site mails a
// moderation notice to its own owner. That is many scripts from one IP, but
// the mail stays with the sites' owners, so Path 4 must not report a relay.
func TestOnFileAt_Path4_IgnoresNoticesToSendersOwnDomains(t *testing.T) {
	p, findings := fanoutPipeline(t, "a", "b", "c", "d")
	ip := "203.0.113.7"
	now := time.Unix(1_700_000_000, 0).UTC()

	feedSiteMail(t, p, "m1", "a", ip, now.Add(-4*time.Minute), "admin@site-a.example")
	feedSiteMail(t, p, "m2", "b", ip, now.Add(-3*time.Minute), "admin@site-b.example")
	feedSiteMail(t, p, "m3", "b", ip, now.Add(-3*time.Minute), "author@elsewhere.example")
	feedSiteMail(t, p, "m4", "c", ip, now.Add(-2*time.Minute), "owner@site-c.example")
	feedSiteMail(t, p, "m5", "d", ip, now, "admin@news.site-d.example")

	if fanoutFired(*findings) {
		t.Fatalf("Path 4 must not fire for notices to the sending sites' own domains, got %+v", *findings)
	}
}

// True positive: the same fanout, but the scripts reach recipients outside
// their own account, including another hosted account's domain. Mixing in
// mail to the senders' own domains must not hide them.
func TestOnFileAt_Path4_CountsRecipientsOutsideSendersDomains(t *testing.T) {
	p, findings := fanoutPipeline(t, "a", "b", "c", "d")
	ip := "203.0.113.8"
	now := time.Unix(1_700_000_000, 0).UTC()

	feedSiteMail(t, p, "m1", "a", ip, now.Add(-4*time.Minute), "admin@site-a.example", "admin@site-b.example")
	feedSiteMail(t, p, "m2", "b", ip, now.Add(-3*time.Minute), "admin@site-b.example", "victim1@elsewhere.example")
	feedSiteMail(t, p, "m3", "c", ip, now.Add(-2*time.Minute), "admin@site-c.example", "victim2@elsewhere.example")
	feedSiteMail(t, p, "m4", "d", ip, now, "admin@site-d.example", "victim3@elsewhere.example", "victim4@elsewhere.example")

	if !fanoutFired(*findings) {
		t.Fatalf("Path 4 must fire when scripts reach recipients outside their own domains, got %+v", *findings)
	}
}

func TestOnFileAt_Path4_FiresWhenDomainLookupFails(t *testing.T) {
	for _, data := range []string{"missing", "main_domain: [invalid", ""} {
		t.Run(data, func(t *testing.T) {
			p, findings := fanoutPipeline(t, "b", "c")
			if data != "missing" {
				dir := filepath.Join(p.domains.root, "usera")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "main"), []byte(data), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Unix(1_700_000_000, 0).UTC()
			for i, site := range []string{"a", "b", "c"} {
				feedSiteMail(t, p, "m"+site, site, "192.0.2.56", now.Add(time.Duration(i)*time.Second), "admin@site-"+site+".example")
			}
			if !fanoutFired(*findings) {
				t.Fatalf("domain lookup failure must leave Path 4 firing, got %+v", *findings)
			}
		})
	}
}

func TestOnFileAt_Path4_FiresForCraftedExternalRecipients(t *testing.T) {
	for _, recipient := range []string{
		"victim%d@tenant.site-%s.example",
		`"victim%d<admin@site-%s.example>"@outside.example`,
	} {
		t.Run(recipient, func(t *testing.T) {
			p, findings := fanoutPipeline(t, "a", "b", "c")
			now := time.Unix(1_700_000_000, 0).UTC()
			for i, site := range []string{"a", "b", "c"} {
				feedSiteMail(t, p, "m"+site, site, "192.0.2.57", now.Add(time.Duration(i)*time.Second),
					fmt.Sprintf(recipient, 0, site), fmt.Sprintf(recipient, 1, site))
			}
			if !fanoutFired(*findings) {
				t.Fatalf("external recipients must leave Path 4 firing, got %+v", *findings)
			}
		})
	}
}

func TestOnFileAt_Path4_OwnNoticesCannotHideParseGap(t *testing.T) {
	for _, recipients := range [][]string{nil, {`"unfinished@site-a.example`, "admin@site-a.example"}} {
		p, findings := fanoutPipeline(t, "a", "b", "c")
		now := time.Unix(1_700_000_000, 0).UTC()
		feedSiteMail(t, p, "ma", "a", "192.0.2.58", now, recipients...)
		feedSiteMail(t, p, "mb", "b", "192.0.2.58", now.Add(time.Second), "admin@site-b.example")
		feedSiteMail(t, p, "mc", "c", "192.0.2.58", now.Add(2*time.Second), "admin@site-c.example")
		if !fanoutFired(*findings) {
			t.Fatalf("recipient parse gap must leave Path 4 firing, got %+v", *findings)
		}
	}
}
