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
