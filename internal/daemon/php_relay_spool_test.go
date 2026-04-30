//go:build linux

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	pipeline := newSpoolPipeline(eng, domains, pol, nil, func(f alert.Finding) {
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
