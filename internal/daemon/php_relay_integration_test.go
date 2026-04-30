//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// TestEndToEnd_SpoolFlowFiresAndAutoFreezeRuns wires the entire Stage 1
// pipeline against a tempdir spool and asserts the occonsultingcy
// fixture pattern produces a Path 1 finding and a (dry-run) AutoFreeze.
func TestEndToEnd_SpoolFlowFiresAndAutoFreezeRuns(t *testing.T) {
	spool := t.TempDir()
	sub := filepath.Join(spool, "k")
	_ = os.MkdirAll(sub, 0o755)

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 1
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.PHPRelay.Freeze = boolPtr(true)
	cfg.AutoResponse.PHPRelay.DryRun = boolPtr(true)

	udir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(udir, "exampleuser"), 0o755)
	_ = os.WriteFile(filepath.Join(udir, "exampleuser", "main"),
		[]byte("main_domain: example.com\n"), 0o644)
	domains := newUserDomainsResolverWithRoot(udir, time.Hour)
	pol := newTestPolicies(t)

	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)
	eng.SetPolicies(pol)

	var findings []alert.Finding
	var fmu sync.Mutex
	alerter := func(f alert.Finding) {
		fmu.Lock()
		findings = append(findings, f)
		fmu.Unlock()
	}
	pipeline := newSpoolPipeline(eng, domains, pol, nil, newIgnoreList(), alerter)

	auditor := &fakeAuditor{}
	runner := &fakeRunner{onRun: func() {}}
	freezer := newAutoFreezer(psw, cfg, spool, "/usr/sbin/exim", runner, auditor, nil, alwaysDryRun)

	w, err := newSpoolWatcher(spool, pipeline.OnFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	body := `id-H
exampleuser 1168 982
<exampleuser@cpanel.example.test>
1777409086 0
-local
1
info@example.com

233P Received: from exampleuser by cpanel.example.test
037  Subject: x
132  X-PHP-Script: spoof.example.com/wp-admin/admin-ajax.php for 192.0.2.10
048F From: <attacker@spoofed.example>
031R Reply-To: attacker@gmail.example
067  X-Mailer: PHPMailer 7.0.0
`
	if err := os.WriteFile(filepath.Join(sub, "1abcdefghij1234-H"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
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
	snapshot := append([]alert.Finding(nil), findings...)
	fmu.Unlock()
	if len(snapshot) == 0 {
		t.Fatal("expected at least one finding from the inotify pipeline")
	}
	auto := freezer.Apply(snapshot)
	if len(auto) == 0 {
		t.Fatal("expected at least one dry-run AutoFreeze finding")
	}
}
