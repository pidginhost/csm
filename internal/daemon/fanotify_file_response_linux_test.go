//go:build linux

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

// A paused inline response must still publish both engine detections and a
// single pause notice, instead of returning early or marking files remediated.
func TestRealtimeFileResponsePauseKeepsBothDetections(t *testing.T) {
	useRealtimeRules(t, strings.ReplaceAll(strings.ReplaceAll(realtimeHighRule, "severity: high", "severity: critical"), "category: obfuscation", "category: dropper"))
	oldYARA := yara.Active()
	yara.SetActive(matchingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(oldYARA) })
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	cfg.AutoResponse.MaxFileActionsPerHour = 1
	ledger := map[string]any{"version": 1, "attempts": []map[string]any{{"at": time.Now(), "account": "alice", "failed": false}}}
	data, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file-response.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}
	payload := []byte("<?php /* EVIL_MARKER_A " + strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-", 32) + " */")
	pauses := 0
	for _, name := range []string{"a.php", "b.php"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !fm.runSignatureScanWithSize(payload, int64(len(payload)), path, ".php", "", info) {
			t.Fatal("detection lost during pause")
		}
		got := drainChecks(alerts)
		if got["signature_match_realtime"] != alert.Critical || got["yara_match_realtime"] != alert.Critical {
			t.Fatalf("paused response lost findings: %v", got)
		}
		if _, ok := got["auto_response"]; ok {
			t.Fatal("refused response claimed successful remediation")
		}
		if _, ok := got["auto_response_paused"]; ok {
			pauses++
		}
		if actual, err := os.ReadFile(path); err != nil || string(actual) != string(payload) {
			t.Fatalf("paused response changed file: %v", err)
		}
	}
	if pauses != 1 {
		t.Fatalf("pause notices=%d, want one", pauses)
	}
}

func TestRealtimeFileResponsePauseDoesNotRetryOnDelivery(t *testing.T) {
	useRealtimeRules(t, strings.ReplaceAll(strings.ReplaceAll(realtimeHighRule, "severity: high", "severity: critical"), "category: obfuscation", "category: dropper"))
	root := t.TempDir()
	cfg := &config.Config{StatePath: root}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
	lock, err := os.Create(filepath.Join(root, "file-response.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	// The inline call refuses the busy lock. If alert delivery evaluates the
	// response again after the lock clears, it will hit this broken ledger
	// and publish a second pause for a detection already left for review.
	if err = os.WriteFile(filepath.Join(root, "file-response.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 32)
	fm := &FileMonitor{cfg: cfg, alertCh: alerts}
	payload := []byte("<?php /* EVIL_MARKER_A " + strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-", 32) + " */")
	path := filepath.Join(root, "test.php")
	if err = os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fm.runSignatureScanWithSize(payload, int64(len(payload)), path, ".php", "", info) {
		t.Fatal("inline refusal lost the original detection")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	close(alerts)
	var findings []alert.Finding
	detected, paused := false, false
	for f := range alerts {
		findings = append(findings, f)
		detected = detected || f.Check == "signature_match_realtime"
		paused = paused || f.Check == "auto_response_paused"
	}
	if !detected || !paused {
		t.Fatalf("expected the original detection and busy notice: %+v", findings)
	}
	if actions := checks.AutoQuarantineFiles(cfg, findings); len(actions) != 0 {
		t.Fatalf("alert delivery retried a refused inline response: %+v", actions)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(payload) {
		t.Fatalf("refused file was changed: %v", err)
	}
}
