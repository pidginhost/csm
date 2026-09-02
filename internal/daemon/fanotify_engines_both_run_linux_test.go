//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

const realtimeHighRule = `
version: 1
rules:
  - name: test_high_marker
    description: "high-severity yml rule"
    severity: high
    category: obfuscation
    file_types: [".php"]
    patterns: ["EVIL_MARKER_A"]
    min_match: 1
`

func useRealtimeRules(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	signatures.Init(dir)
	t.Cleanup(func() { signatures.Init(t.TempDir()) })
}

func drainChecks(alerts <-chan alert.Finding) map[string]alert.Severity {
	got := map[string]alert.Severity{}
	for {
		select {
		case f := <-alerts:
			got[f.Check] = f.Severity
		default:
			return got
		}
	}
}

// A .yml hit used to end the realtime scan before YARA-X ran, so a file
// that matched a High .yml rule never met the Critical YARA rule and the
// inline quarantine that only a Critical match triggers. Both engines must
// see every file.
func TestRealtimeScanRunsYARAAfterYAMLMatch(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	yara.SetActive(matchingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	path := "/home/alice/public_html/shell.php"
	if !fm.runSignatureScan([]byte("<?php EVIL_MARKER_A; ?>"), path, ".php", "") {
		t.Fatal("scan reported no match")
	}
	got := drainChecks(alerts)
	if got["signature_match_realtime"] != alert.High {
		t.Fatalf("yml finding = %v, want High signature_match_realtime", got)
	}
	if got["yara_match_realtime"] != alert.Critical {
		t.Fatalf("YARA did not run after the yml match: %v", got)
	}
}

// The directory dedup of a non-critical .yml match suppresses that alert
// only; it must not swallow the YARA verdict for the next file.
func TestRealtimeScanDedupDoesNotSkipYARA(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	yara.SetActive(matchingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	dir := "/home/alice/public_html/plugin"
	fm.runSignatureScan([]byte("<?php EVIL_MARKER_A; ?>"), dir+"/a.php", ".php", "")
	drainChecks(alerts)
	fm.runSignatureScan([]byte("<?php EVIL_MARKER_A; ?>"), dir+"/b.php", ".php", "")
	got := drainChecks(alerts)
	if _, dup := got["signature_match_realtime"]; dup {
		t.Fatalf("directory dedup no longer suppresses the repeated yml alert: %v", got)
	}
	if got["yara_match_realtime"] != alert.Critical {
		t.Fatalf("YARA skipped for the deduplicated file: %v", got)
	}
}
