//go:build linux

package daemon

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

// snapshotBackend scans only the bytes it is handed. A path scan would read
// whatever the path names now, not the event, so it fails the test.
type snapshotBackend struct {
	t          *testing.T
	beforeScan func()
	scanned    []byte
	scanErr    error
}

func (*snapshotBackend) ScanBytes([]byte) []yara.Match { return nil }
func (b *snapshotBackend) ScanFile(path string, _ int) []yara.Match {
	b.t.Errorf("realtime YARA reopened %s by path", path)
	return nil
}
func (*snapshotBackend) Reload() error  { return nil }
func (*snapshotBackend) RuleCount() int { return 1 }

func (b *snapshotBackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	if b.beforeScan != nil {
		b.beforeScan()
	}
	b.scanned = bytes.Clone(data)
	if b.scanErr != nil {
		return nil, b.scanErr
	}
	if bytes.Contains(data, []byte("include 'original.png'")) {
		return []yara.Match{{RuleName: "oversize_payload"}}, nil
	}
	return nil, nil
}

// A snapshot past the old 12 MiB message limit is scanned from the event's
// bytes, whatever happens to the path meanwhile.
func TestRealtimeYARAScansOversizeSnapshotFromBytes(t *testing.T) {
	for _, scenario := range []string{"whole", "prefix", "replaced", "rewritten", "unlinked"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "big.php")
			data := append([]byte("<?php include 'original.png'; ?>"), bytes.Repeat([]byte(" "), 20<<20)...)
			onDisk := data
			if scenario == "prefix" {
				onDisk = append(bytes.Clone(data), []byte("unread tail")...)
			}
			if err := os.WriteFile(path, onDisk, 0600); err != nil {
				t.Fatal(err)
			}
			event, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer event.Close()
			backend := &snapshotBackend{t: t, beforeScan: func() {
				switch scenario {
				case "replaced":
					replacement := filepath.Join(filepath.Dir(path), "replacement.php")
					if err := os.WriteFile(replacement, []byte("<?php include 'replacement.png'; ?>"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "rewritten":
					if err := os.WriteFile(path, []byte("<?php include 'replacement.png'; ?>"), 0600); err != nil {
						t.Fatal(err)
					}
				case "unlinked":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}}
			yara.SetActive(backend)
			t.Cleanup(func() { yara.SetActive(nil) })
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
			if !fm.runEventSignatureScan(int(event.Fd()), data, path, ".php", "pid=123") {
				t.Fatalf("oversize event content was not scanned; alerts: %v", drainYARAAlerts(alerts))
			}
			if !bytes.Equal(backend.scanned, data) {
				t.Fatal("scan did not use the event snapshot")
			}
			got := drainYARAAlerts(alerts)
			if len(got) != 1 || got[0].Check != "yara_match_realtime" {
				t.Fatalf("alerts = %+v", got)
			}
			// A window short of the file must not stand in for its digest:
			// Re-check compares against the whole file and would call an
			// unchanged file modified.
			want := fmt.Sprintf("%x", sha256.Sum256(data))
			if scenario == "prefix" {
				want = ""
			}
			if got[0].ContentSHA256 != want {
				t.Fatalf("finding fingerprint = %q, want %q", got[0].ContentSHA256, want)
			}
			if got[0].FilePath != path || got[0].ProcessInfo != "pid=123" {
				t.Fatalf("lost event provenance: %+v", got[0])
			}
			if !strings.Contains(got[0].Details, "Included payload files: original.png") || strings.Contains(got[0].Details, "replacement.png") {
				t.Fatalf("details do not describe scanned content: %s", got[0].Details)
			}
		})
	}
}

// Every realtime YARA finding names the digest of the bytes it matched, so
// a later fingerprint stamp never reopens a path that may name new content.
func TestRealtimeYARAFindingCarriesSnapshotDigest(t *testing.T) {
	data := []byte("<?php include 'original.png'; ?>")
	yara.SetActive(&snapshotBackend{t: t})
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	if !fm.runSignatureScan(data, filepath.Join(t.TempDir(), "small.php"), ".php", "") {
		t.Fatal("small event was not matched")
	}
	got := drainYARAAlerts(alerts)
	if len(got) != 1 || got[0].ContentSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestRealtimeYARAScanFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.php")
	data := []byte("<?php include 'original.png'; ?>")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	yara.SetActive(&snapshotBackend{t: t, scanErr: errors.New("worker read failed")})
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	if fm.runSignatureScan(data, path, ".php", "") {
		t.Fatal("failed scan reported a match")
	}
	got := drainYARAAlerts(alerts)
	if len(got) != 1 || got[0].Check != "yara_realtime_scan_error" {
		t.Fatalf("alerts = %+v", got)
	}
}

func drainYARAAlerts(ch chan alert.Finding) []alert.Finding {
	var findings []alert.Finding
	for len(ch) > 0 {
		findings = append(findings, <-ch)
	}
	return findings
}

func TestRealtimeYARAScansEventNotPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changed.php")
	data := []byte("<?php echo 'clean event'; ?>")
	// The path now contains a match, but that is not the event being scanned.
	if err := os.WriteFile(path, []byte("<?php include 'original.png'; ?>"), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &snapshotBackend{t: t}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	if fm.runSignatureScan(data, path, ".php", "") {
		t.Fatal("a replacement's match was attributed to the clean event")
	}
	if got := drainYARAAlerts(alerts); len(got) != 0 {
		t.Fatalf("clean snapshot alerts = %+v", got)
	}
	if !bytes.Equal(backend.scanned, data) {
		t.Fatal("scan did not use the clean snapshot")
	}
}

// Real-time PHP scans read a 32 KiB window. For a larger file the finding
// leaves the digest to the later whole-file stamp, so Re-check can clear an
// unchanged file once the rule no longer matches it.
func TestRealtimeYARAPartialWindowLeavesDigestToStamp(t *testing.T) {
	data := append([]byte("<?php include 'original.png'; ?>"), bytes.Repeat([]byte(" "), 32<<10)...)
	yara.SetActive(&snapshotBackend{t: t})
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	if !fm.runSignatureScanWithSize(data, int64(len(data))+8<<10, filepath.Join(t.TempDir(), "big.php"), ".php", "", nil) {
		t.Fatal("window was not matched")
	}
	got := drainYARAAlerts(alerts)
	if len(got) != 1 || got[0].ContentSHA256 != "" {
		t.Fatalf("partial window fingerprinted: %+v", got)
	}
}
