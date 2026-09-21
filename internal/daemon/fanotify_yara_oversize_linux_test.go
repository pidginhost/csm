//go:build linux

package daemon

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Model the worker's complete-file contract, including rejection of a file
// larger than maxBytes. A fabricated match would hide a truncated-read retry.
type oversizeInlineBackend struct {
	beforeRetry func()
	scannedPath string
	scannedData []byte
	scanErr     error
	wrongDigest bool
	inspect     func(string)
}

func (*oversizeInlineBackend) ScanBytes([]byte) []yara.Match     { return nil }
func (*oversizeInlineBackend) ScanFile(string, int) []yara.Match { return nil }
func (*oversizeInlineBackend) Reload() error                     { return nil }
func (*oversizeInlineBackend) RuleCount() int                    { return 1 }

func (b *oversizeInlineBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	if b.beforeRetry != nil {
		b.beforeRetry()
	}
	return nil, fmt.Errorf("inline scan: %w", yaraipc.ErrPayloadTooLarge)
}

func (b *oversizeInlineBackend) ScanFileChecked(path string, maxBytes int) (yara.FileScanResult, error) {
	b.scannedPath = path
	if b.inspect != nil {
		b.inspect(path)
	}
	if b.scanErr != nil {
		return yara.FileScanResult{}, b.scanErr
	}
	f, err := os.Open(path)
	if err != nil {
		return yara.FileScanResult{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return yara.FileScanResult{}, err
	}
	if len(data) > maxBytes {
		return yara.FileScanResult{}, errors.New("file exceeds scan limit")
	}
	b.scannedData = data
	sum := sha256.Sum256(data)
	if b.wrongDigest {
		sum = sha256.Sum256([]byte("different content"))
	}
	var matches []yara.Match
	if bytes.Contains(data, []byte("include 'original.png'")) {
		matches = []yara.Match{{RuleName: "oversize_payload"}}
	}
	return yara.FileScanResult{Matches: matches, ContentSHA256: fmt.Sprintf("%x", sum)}, nil
}

func TestRealtimeYARARetriesOversizeSnapshot(t *testing.T) {
	for _, scenario := range []string{"whole", "prefix", "replaced", "rewritten", "unlinked"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "big.php")
			data := append([]byte("<?php include 'original.png'; ?>"), bytes.Repeat([]byte(" "), yaraipc.MaxScanBytes)...)
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
			backend := &oversizeInlineBackend{beforeRetry: func() {
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
			if !bytes.Equal(backend.scannedData, data) {
				t.Fatal("retry did not scan the event snapshot")
			}
			got := drainYARAAlerts(alerts)
			if len(got) != 1 || got[0].Check != "yara_match_realtime" {
				t.Fatalf("alerts = %+v", got)
			}
			if got[0].ContentSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
				t.Fatalf("finding fingerprint does not describe scanned content: %s", got[0].ContentSHA256)
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

func TestRealtimeYARARetryFailure(t *testing.T) {
	for _, wrongDigest := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrongDigest=%t", wrongDigest), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "big.php")
			data := []byte("<?php include 'original.png'; ?>")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			backend := &oversizeInlineBackend{wrongDigest: wrongDigest}
			if !wrongDigest {
				backend.scanErr = errors.New("worker read failed")
			}
			yara.SetActive(backend)
			t.Cleanup(func() { yara.SetActive(nil) })
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
			if fm.runSignatureScan(data, path, ".php", "") {
				t.Fatal("failed retry reported a match")
			}
			got := drainYARAAlerts(alerts)
			if len(got) != 1 || got[0].Check != "yara_realtime_scan_error" {
				t.Fatalf("alerts = %+v", got)
			}
			if _, err := os.Stat(backend.scannedPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("snapshot retained after failed scan: %v", err)
			}
		})
	}
}

func drainYARAAlerts(ch chan alert.Finding) []alert.Finding {
	var findings []alert.Finding
	for len(ch) > 0 {
		findings = append(findings, <-ch)
	}
	return findings
}

// The worker is a separate process; /proc/self/fd would incorrectly name its
// descriptors. The snapshot must be readable by a child and immutable even
// through another writable descriptor, then released after the scan returns.
func TestRealtimeYARASnapshotSealedAndReleased(t *testing.T) {
	data := []byte("<?php include 'original.png'; ?>")
	backend := &oversizeInlineBackend{inspect: func(path string) {
		got, err := exec.Command("cat", path).Output()
		if err != nil {
			t.Fatalf("child read: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("child read different bytes")
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteAt([]byte("changed"), 0); !errors.Is(err, unix.EPERM) {
			t.Fatalf("snapshot write: %v, want EPERM", err)
		}
		if err := f.Truncate(0); !errors.Is(err, unix.EPERM) {
			t.Fatalf("snapshot truncate: %v, want EPERM", err)
		}
		if err := f.Truncate(int64(len(data) + 1)); !errors.Is(err, unix.EPERM) {
			t.Fatalf("snapshot grow: %v, want EPERM", err)
		}
	}}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	if !fm.runSignatureScan(data, "/unused/event.php", ".php", "") {
		t.Fatal("snapshot scan failed")
	}
	if _, err := os.Stat(backend.scannedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot retained after scan: %v", err)
	}
}

func TestRealtimeYARARetryCleanSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changed.php")
	data := []byte("<?php echo 'clean event'; ?>")
	// The path now contains a match, but that is not the event being scanned.
	if err := os.WriteFile(path, []byte("<?php include 'original.png'; ?>"), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &oversizeInlineBackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	if fm.runSignatureScan(data, path, ".php", "") {
		t.Fatal("retry attributed a replacement's match to the clean event")
	}
	if got := drainYARAAlerts(alerts); len(got) != 0 {
		t.Fatalf("clean snapshot alerts = %+v", got)
	}
	if !bytes.Equal(backend.scannedData, data) {
		t.Fatal("retry did not scan the clean snapshot")
	}
}
