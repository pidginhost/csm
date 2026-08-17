//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

type failingFanotifyYARABackend struct{}

func (failingFanotifyYARABackend) ScanFile(string, int) []yara.Match { return nil }
func (failingFanotifyYARABackend) ScanBytes([]byte) []yara.Match     { return nil }
func (failingFanotifyYARABackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, errors.New("worker unavailable")
}
func (failingFanotifyYARABackend) RuleCount() int { return 1 }
func (failingFanotifyYARABackend) Reload() error  { return nil }

type matchingFanotifyYARABackend struct{}

func (matchingFanotifyYARABackend) ScanFile(string, int) []yara.Match { return nil }
func (matchingFanotifyYARABackend) ScanBytes([]byte) []yara.Match {
	return []yara.Match{{RuleName: "phps_test"}}
}
func (matchingFanotifyYARABackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return []yara.Match{{RuleName: "phps_test"}}, nil
}
func (matchingFanotifyYARABackend) RuleCount() int { return 1 }
func (matchingFanotifyYARABackend) Reload() error  { return nil }

func TestFanotifyYARAErrorIsNotTreatedAsClean(t *testing.T) {
	alerts := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	yara.SetActive(failingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	if matched := fm.runSignatureScan([]byte("payload"), "/home/alice/public_html/x.php", ".php", ""); matched {
		t.Fatal("scan error must not be reported as a YARA match")
	}
	select {
	case finding := <-alerts:
		if finding.Check != "yara_scan_incomplete" {
			t.Fatalf("finding = %+v, want yara_scan_incomplete", finding)
		}
	default:
		t.Fatal("scan error was silently treated as clean")
	}
}

func TestFanotifyPhpsEventReachesContentScanner(t *testing.T) {
	alerts := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	yara.SetActive(matchingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	path := filepath.Join(t.TempDir(), "staged.phps")
	if err := os.WriteFile(path, []byte("<?php echo 'staged';"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	fm.analyzeFile(fileEvent{path: path, fd: int(file.Fd())})
	select {
	case finding := <-alerts:
		if finding.Check != "yara_match_realtime" {
			t.Fatalf("finding = %+v, want yara_match_realtime", finding)
		}
	default:
		t.Fatal(".phps event did not reach realtime content scanning")
	}
	if isPHPExtension(filepath.Base(path)) {
		t.Fatal("content-scanned .phps event was reclassified as executable PHP")
	}
}
