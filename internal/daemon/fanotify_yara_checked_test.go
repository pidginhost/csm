//go:build linux

package daemon

import (
	"errors"
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
