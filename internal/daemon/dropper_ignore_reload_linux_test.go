//go:build linux

package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestDropperIgnorePathsFollowReloadAndPreserveOverflow(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	cfg := &config.Config{}
	cfg.Thresholds.DropperDetection = true
	cfg.Suppressions.IgnorePaths = []string{"/home/alice/public_html/old/*"}
	config.SetActive(cfg)
	findings := make(chan alert.Finding, 2)
	fm := &FileMonitor{cfg: cfg, alertCh: findings}
	fm.initDropperDetector(cfg)
	fm.dropper.tr.maxTracked = 1
	now := time.Now()
	oldPath := newDropperCandidate(now, "/home/alice/public_html/old/shell.php")
	newPath := newDropperCandidate(now, "/home/alice/public_html/new/shell.php")
	if fm.dropper.admit(oldPath) {
		t.Fatal("startup suppression ignored")
	}
	reloaded := *cfg
	reloaded.Suppressions.IgnorePaths = []string{"/home/alice/public_html/new/*"}
	config.SetActive(&reloaded)
	if fm.dropper.admit(newPath) {
		t.Error("new suppression did not take effect")
	}
	if !fm.dropper.admit(oldPath) {
		t.Error("removed suppression still hides candidates")
	}
	other := newDropperCandidate(now, "/home/alice/public_html/uploads/second.php")
	if fm.dropper.admit(other) {
		t.Error("full tracker admitted another candidate")
	}
	if got := fm.dropper.tr.overflowDropped(); got != 1 {
		t.Errorf("capacity losses = %d, want exactly one unsuppressed candidate", got)
	}
	fm.reportDropperOverflow()
	fm.reportDropperOverflow()
	if len(findings) != 1 {
		t.Fatalf("coverage warnings = %d, want exactly one", len(findings))
	}
	if finding := <-findings; finding.Check != "self_deleting_dropper_overflow" {
		t.Fatalf("coverage warning check = %q", finding.Check)
	}
}
