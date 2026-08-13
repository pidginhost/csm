package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func countFrozenFindings(t *testing.T, cfg *config.Config, lines []string) int {
	t.Helper()
	count := 0
	for _, line := range lines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "exim_frozen_realtime" {
				count++
			}
		}
	}
	return count
}

// Exim re-logs "Message is frozen" for the same queued message on every queue
// run; one stuck bounce must produce one finding, not one per queue run.
func TestEximFrozenDedupsRepeatLogLinesPerMessageID(t *testing.T) {
	resetEximFrozenDedup()
	cfg := &config.Config{}
	lines := []string{
		"2026-08-13 20:45:33 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)",
		"2026-08-13 20:58:19 1wuZUi-0000000BrCR-0u0H Message is frozen",
		"2026-08-13 21:11:12 1wuZUi-0000000BrCR-0u0H Message is frozen",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 1 {
		t.Errorf("got %d frozen findings for one message, want 1", got)
	}
}

func TestEximFrozenDistinctMessagesAlertIndividually(t *testing.T) {
	resetEximFrozenDedup()
	cfg := &config.Config{}
	lines := []string{
		"2026-08-13 20:45:33 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)",
		"2026-08-13 21:07:38 1wuZpz-0000000Byih-1TiL Frozen (delivery error message)",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 2 {
		t.Errorf("got %d frozen findings for two messages, want 2", got)
	}
}

// "Unfrozen by errmsg timer" is a recovery event, not a spam indicator; the
// substring "frozen" inside "Unfrozen" must not raise a finding.
func TestEximFrozenUnfreezeLinesIgnored(t *testing.T) {
	resetEximFrozenDedup()
	cfg := &config.Config{}
	lines := []string{
		"2026-08-13 20:26:10 1wuCbn-00000004YPU-3U2V Unfrozen by errmsg timer",
		"2026-08-13 20:26:31 1wuCXs-00000004XEk-3Rfd Unfrozen by forced delivery",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 0 {
		t.Errorf("got %d frozen findings for unfreeze events, want 0", got)
	}
}

// A frozen line whose message ID cannot be parsed still alerts: fail-open so a
// log-format change degrades to noise, not silence.
func TestEximFrozenNoMessageIDStillAlerts(t *testing.T) {
	resetEximFrozenDedup()
	cfg := &config.Config{}
	lines := []string{
		"2026-08-13 20:45:33 queue run: 3 frozen messages skipped",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 1 {
		t.Errorf("got %d frozen findings for ID-less line, want 1", got)
	}
}
