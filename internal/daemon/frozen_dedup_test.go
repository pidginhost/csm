package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
		"2026-08-13 20:26:52 future-id-format Unfrozen by forced delivery",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 0 {
		t.Errorf("got %d frozen findings for unfreeze events, want 0", got)
	}
}

func TestEximFrozenUnfreezeAllowsRefreezeFinding(t *testing.T) {
	resetEximFrozenDedup()
	start := time.Date(2026, 8, 13, 20, 45, 33, 0, time.UTC)
	id := "1wuZUi-0000000BrCR-0u0H"

	if !eximFrozenShouldAlert("2026-08-13 20:45:33 "+id+" Frozen (delivery error message)", start) {
		t.Fatal("initial freeze should alert")
	}
	if eximFrozenShouldAlert("2026-08-13 20:46:33 "+id+" Unfrozen by forced delivery", start.Add(time.Minute)) {
		t.Fatal("unfreeze should not alert")
	}
	if !eximFrozenShouldAlert("2026-08-13 20:47:33 "+id+" Frozen (delivery error message)", start.Add(2*time.Minute)) {
		t.Fatal("freeze after an unfreeze should alert again")
	}
}

func TestEximFrozenRepeatsRefreshDedupLifetime(t *testing.T) {
	resetEximFrozenDedup()
	start := time.Date(2026, 8, 13, 20, 45, 33, 0, time.UTC)
	id := "1wuZUi-0000000BrCR-0u0H"

	if !eximFrozenShouldAlert("2026-08-13 20:45:33 "+id+" Frozen (delivery error message)", start) {
		t.Fatal("initial freeze should alert")
	}
	if eximFrozenShouldAlert("2026-08-14 19:45:33 "+id+" Message is frozen", start.Add(23*time.Hour)) {
		t.Fatal("repeat queue run should be suppressed")
	}
	if eximFrozenShouldAlert("2026-08-14 21:45:33 "+id+" Message is frozen", start.Add(25*time.Hour)) {
		t.Fatal("continuously frozen message should remain suppressed past the original TTL")
	}
}

func TestEximFrozenInactiveIDExpires(t *testing.T) {
	resetEximFrozenDedup()
	start := time.Date(2026, 8, 13, 20, 45, 33, 0, time.UTC)
	line := "2026-08-13 20:45:33 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)"

	if !eximFrozenShouldAlert(line, start) {
		t.Fatal("initial freeze should alert")
	}
	if !eximFrozenShouldAlert(line, start.Add(eximFrozenDedupTTL)) {
		t.Fatal("inactive queue ID should be re-armed after the stale-state TTL")
	}
}

func TestEximFrozenDedupStateIsBounded(t *testing.T) {
	resetEximFrozenDedup()
	start := time.Date(2026, 8, 13, 20, 45, 33, 0, time.UTC)
	eximFrozenDedup.mu.Lock()
	for i := 0; i < eximFrozenDedupMaxEntries; i++ {
		eximFrozenDedup.seen["existing-"+strconv.Itoa(i)] = start
	}
	eximFrozenDedup.nextPrune = start.Add(eximFrozenDedupPruneInterval)
	eximFrozenDedup.mu.Unlock()

	line := "2026-08-13 20:45:34 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)"
	if !eximFrozenShouldAlert(line, start.Add(time.Second)) {
		t.Fatal("new queue ID should fail open when the dedup state is full")
	}

	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if got := len(eximFrozenDedup.seen); got != eximFrozenDedupMaxEntries {
		t.Fatalf("dedup state has %d entries, want cap %d", got, eximFrozenDedupMaxEntries)
	}
	if _, ok := eximFrozenDedup.seen["1wuZUi-0000000BrCR-0u0H"]; !ok {
		t.Fatal("new queue ID was not retained after capacity eviction")
	}
}

func TestEximFrozenDedupsTimezoneAndPIDLogPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		repeat string
	}{
		{
			name:   "timezone",
			first:  "2026-08-13 20:45:33 +0300 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)",
			repeat: "2026-08-13 20:58:19 +0300 1wuZUi-0000000BrCR-0u0H Message is frozen",
		},
		{
			name:   "pid",
			first:  "2026-08-13 20:45:33 [12345] 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)",
			repeat: "2026-08-13 20:58:19 [23456] 1wuZUi-0000000BrCR-0u0H Message is frozen",
		},
		{
			name:   "timezone and pid",
			first:  "2026-08-13 20:45:33 +0300 [12345] 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)",
			repeat: "2026-08-13 20:58:19 +0300 [23456] 1wuZUi-0000000BrCR-0u0H Message is frozen",
		},
		{
			name:   "pid and timezone",
			first:  "2026-08-13 20:45:33 [12345] +0300 1wuZUi-0000000BrCR-0u0H Frozen (delivery error message)",
			repeat: "2026-08-13 20:58:19 [23456] +0300 1wuZUi-0000000BrCR-0u0H Message is frozen",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetEximFrozenDedup()
			cfg := &config.Config{}
			if got := countFrozenFindings(t, cfg, []string{tc.first, tc.repeat}); got != 1 {
				t.Fatalf("got %d frozen findings, want 1", got)
			}
		})
	}
}

func TestEximFrozenIgnoresIncidentalTextAfterQueueAction(t *testing.T) {
	resetEximFrozenDedup()
	cfg := &config.Config{}
	lines := []string{
		`2026-08-13 20:45:33 1wuZUi-0000000BrCR-0u0H <= sender@example.com H=mail.example T="Frozen account report"`,
		`2026-08-13 20:45:34 1wuZpz-0000000Byih-1TiL ** user@example.com R=dnslookup: Message is frozen in remote system`,
		`2026-08-13 20:45:35 future-id-format <= sender@example.com T="Frozen account report"`,
		"2026-08-13 20:45:36 queue run: 3 frozen messages skipped",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 0 {
		t.Fatalf("got %d frozen findings for incidental text, want 0", got)
	}
}

func TestEximFrozenChannelDropRearmsDedup(t *testing.T) {
	resetEximFrozenDedup()
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alertCh := make(chan alert.Finding, 1)
	alertCh <- alert.Finding{Check: "channel_blocker"}
	w, err := NewLogWatcher(path, &config.Config{}, parseEximLogLine, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	appendLine := func(line string) {
		t.Helper()
		f, openErr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, writeErr := f.WriteString(line + "\n"); writeErr != nil {
			_ = f.Close()
			t.Fatal(writeErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		w.readNewLines()
	}

	id := "1wuZUi-0000000BrCR-0u0H"
	appendLine("2026-08-13 20:45:33 " + id + " Frozen (delivery error message)")
	<-alertCh // remove the blocker after the first finding was dropped
	appendLine("2026-08-13 20:58:19 " + id + " Message is frozen")

	select {
	case got := <-alertCh:
		if got.Check != "exim_frozen_realtime" {
			t.Fatalf("check = %q, want exim_frozen_realtime", got.Check)
		}
	default:
		t.Fatal("repeat freeze was suppressed after the first finding was dropped")
	}
}

// A frozen line whose message ID cannot be parsed still alerts: fail-open so a
// log-format change degrades to noise, not silence.
func TestEximFrozenNoMessageIDStillAlerts(t *testing.T) {
	resetEximFrozenDedup()
	cfg := &config.Config{}
	lines := []string{
		"2026-08-13 20:45:33 future-id-format Frozen (delivery error message)",
	}
	if got := countFrozenFindings(t, cfg, lines); got != 1 {
		t.Errorf("got %d frozen findings for ID-less line, want 1", got)
	}
}
