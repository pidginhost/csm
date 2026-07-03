package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestScanEximHistoryForPHPRelayAccountVolume_ReplaysLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteString("2026-04-29 12:00:01 1ab" + string(rune('A'+i%26)) + "-DEF <= info@example.com U=exampleuser ID=1 B=redirect_resolver\n")
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write exim mainlog fixture: %v", err)
	}

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	eng := newEvaluator(nil, nil, newPerAccountWindow(5000), cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	// now is aligned to the fixture timestamps so the replayed lines fall inside
	// the account detection window; the replay filters by real exim timestamp.
	now := time.Date(2026, 4, 29, 12, 30, 0, 0, time.Local)
	var findings []alert.Finding
	var mu sync.Mutex
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, now, func(f alert.Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	})
	mu.Lock()
	defer mu.Unlock()
	fired := 0
	for _, f := range findings {
		if f.Path == "volume_account" {
			fired++
		}
	}
	if fired == 0 {
		t.Errorf("expected at least one volume_account finding, got %+v", findings)
	}
}

func TestScanEximHistoryForPHPRelayAccountVolume_SkipsOversizedLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString(phpRelayHistoryLine(i))
	}
	b.WriteString(strings.Repeat("X", 1024*1024+128) + "\n")
	for i := 10; i < 80; i++ {
		b.WriteString(phpRelayHistoryLine(i))
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write exim mainlog fixture: %v", err)
	}

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	eng := newEvaluator(nil, nil, newPerAccountWindow(5000), cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	now := time.Date(2026, 4, 29, 13, 0, 0, 0, time.Local)
	var findings []alert.Finding
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, now, func(f alert.Finding) {
		findings = append(findings, f)
	})

	fired := 0
	for _, f := range findings {
		if f.Path == "volume_account" {
			fired++
		}
	}
	if fired == 0 {
		t.Fatalf("expected scan to continue after oversized line, got %+v", findings)
	}
}

func TestScanEximHistoryForPHPRelayAccountVolume_StopsAfterContextCancel(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteString(phpRelayHistoryLine(i))
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write exim mainlog fixture: %v", err)
	}

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 1
	accounts := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, accounts, cfg, nil)
	eng.SetEffectiveAccountLimit(1)

	now := time.Date(2026, 4, 29, 13, 0, 0, 0, time.Local)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var emitted int
	ScanEximHistoryForPHPRelayAccountVolume(ctx, logPath, eng, now, func(alert.Finding) {
		emitted++
		cancel()
	})

	if emitted != 1 {
		t.Fatalf("emitted = %d, want 1", emitted)
	}
	if got := accounts.volumeSince("exampleuser", now.Add(-phpRelayAccountWindowDur)); got != 1 {
		t.Fatalf("processed events after cancellation = %d, want 1", got)
	}
}

func phpRelayHistoryLine(i int) string {
	return fmt.Sprintf("2026-04-29 12:%02d:01 1ab%03d-DEF <= info@example.com U=exampleuser ID=1 B=redirect_resolver\n", i%60, i)
}

// REL-01: history replay must ignore lines older than the account detection
// window instead of stamping every line "now". With the old code an
// exim_mainlog spanning days fired a false last-hour Critical on every restart.
func TestScanEximHistoryForPHPRelayAccountVolume_SkipsLinesOutsideWindow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	// 200 sends for one account, all dated a day before `now`.
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "2026-04-28 09:%02d:01 1ab%03d-DEF <= info@example.com U=exampleuser ID=1 B=redirect_resolver\n", i%60, i)
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write exim mainlog fixture: %v", err)
	}

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	accounts := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, accounts, cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	now := time.Date(2026, 4, 29, 13, 0, 0, 0, time.Local) // ~28h after the log lines
	var findings []alert.Finding
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, now, func(f alert.Finding) {
		findings = append(findings, f)
	})
	for _, f := range findings {
		if f.Path == "volume_account" {
			t.Fatalf("day-old log lines must not fire a last-hour account-volume Critical: %+v", f)
		}
	}
	if got := accounts.volumeSince("exampleuser", now.Add(-phpRelayAccountWindowDur)); got != 0 {
		t.Fatalf("out-of-window events leaked into the account window: %d", got)
	}
}

func TestScanEximHistoryForPHPRelayAccountVolume_SkipsFutureDatedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&b, "2026-04-29 14:%02d:01 1ab%03d-DEF <= info@example.com U=exampleuser ID=1 B=redirect_resolver\n", i%60, i)
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write exim mainlog fixture: %v", err)
	}

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	accounts := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, accounts, cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	now := time.Date(2026, 4, 29, 13, 0, 0, 0, time.Local)
	var findings []alert.Finding
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, now, func(f alert.Finding) {
		findings = append(findings, f)
	})
	for _, f := range findings {
		if f.Path == "volume_account" {
			t.Fatalf("future-dated log lines must not fire account-volume Critical: %+v", f)
		}
	}
	if got := accounts.volumeSince("exampleuser", now.Add(-phpRelayAccountWindowDur)); got != 0 {
		t.Fatalf("future-dated events leaked into the account window: %d", got)
	}
}

// REL-01 (unit): the account event is stamped with the supplied eventTime, not
// `now`, so a historical replay does not compress the window.
func TestParsePHPRelayAccountVolumeAt_StampsEventTime(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	accounts := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, accounts, cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	now := time.Date(2026, 4, 29, 13, 0, 0, 0, time.Local)
	old := now.Add(-90 * time.Minute) // outside the 60-min window
	line := "2026-04-29 11:30:01 1abc-DEF <= info@example.com U=exampleuser ID=1 B=redirect_resolver"
	if got := eng.parsePHPRelayAccountVolumeAt(line, old, now); got != nil {
		t.Fatalf("an out-of-window event must not fire, got %+v", got)
	}
	if got := accounts.volumeSince("exampleuser", now.Add(-phpRelayAccountWindowDur)); got != 0 {
		t.Fatalf("event stamped at eventTime should sit outside the window, count=%d", got)
	}
	// A recent event does count.
	eng.parsePHPRelayAccountVolumeAt(line, now.Add(-5*time.Minute), now)
	if got := accounts.volumeSince("exampleuser", now.Add(-phpRelayAccountWindowDur)); got != 1 {
		t.Fatalf("in-window event should count once, got %d", got)
	}
}
