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

	var findings []alert.Finding
	var mu sync.Mutex
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, time.Now(), func(f alert.Finding) {
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

	var findings []alert.Finding
	ScanEximHistoryForPHPRelayAccountVolume(context.Background(), logPath, eng, time.Now(), func(f alert.Finding) {
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

	now := time.Now()
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
