package daemon

import (
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
	_ = os.WriteFile(logPath, []byte(b.String()), 0o644)

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	eng := newEvaluator(nil, nil, newPerAccountWindow(5000), cfg, nil)
	eng.SetEffectiveAccountLimit(50)

	var findings []alert.Finding
	var mu sync.Mutex
	ScanEximHistoryForPHPRelayAccountVolume(logPath, eng, time.Now(), func(f alert.Finding) {
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
