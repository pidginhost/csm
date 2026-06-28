package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestPHPShieldWatchDecision(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		scriptExists bool
		wantWatch    bool
		wantWarn     bool
	}{
		{
			name:    "disabled: neither watch nor warn",
			enabled: false, scriptExists: false,
			wantWatch: false, wantWarn: false,
		},
		{
			name:    "disabled even if script present",
			enabled: false, scriptExists: true,
			wantWatch: false, wantWarn: false,
		},
		{
			name:    "enabled and installed: watch",
			enabled: true, scriptExists: true,
			wantWatch: true, wantWarn: false,
		},
		{
			name:    "enabled but not installed: warn, do not watch",
			enabled: true, scriptExists: false,
			wantWatch: false, wantWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watch, warn := phpShieldWatchDecision(tt.enabled, tt.scriptExists)
			if watch != tt.wantWatch || warn != tt.wantWarn {
				t.Fatalf("phpShieldWatchDecision(%v, %v) = (watch=%v, warn=%v), want (watch=%v, warn=%v)",
					tt.enabled, tt.scriptExists, watch, warn, tt.wantWatch, tt.wantWarn)
			}
		})
	}
}

func TestPHPShieldMissingScriptWarningUsesSupportedCommand(t *testing.T) {
	for _, want := range []string{
		"csm enable --php-shield",
		"systemctl restart lsws || apachectl graceful",
		"restart csm",
	} {
		if !strings.Contains(phpShieldMissingScriptWarning, want) {
			t.Fatalf("php shield warning missing %q: %s", want, phpShieldMissingScriptWarning)
		}
	}
	if strings.Contains(phpShieldMissingScriptWarning, "csm php-shield install") {
		t.Fatalf("php shield warning still names unsupported command: %s", phpShieldMissingScriptWarning)
	}
}

func TestRetryLogWatcherNamedMarksPHPShieldAttachedAfterEventLogAppears(t *testing.T) {
	oldInterval := logWatcherRetryInterval
	logWatcherRetryInterval = 10 * time.Millisecond
	t.Cleanup(func() { logWatcherRetryInterval = oldInterval })

	path := filepath.Join(t.TempDir(), "events.log")
	d := New(&config.Config{}, nil, nil, "")
	d.MarkWatcher("php_shield", false)

	d.wg.Add(1)
	done := make(chan struct{})
	go func() {
		d.retryLogWatcherNamed(path, parsePHPShieldLogLine, "php_shield")
		close(done)
	}()

	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		close(d.stopCh)
		d.wg.Wait()
		t.Fatal("named retry did not attach after PHP Shield event log appeared")
	}

	statuses := d.WatcherStatuses()
	if attached, ok := statuses["php_shield"]; !ok || !attached {
		t.Fatalf("php_shield watcher status = %v (present=%v), want attached", attached, ok)
	}

	close(d.stopCh)
	d.wg.Wait()
}
