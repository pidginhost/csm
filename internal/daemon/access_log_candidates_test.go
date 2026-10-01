package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestAccessLogRetryFindsLaterCandidate(t *testing.T) {
	oldInterval := logWatcherRetryInterval
	logWatcherRetryInterval = 10 * time.Millisecond
	t.Cleanup(func() { logWatcherRetryInterval = oldInterval })

	root := t.TempDir()
	candidates := []string{
		filepath.Join(root, "primary_access_log"),
		filepath.Join(root, "second_access_log"),
		filepath.Join(root, "third_access_log"),
	}
	panel, server := platform.PanelNone, platform.WSApache
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{
		Panel: &panel, WebServer: &server,
		AccessLogPaths: candidates,
		ErrorLogPaths:  []string{filepath.Join(root, "error_log")},
	})
	t.Cleanup(platform.ResetForTest)
	if got := discoverAccessLogPath(); got != "" {
		t.Fatalf("discovered missing log: %q", got)
	}

	cfg := &config.Config{}
	cfg.MailLogs.Source = "file"
	cfg.MailLogs.File = filepath.Join(root, "mail_log")
	d := New(cfg, nil, nil, "")
	d.startLogWatchers()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	if err := os.WriteFile(candidates[2], nil, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		d.logWatchersMu.Lock()
		attached := false
		for _, w := range d.logWatchers {
			if w.path == candidates[2] {
				attached = true
			}
		}
		d.logWatchersMu.Unlock()
		if attached {
			return
		}
		select {
		case <-deadline:
			t.Fatal("retry did not attach to the later access-log candidate")
		case <-ticker.C:
		}
	}
}
