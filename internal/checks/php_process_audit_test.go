package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestPHPProcessAuditKeepsDistinctObservations(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) {
			return []string{"/proc/4242/cmdline", "/proc/4243/cmdline"}, nil
		},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/proc/4242/cmdline":
				return []byte("lsphp\x00/var/www/example/wp-content/uploads/first.php\x00"), nil
			case "/proc/4243/cmdline":
				return []byte("lsphp\x00/var/www/example/wp-content/uploads/second.php\x00"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})
	findings := CheckPHPProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) != 2 {
		t.Fatalf("detected %d PHP processes, want two", len(findings))
	}
	// The runner assigns one timestamp to unstamped findings in a scan.
	alert.FillTimestamps(findings, time.Unix(123, 0))
	if findings[0].Details == findings[1].Details {
		t.Fatal("separate processes lost their distinguishing evidence")
	}
	if alert.FindingID(findings[0]) != alert.FindingID(findings[1]) {
		t.Fatal("fixture no longer exercises a shared legacy audit identity")
	}

	alert.CloseAuditSinks()
	t.Cleanup(alert.CloseAuditSinks)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.AuditLog.File.Enabled = true
	cfg.Alerts.AuditLog.File.Path = path
	assertRecordedOnce := func() {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		counts := make(map[string]int)
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var event alert.AuditEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			counts[event.Details]++
		}
		for _, f := range findings {
			if count := counts[f.Details]; count != 1 {
				t.Errorf("process %d has %d audit records, want one", f.PID, count)
			}
		}
	}
	if err := alert.DispatchWithSources(cfg, nil, findings); err != nil {
		t.Fatal(err)
	}
	assertRecordedOnce()
	// Replays in separate batches must preserve both original observations
	// without producing another row for either process.
	for i := len(findings) - 1; i >= 0; i-- {
		if err := alert.DispatchWithSources(cfg, nil, findings[i:i+1]); err != nil {
			t.Fatal(err)
		}
	}
	assertRecordedOnce()
}
