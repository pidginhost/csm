package daemon

import (
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The action log lives beside the SIEM audit log, so an operator who moved
// their log directory gets both streams in the same place.
func TestActionLogPathFollowsTheAuditLogDirectory(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.AuditLog.File.Path = "/srv/logs/csm/audit.jsonl"

	if got, want := actionLogPath(cfg), "/srv/logs/csm/actions.jsonl"; got != want {
		t.Fatalf("action log path = %q, want %q", got, want)
	}
}

func TestActionLogPathFallsBackToThePackagedLogDirectory(t *testing.T) {
	if got, want := actionLogPath(&config.Config{}), filepath.Join(defaultLogDir, "actions.jsonl"); got != want {
		t.Fatalf("action log path = %q, want %q", got, want)
	}
}
