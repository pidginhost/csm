package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestStagingDirectoryFindingPresenceAndRemediation(t *testing.T) {
	root := t.TempDir()
	withQuarantineAllowedRoots(t, root)
	path := filepath.Join(root, "wp-content/upgrade/example-plugin.1.0")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	const check = "php_in_sensitive_dir_realtime"
	finding := alert.Finding{Check: check, Severity: alert.Warning, FilePath: path}
	if got := VerifyFinding(check, "", "", path); !got.Checked || got.Resolved {
		t.Fatalf("existing directory = %+v", got)
	}
	if HasFix(check) {
		t.Fatal("staging warning exposed a file remediation action")
	}
	if got := ApplyFix(context.Background(), check, "", "", path); got.Error == "" {
		t.Fatalf("unexpected remediation: %+v", got)
	}
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
	if got := AutoQuarantineFiles(cfg, []alert.Finding{finding}); len(got) != 0 {
		t.Fatalf("staging warning auto-remediated: %+v", got)
	}
	if _, eligible := QuarantineFindingFile(finding); eligible {
		t.Fatal("staging directory admitted for scan quarantine")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("staging directory was changed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := VerifyFinding(check, "", "", path); !got.Checked || !got.Resolved {
		t.Fatalf("removed directory = %+v", got)
	}
}
