package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSensitiveWatchsetGlobsExpand(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(root, "etc/shadow"))
	mustWrite(filepath.Join(root, "etc/sudoers.d/dropin1"))
	mustWrite(filepath.Join(root, "etc/sudoers.d/dropin2"))
	mustWrite(filepath.Join(root, "etc/cron.d/anacron"))

	got := ExpandWatchset(root)

	want := map[string]bool{
		"etc/shadow":            true,
		"etc/sudoers.d/dropin1": true,
		"etc/sudoers.d/dropin2": true,
		"etc/cron.d/anacron":    true,
	}
	for _, p := range got {
		rel, _ := filepath.Rel(root, p)
		delete(want, rel)
	}
	if len(want) != 0 {
		t.Fatalf("watchset missing entries: %+v (got: %+v)", want, got)
	}
}

func TestEvaluateSensitiveFileWrite(t *testing.T) {
	cases := []struct {
		name        string
		uid         uint32
		path        string
		wantFinding bool
		wantSev     alert.Severity
	}{
		{"shadow_write_root", 0, "/etc/shadow", true, alert.High},
		{"shadow_write_user", 1000, "/etc/shadow", true, alert.Critical},
		{"sudoers_d_root", 0, "/etc/sudoers.d/91-extra", true, alert.High},
		{"sshd_config_user", 1000, "/etc/ssh/sshd_config", true, alert.Critical},
		{"crontab_user_root", 0, "/var/spool/cron/root", true, alert.High},
		{"unknown_path_returns_false", 1000, "/tmp/x", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := EvaluateSensitiveFileWrite(tc.path, tc.uid, 1234, "writer")
			if ok != tc.wantFinding {
				t.Fatalf("got finding=%v, want %v", ok, tc.wantFinding)
			}
			if ok && f.Severity != tc.wantSev {
				t.Fatalf("Severity = %v, want %v", f.Severity, tc.wantSev)
			}
		})
	}
}
