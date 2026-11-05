package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestFTPScanLoginUsesAuthenticatedPeer(t *testing.T) {
	for _, withStore := range []bool{false, true} {
		name := "legacy"
		if withStore {
			name = "stored"
		}
		t.Run(name, func(t *testing.T) {
			var st *state.Store
			if withStore {
				var err error
				st, err = state.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = st.Close() })
			}
			at := time.Now().Add(-time.Hour).Truncate(time.Second)
			prefix := at.Format(time.RFC3339) + " 192.0.2.1 pure-ftpd[1]: "
			lines := []string{
				prefix + "203.0.113.9 [INFO] alice is now logged in",
				prefix + "2001:db8::9 [INFO] bob is now logged in",
				prefix + "(?@host.example.com) [INFO] 198.51.100.9 is now logged in",
				prefix + "(?@203.0.113.8) [DEBUG] Command [USER] [alice is now logged in]",
			}
			path := filepath.Join(t.TempDir(), "messages")
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
			findings := CheckFTPLogins(context.Background(), &config.Config{}, st)
			if len(findings) != 2 {
				t.Fatalf("findings = %+v, want exactly two logins", findings)
			}
			for i, ip := range []string{"203.0.113.9", "2001:db8::9"} {
				f := findings[i]
				if f.Check != "ftp_login" || f.SourceIP != ip || !f.Timestamp.Equal(at) {
					t.Errorf("finding = %+v, want login from %s at %s", f, ip, at)
				}
			}
		})
	}
}
