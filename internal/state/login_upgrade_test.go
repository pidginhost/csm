package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestLoginUpgradeStoredSuppressions(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for old, current := range map[string]string{
		"ftp_login_realtime": "ftp_login",
		"ssh_login_realtime": "ssh_login_unknown_ip",
	} {
		for _, check := range []string{old, current} {
			if err := s.SaveSuppressions([]SuppressionRule{{ID: "mute", Check: check, PathPattern: "/home/account/*"}}); err != nil {
				t.Fatal(err)
			}
			rules := s.LoadSuppressions()
			for _, name := range []string{old, current} {
				if !s.IsSuppressed(alert.Finding{Check: name, FilePath: "/home/account/file"}, rules) {
					t.Errorf("stored %s rule does not mute %s", check, name)
				}
				if s.IsSuppressed(alert.Finding{Check: name, FilePath: "/home/other/file"}, rules) {
					t.Error("upgrade broadened a path-scoped mute")
				}
			}
		}
	}
}
