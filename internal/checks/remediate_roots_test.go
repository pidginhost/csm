package checks

import "testing"

// A fix target must lie strictly below a remediation root. The root itself
// (/home, /tmp, /var/tmp) and an account's home directory are never
// remediation targets: quarantining one renames the whole tree away.
func TestSanitizeFixPathRefusesRootsAndAccountHomes(t *testing.T) {
	roots := []string{"/home", "/tmp", "/dev/shm", "/var/tmp"}
	for _, p := range []string{"/home", "/home/", "/tmp", "/var/tmp", "/dev/shm", "/home/alice", "/home/alice/", "/home/alice/.."} {
		if got, err := sanitizeFixPath(p, roots); err == nil {
			t.Errorf("sanitizeFixPath(%q) = %q, want refusal", p, got)
		}
	}
	for _, p := range []string{"/home/alice/public_html/evil.php", "/home/alice/evil.php", "/tmp/miner", "/var/tmp/.x/run.sh"} {
		if _, err := sanitizeFixPath(p, roots); err != nil {
			t.Errorf("sanitizeFixPath(%q): %v, want accepted", p, err)
		}
	}
}
