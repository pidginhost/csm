package checks

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Debian's cron keeps user crontabs under /var/spool/cron/crontabs; the
// sensitive-file watchset must cover that layout too.
func TestExpandWatchsetIncludesDebianCrontabs(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var/spool/cron/alice", "var/spool/cron/crontabs/bob"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("0 * * * * /bin/true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := ExpandWatchset(root)
	for _, want := range []string{filepath.Join(root, "var/spool/cron/alice"), filepath.Join(root, "var/spool/cron/crontabs/bob")} {
		if !slices.Contains(got, want) {
			t.Errorf("watchset misses %s", want)
		}
	}
}
