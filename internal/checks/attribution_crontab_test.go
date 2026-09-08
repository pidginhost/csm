package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

type spoolDirInfo struct{ name string }

func (d spoolDirInfo) Name() string       { return d.name }
func (d spoolDirInfo) Size() int64        { return 0 }
func (d spoolDirInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (d spoolDirInfo) ModTime() time.Time { return time.Now() }
func (d spoolDirInfo) IsDir() bool        { return true }
func (d spoolDirInfo) Sys() interface{}   { return nil }

// A suspicious crontab is attributed to the spool's owner only when that
// owner is a hosting account: root and service spools stay unattributed.
func TestSuspiciousCrontabStampsSpoolOwner(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	writePasswdFixture(t, "/home")
	spool := "/var/spool/cron"
	prevSpool := cronSpoolDir
	cronSpoolDir = func() string { return spool }
	t.Cleanup(func() { cronSpoolDir = prevSpool })

	// A comment carrying one matcher token is inert but still matches.
	line := "# csm-fixture token: reverse\n"
	files := map[string]string{
		filepath.Join(spool, "alice"):  line,
		filepath.Join(spool, "root"):   line,
		filepath.Join(spool, "nobody"): line,
	}
	dirs := map[string]bool{"/home/alice": true, "/home/nobody": true}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join(spool, "*") {
				return []string{filepath.Join(spool, "alice"), filepath.Join(spool, "root"), filepath.Join(spool, "nobody")}, nil
			}
			return nil, nil
		},
		readFile: func(path string) ([]byte, error) {
			if body, ok := files[path]; ok {
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(path string) (os.FileInfo, error) {
			if dirs[path] {
				return spoolDirInfo{name: filepath.Base(path)}, nil
			}
			if _, ok := files[path]; ok {
				return mtimesByPath(map[string]time.Time{path: time.Now()})(path)
			}
			return nil, os.ErrNotExist
		},
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})

	owners := map[string]string{}
	for _, f := range CheckCrontabs(context.Background(), &config.Config{}, newTestStore(t)) {
		if f.Check == "suspicious_crontab" {
			owners[filepath.Base(f.FilePath)] = f.TenantID
			if got := extractAccountFromFinding(f); got != f.TenantID {
				t.Errorf("%s: correlation account %q != TenantID %q", f.FilePath, got, f.TenantID)
			}
		}
	}
	if len(owners) != 2 {
		t.Fatalf("want alice and nobody spools, got %v", owners)
	}
	if owners["alice"] != "alice" {
		t.Errorf("alice spool owner = %q", owners["alice"])
	}
	if owners["nobody"] != "" {
		t.Errorf("service spool promoted to hosting owner: %q", owners["nobody"])
	}
	if _, reported := owners["root"]; reported && owners["root"] != "" {
		t.Errorf("root spool attributed: %q", owners["root"])
	}
}
