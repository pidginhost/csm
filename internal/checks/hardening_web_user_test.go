package checks

import (
	"os"
	"testing"
)

func withWebServerUsers(t *testing.T, users []string, spool string) {
	t.Helper()
	oldUsers, oldSpool := webServerUsers, cronSpoolDir
	webServerUsers = func() []string { return users }
	cronSpoolDir = func() string { return spool }
	t.Cleanup(func() {
		webServerUsers = oldUsers
		cronSpoolDir = oldSpool
	})
}

// The nobody-crontab audit looked only at /var/spool/cron/nobody. On a
// Debian Plesk host the web server runs as www-data with crontabs under
// /var/spool/cron/crontabs, so a planted www-data crontab passed the audit.
func TestAuditOSWebUserCronUsesPlatformUser(t *testing.T) {
	withWebServerUsers(t, []string{"www-data"}, "/var/spool/cron/crontabs")
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/spool/cron/crontabs/www-data" {
				return fakeFileInfo{name: "www-data", size: 64}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_nobody_cron" {
			if r.Status != "fail" {
				t.Fatalf("www-data crontab with content should fail, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Fatal("os_nobody_cron result not found")
}

// The group-writable PHP scan only knew cPanel/Apache group names, so
// nginx-owned group-writable files on a panel-less host were invisible.
func TestGetWebServerGIDsIncludesPlatformUsers(t *testing.T) {
	withWebServerUsers(t, []string{"nginx"}, "/var/spool/cron")
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/group" {
				return []byte("root:x:0:\nnginx:x:990:\nnobody:x:65534:\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	gids := getWebServerGIDs()
	if !gids[990] {
		t.Fatalf("nginx gid 990 missing from web server GIDs: %v", gids)
	}
	if !gids[65534] {
		t.Fatalf("nobody must stay in the set: %v", gids)
	}
}
