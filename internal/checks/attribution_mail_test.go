package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// withOwnerTable maps example.com to alice and example.net to bob; every
// other domain is unmapped so its finding must stay unattributed.
func withOwnerTable(t *testing.T) {
	t.Helper()
	t.Cleanup(SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		switch domain {
		case "example.com":
			return "alice", true
		case "example.net":
			return "bob", true
		}
		return "", false
	}))
}

// openTempLog serves a fixture log through the osFS.Open seam tailFile uses.
func openTempLog(t *testing.T, body string) func(string) (*os.File, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return func(string) (*os.File, error) { return os.Open(path) } // #nosec G304 -- test fixture
}

func ownersByCheck(findings []alert.Finding, check string) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		if f.Check == check {
			out[f.TenantID]++
		}
	}
	return out
}

func TestMailPerAccountLeavesSenderAggregateUnattributed(t *testing.T) {
	withOwnerTable(t)
	var b strings.Builder
	for i := 0; i < perAccountMailThreshold; i++ {
		b.WriteString("2026-09-08 10:00:00 1abc23-000456-AB <= user@example.com H=localhost [127.0.0.1] P=local S=100\n")
		b.WriteString("2026-09-08 10:00:00 1abc23-000456-AC <= user@example.org H=localhost [127.0.0.1] P=local S=100\n")
	}
	withMockOS(t, &mockOS{open: openTempLog(t, b.String())})
	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	owners := ownersByCheck(findings, "mail_per_account")
	if owners[""] != 2 || len(owners) != 1 {
		t.Fatalf("owners %v from %+v", owners, findings)
	}
	for _, f := range findings {
		if got := extractAccountFromFinding(f); got != f.TenantID {
			t.Errorf("correlation account %q != TenantID %q", got, f.TenantID)
		}
	}
}

func TestForwarderFindingsStampOwner(t *testing.T) {
	withOwnerTable(t)
	withTestStore(t)
	files := map[string]string{
		"/etc/valiases/example.com": "sales: |/usr/local/bin/handler\ninfo: /dev/null\n",
		"/etc/valiases/example.org": "sales: |/usr/local/bin/handler\n",
		"/etc/localdomains":         "example.com\nexample.org\n",
	}
	// The audit reads valiases through osFS.Open, so each logical path is
	// backed by a real temporary file.
	backing := map[string]string{}
	for path, body := range files {
		real := filepath.Join(t.TempDir(), filepath.Base(path))
		if err := os.WriteFile(real, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		backing[path] = real
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{"/etc/valiases/example.com", "/etc/valiases/example.org"}, nil
			}
			return nil, nil
		},
		readFile: func(path string) ([]byte, error) {
			if body, ok := files[path]; ok {
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(path string) (*os.File, error) {
			if real, ok := backing[path]; ok {
				return os.Open(real) // #nosec G304 -- test fixture
			}
			return nil, os.ErrNotExist
		},
		stat: mtimesByPath(map[string]time.Time{"/etc/valiases/example.com": time.Now(), "/etc/valiases/example.org": time.Now()}),
	})
	findings := CheckForwarders(context.Background(), &config.Config{}, newTestStore(t))
	pipes := ownersByCheck(findings, "email_pipe_forwarder")
	if pipes["alice"] != 1 || pipes[""] != 1 {
		t.Fatalf("pipe forwarder owners %v from %+v", pipes, findings)
	}
	if blackholes := ownersByCheck(findings, "email_suspicious_forwarder"); blackholes["alice"] != 1 {
		t.Fatalf("blackhole owners %v", blackholes)
	}
	for _, f := range findings {
		if got := extractAccountFromFinding(f); got != f.TenantID {
			t.Errorf("%s: correlation account %q != TenantID %q", f.Check, got, f.TenantID)
		}
	}
}

func TestCPanelLoginFindingsStampOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	access := `203.0.113.5 - alice [08/Sep/2026:10:00:00 +0000] "POST /execute/Fileman/upload_files HTTP/1.1" 200 123 "https://example.com:2083/" "-" 2083` + "\n" +
		`203.0.113.6 - - [08/Sep/2026:10:00:01 +0000] "POST /execute/Fileman/upload_files HTTP/1.1" 200 123 "https://example.com:2083/" "-" 2083` + "\n"
	withMockOS(t, &mockOS{open: openTempLog(t, access)})
	findings := CheckCpanelFileManager(context.Background(), &config.Config{}, nil)
	uploads := ownersByCheck(findings, "cpanel_file_upload")
	if uploads["alice"] != 1 || uploads[""] != 1 {
		t.Fatalf("file upload owners %v from %+v", uploads, findings)
	}

	logins := ""
	stamp := time.Now().Format("2006-01-02 15:04:05 -0700")
	for _, ip := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"} {
		logins += "[" + stamp + "] info [cpaneld] " + ip + " NEW alice:token address=" + ip + ",app=cpaneld,method=handle_form_login\n"
	}
	withMockOS(t, &mockOS{open: openTempLog(t, logins)})
	multi := ownersByCheck(CheckCpanelLogins(context.Background(), &config.Config{}, newTestStore(t)), "cpanel_multi_ip_login")
	if multi["alice"] != 1 {
		t.Fatalf("multi-IP login owners %v", multi)
	}
}

func TestFTPLoginAfterBruteforceStampsOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	withOwnerTable(t)
	cases := map[string]string{
		"alice":               "alice",
		"ftpuser@example.com": "alice",
		"nobody":              "",
		"ftpuser@example.org": "",
	}
	for account, want := range cases {
		f := ftpLoginFinding("203.0.113.9", "[08/Sep/2026 10:00:00] 203.0.113.9 "+account+" is now logged in", ftpFailThreshold)
		if f.Check != "ftp_login_after_bruteforce" || f.TenantID != want {
			t.Errorf("%s: %+v (want owner %q)", account, f, want)
		}
	}
}

func TestMailVolumeDoesNotTrustEnvelopeOwner(t *testing.T) {
	withOwnerTable(t)
	for _, fields := range []string{
		"H=mail.example.org [203.0.113.5] P=esmtp",
		"H=mail.example.org [203.0.113.5] P=esmtpsa A=dovecot_login:user@example.net",
	} {
		line := "2026-09-08 10:00:00 1abc23-000456-AB <= user@example.com " + fields + " S=100\n"
		withMockOS(t, &mockOS{open: openTempLog(t, strings.Repeat(line, perAccountMailThreshold))})
		findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
		if len(findings) != 1 || findings[0].Check != "mail_per_account" {
			t.Fatalf("findings = %+v", findings)
		}
		if findings[0].TenantID != "" {
			t.Errorf("sender-domain aggregate assigned to %q", findings[0].TenantID)
		}
	}
}

func TestCpanelMultiIPLoginDoesNotAttributeSystemUser(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	var lines strings.Builder
	stamp := time.Now().Format("2006-01-02 15:04:05 -0700")
	for _, user := range []string{"alice", "root", "nobody"} {
		for _, ip := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"} {
			lines.WriteString("[" + stamp + "] info [cpaneld] " + ip + " NEW " + user + ":fixture address=" + ip + ",app=cpaneld,method=handle_form_login\n")
		}
	}
	withMockOS(t, &mockOS{open: openTempLog(t, lines.String())})
	got := ownersByCheck(CheckCpanelLogins(context.Background(), &config.Config{}, nil), "cpanel_multi_ip_login")
	if len(got) != 2 || got["alice"] != 1 || got[""] != 2 {
		t.Fatalf("owners = %v, want alice and two unattributed rows", got)
	}
}
