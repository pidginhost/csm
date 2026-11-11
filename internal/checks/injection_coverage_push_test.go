package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckExfiltration functions with /proc data ---------------------

func TestCheckOutboundPasteSitesWithConnections(t *testing.T) {
	// Simulate connection to pastebin IP (not actually checked by IP, but exercises the code)
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte("  sl  local_address rem_address   st\n   0: 0100007F:C000 CB007105:0050 01 00000000:00000000 00:00000000 00000000  1000\n"), nil
			}
			if name == "/etc/passwd" {
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "ss" || name == "lsof" {
				return []byte(""), nil
			}
			return nil, nil
		},
	})

	findings := CheckOutboundPasteSites(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckFileIndex with home dir data --------------------------------

func TestCheckFileIndexWithHome(t *testing.T) {
	stateDir := t.TempDir()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "wp-content/uploads") {
				return []os.DirEntry{testDirEntry{name: "evil.php", isDir: false}}, nil
			}
			if strings.Contains(name, "alice") {
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
	})

	cfg := &config.Config{StatePath: stateDir}
	findings := CheckFileIndex(context.Background(), cfg, nil)
	_ = findings
}

// --- CheckForwarders with valiases data ------------------------------

func TestCheckForwardersWithValiases(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "valiases") {
				return []string{"/etc/valiases/example.com"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "valiases") {
				tmp := t.TempDir() + "/valiases"
				_ = os.WriteFile(tmp, []byte("catch: |/usr/bin/malware\ninfo: external@hacker.com\n"), 0644)
				return os.Open(tmp)
			}
			if strings.Contains(name, "localdomains") {
				tmp := t.TempDir() + "/localdomains"
				_ = os.WriteFile(tmp, []byte("example.com\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "localdomains") {
				return []byte("example.com\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckDNSZoneChanges with whmapi data ----------------------------

func TestCheckDNSZoneChangesWithData(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(`{"data":{"zone":[{"domain":"example.com"}]}}`), nil
			}
			return nil, nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckDNSZoneChanges(context.Background(), &config.Config{}, store)
}

// --- CheckSSLCertIssuance with whmapi data ---------------------------

func TestCheckSSLCertIssuanceWithData(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(`{"data":{"certificates":[]}}`), nil
			}
			return nil, nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckSSLCertIssuance(context.Background(), &config.Config{}, store)
}

// --- CheckDatabaseContent with home data -----------------------------

func TestCheckDatabaseContentWithHome(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	_ = CheckDatabaseContent(context.Background(), &config.Config{}, nil)
}

// --- CheckEmailPasswords with shadow data ----------------------------

func TestCheckEmailPasswordsWithShadowFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "shadow") {
				tmp := t.TempDir() + "/shadow"
				_ = os.WriteFile(tmp, []byte("info:{BLF-CRYPT}$2y$05$hash\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	_ = CheckEmailPasswords(context.Background(), &config.Config{}, nil)
}

// --- CheckCpanelFileManager with log data ----------------------------

func TestCheckCpanelFileManagerWithLog(t *testing.T) {
	logData := `203.0.113.5 - alice [12/Apr/2026:10:00:00 +0000] "POST /execute/Fileman/upload_files HTTP/1.1" 200 123 "https://example.com:2083/" "-"` + "\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
		},
	})

	findings := CheckCpanelFileManager(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckOutboundEmailContent with spool files ----------------------

// A mailbox user's ordinary mail stays quiet, but phishing in its body must
// be reported even when the headers carry no indicator.
func TestCheckOutboundEmailContentWithFiles(t *testing.T) {
	const msgID = "1vOutA-000001-AB"
	const spoolMessage = "/var/spool/exim/input/A/" + msgID
	logPath := filepath.Join(t.TempDir(), "exim_mainlog")
	line := "2026-11-09 10:00:00 " + msgID + " <= alice@example.com H=(client) [203.0.113.9]:4000 P=esmtpsa A=dovecot_login:alice@example.com S=900 T=\"Normal email\" for bob@example.net\n"
	if err := os.WriteFile(logPath, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"ordinary", "Hello Bob, here are the meeting notes.", 0},
		{"phishing body", "Verify your account. Confirm your identity at https://example.org/redirect?url=https://example.net/", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads []string
			withMockOS(t, &mockOS{
				open: func(name string) (*os.File, error) {
					if name == platform.EximMainLog {
						return os.Open(logPath)
					}
					return nil, os.ErrNotExist
				},
				readFile: func(name string) ([]byte, error) {
					reads = append(reads, name)
					switch name {
					case spoolMessage + "-H":
						return []byte("From: alice@example.com\nSubject: Normal email\n"), nil
					case spoolMessage + "-D":
						return []byte(msgID + "-D\n" + tc.body), nil
					}
					return nil, os.ErrNotExist
				},
				stat: func(name string) (os.FileInfo, error) {
					if name == spoolMessage+"-H" {
						return fakeFileInfo{name: filepath.Base(name), size: 500}, nil
					}
					return nil, os.ErrNotExist
				},
			})

			findings := CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
			if want := []string{spoolMessage + "-H", spoolMessage + "-D"}; !slices.Equal(reads, want) {
				t.Errorf("spool reads = %v, want %v", reads, want)
			}
			if len(findings) != tc.want {
				t.Fatalf("findings = %+v, want %d", findings, tc.want)
			}
			if tc.want == 0 {
				return
			}
			f := findings[0]
			if f.Check != "email_phishing_content" || f.Severity != alert.High {
				t.Errorf("finding = %+v, want a high-severity outbound phishing finding", f)
			}
			if f.Mailbox != "alice@example.com" || f.Domain != "example.com" || !strings.Contains(f.Message, msgID) {
				t.Errorf("finding lost the outbound message identity: %+v", f)
			}
			for _, indicator := range []string{"phishing URL pattern: /redirect?url=", "credential harvesting language"} {
				if !strings.Contains(f.Details, indicator) {
					t.Errorf("details = %q, want body indicator %q", f.Details, indicator)
				}
			}
		})
	}
}
