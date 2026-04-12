package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
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

func TestCheckOutboundEmailContentWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "input") {
				return []os.DirEntry{testDirEntry{name: "ABC123-H", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte("From: alice@example.com\nSubject: Normal email\n"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "ABC123-H", size: 500}, nil
		},
	})

	_ = CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
}
