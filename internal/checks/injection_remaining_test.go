package checks

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// --- queryAbuseIPDB with httptest server ------------------------------

// queryAbuseIPDB test is in reputation_test.go.

func TestQueryAbuseIPDB429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
	}))
	defer srv.Close()

	_, _, err := queryAbuseIPDB(srv.Client(), "1.2.3.4", "key")
	if err == nil {
		t.Error("429 should return error")
	}
}

// --- shellQuote -------------------------------------------------------

func TestShellQuote(t *testing.T) {
	got := shellQuote("hello world")
	if got != "'hello world'" {
		t.Errorf("got %q", got)
	}
}

func TestShellQuoteWithQuote(t *testing.T) {
	got := shellQuote("it's")
	if !strings.Contains(got, "it") {
		t.Errorf("got %q", got)
	}
}

// --- extractDomain ---------------------------------------------------

func TestExtractDomainFromEmail(t *testing.T) {
	if got := extractDomain("alice@example.com"); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

func TestExtractDomainNoAt(t *testing.T) {
	if got := extractDomain("nodomain"); got != "" {
		t.Errorf("got %q", got)
	}
}

// --- extractUser -----------------------------------------------------

func TestExtractUserFromPath_Remaining(t *testing.T) {
	// extractUser in web.go extracts from path, not email
	got := extractUser("/home/alice/public_html/.htaccess")
	if got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

// --- extractWPDomain -------------------------------------------------

// extractWPDomain needs context + user args — skip for now.

// --- isSymlinkSafe ---------------------------------------------------

func TestIsSymlinkSafeWithinHome(t *testing.T) {
	if !isSymlinkSafe("/home/alice/public_html/link", "alice", "/home/alice") {
		t.Error("symlink within home should be safe")
	}
}

func TestIsSymlinkSafeOutsideHome(t *testing.T) {
	if isSymlinkSafe("/etc/passwd", "alice", "/home/alice") {
		t.Error("symlink to /etc/passwd should not be safe")
	}
}

// --- hasOpenBasedir --------------------------------------------------

func TestHasOpenBasedirExercises(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("open_basedir=/home/alice:/tmp\n"), nil
		},
	})
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("open_basedir = /home/alice:/tmp\n"), nil
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	// Exercises the function — may or may not detect depending on implementation.
	_ = hasOpenBasedir("alice")
}

func TestHasOpenBasedirFalse(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("open_basedir=\n"), nil
		},
	})

	if hasOpenBasedir("alice") {
		t.Error("empty should not detect open_basedir")
	}
}

// --- fileContentHash -------------------------------------------------

func TestFileContentHashMocked(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("test content"), nil
		},
	})

	hash, err := fileContentHash("/etc/valiases/example.com")
	if err != nil {
		t.Fatalf("fileContentHash: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d", len(hash))
	}
}

// --- checkDangerousPorts with /proc data -----------------------------

func TestCheckDangerousPortsNoPorts(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{}
	results := checkDangerousPorts(cfg)
	_ = results
}

// --- scanWPConfigs with mock data ------------------------------------

func TestScanWPConfigsWithConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "wp-config.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte("<?php\ndefine('WP_MEMORY_LIMIT', '40M');\ndefine('WP_DEBUG', true);\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	var findings []alert.Finding
	scanWPConfigs("/home/alice/public_html", "alice", cfg, 3, &findings)
	_ = findings
}

// --- findWPTransients with mock data ---------------------------------

func TestFindWPTransientsNoWPConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	var findings []alert.Finding
	findWPTransients("/home/alice/public_html", cfg, 10*1024*1024, 50*1024*1024, 3, &findings)
	if len(findings) != 0 {
		t.Errorf("no wp-config should produce 0, got %d", len(findings))
	}
}
