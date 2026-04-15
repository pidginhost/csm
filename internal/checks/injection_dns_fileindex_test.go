package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// --- resolveDNSServerUIDs ---------------------------------------------

func TestResolveDNSServerUIDsParsesPasswdFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/passwd" {
				return []byte(strings.Join([]string{
					"root:x:0:0:root:/root:/bin/bash",
					"named:x:25:25:Named:/var/named:/sbin/nologin",
					"unbound:x:1001:1001:Unbound:/var/lib/unbound:/sbin/nologin",
					"pdns:x:953:953::/var/spool/powerdns:/sbin/nologin",
					"alice:x:1000:1000::/home/alice:/bin/bash",
					"corrupt-line-with-no-fields",
				}, "\n")), nil
			}
			return nil, os.ErrNotExist
		},
	})

	got := resolveDNSServerUIDs()
	for _, want := range []string{"25", "1001", "953"} {
		if !got[want] {
			t.Errorf("expected DNS server UID %s, got %v", want, got)
		}
	}
	if got["0"] || got["1000"] {
		t.Errorf("non-DNS UIDs should not appear, got %v", got)
	}
}

func TestResolveDNSServerUIDsMissingPasswdReturnsEmpty(t *testing.T) {
	withMockOS(t, &mockOS{}) // ReadFile defaults to ErrNotExist
	got := resolveDNSServerUIDs()
	if len(got) != 0 {
		t.Errorf("missing /etc/passwd should yield empty map, got %v", got)
	}
}

// --- parseResolvers ---------------------------------------------------

func TestParseResolversParsesNameserverLines(t *testing.T) {
	tmp := t.TempDir()
	resolv := filepath.Join(tmp, "resolv.conf")
	content := strings.Join([]string{
		"# /etc/resolv.conf",
		"search example.com",
		"nameserver 1.1.1.1",
		"nameserver 8.8.8.8",
		"options ndots:1",
		"nameserver  2001:4860:4860::8888",
	}, "\n")
	if err := os.WriteFile(resolv, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/etc/resolv.conf" {
				return os.Open(resolv)
			}
			return nil, os.ErrNotExist
		},
	})

	got := parseResolvers()
	want := []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"}
	if len(got) != len(want) {
		t.Fatalf("expected %d resolvers, got %d: %v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("resolver[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestParseResolversMissingFileReturnsNil(t *testing.T) {
	withMockOS(t, &mockOS{}) // Open defaults to ErrNotExist
	if got := parseResolvers(); got != nil {
		t.Errorf("missing /etc/resolv.conf should return nil, got %v", got)
	}
}

// --- scanDirForExecutables --------------------------------------------

func TestScanDirForExecutablesDepthZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "x"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	var entries []string
	scanDirForExecutables(tmp, 0, dirMtimeCache{}, nil, true, &entries)
	if len(entries) != 0 {
		t.Errorf("depth=0 should yield no entries, got %v", entries)
	}
}

func TestScanDirForExecutablesMissingDir(t *testing.T) {
	var entries []string
	scanDirForExecutables("/nonexistent-dir-xyz", 4, dirMtimeCache{}, nil, true, &entries)
	if len(entries) != 0 {
		t.Errorf("missing dir should yield no entries, got %v", entries)
	}
}

func TestScanDirForExecutablesIgnoresNonExecutable(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "data.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var entries []string
	scanDirForExecutables(tmp, 4, dirMtimeCache{}, nil, true, &entries)
	if len(entries) != 0 {
		t.Errorf("non-executable file should be ignored, got %v", entries)
	}
}

func TestScanDirForExecutablesFlagsExecutable(t *testing.T) {
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "binary")
	if err := os.WriteFile(exe, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	var entries []string
	scanDirForExecutables(tmp, 4, dirMtimeCache{}, nil, true, &entries)
	if len(entries) != 1 || filepath.Base(entries[0]) != "binary" {
		t.Errorf("expected one executable flagged, got %v", entries)
	}
}

func TestScanDirForExecutablesUsesPrevWhenUnchanged(t *testing.T) {
	tmp := t.TempDir()
	info, _ := os.Stat(tmp)
	cache := dirMtimeCache{tmp: info.ModTime().Unix()}
	prev := map[string][]string{tmp: {"/cached/binary"}}

	var entries []string
	scanDirForExecutables(tmp, 4, cache, prev, false, &entries)
	if len(entries) != 1 || entries[0] != "/cached/binary" {
		t.Errorf("expected cached entries reused, got %v", entries)
	}
}

func TestScanDirForExecutablesRecursesIntoSubdirs(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "deep")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(sub, "buried")
	if err := os.WriteFile(exe, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	var entries []string
	scanDirForExecutables(tmp, 4, dirMtimeCache{}, nil, true, &entries)
	found := false
	for _, e := range entries {
		if filepath.Base(e) == "buried" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected nested executable to be flagged, got %v", entries)
	}
}

// --- extractPHPDefine unquoted-value regression ------------------------

func TestExtractPHPDefineUnquotedBooleanAndNumber(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"define('DISABLE_WP_CRON', true);", "true"},
		{"define('WP_DEBUG', false);", "false"},
		{"define('WP_MEMORY_LIMIT', 256);", "256"},
		// Quoted strings still work (regression check).
		{"define('DB_NAME', 'wordpress');", "wordpress"},
	}
	for _, c := range cases {
		if got := extractPHPDefine(c.in); got != c.want {
			t.Errorf("extractPHPDefine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- scanWPCron --------------------------------------------------------

func TestScanWPCronMissingDir(t *testing.T) {
	var findings []alert.Finding
	scanWPCron("/no-such-dir", "alice", 4, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should yield no findings, got %d", len(findings))
	}
}

func TestScanWPCronDepthBelowZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"),
		[]byte("<?php "), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanWPCron(tmp, "alice", -1, &findings)
	if len(findings) != 0 {
		t.Errorf("depth<0 should yield no findings, got %d", len(findings))
	}
}

func TestScanWPCronEmitsWhenWPCronEnabled(t *testing.T) {
	tmp := t.TempDir()
	// wp-config.php that does NOT define DISABLE_WP_CRON → treated as
	// enabled (default), should emit a Warning finding.
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"),
		[]byte("<?php\ndefine('DB_NAME', 'wp');\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanWPCron(tmp, "alice", 4, &findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %+v", len(findings), findings)
	}
	if findings[0].Check != "perf_wp_cron" || findings[0].Severity != alert.Warning {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestScanWPCronSilentWhenWPCronDisabled(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "wp-config.php"),
		[]byte("<?php\ndefine('DISABLE_WP_CRON', true);\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanWPCron(tmp, "alice", 4, &findings)
	if len(findings) != 0 {
		t.Errorf("DISABLE_WP_CRON=true should produce no findings, got %+v", findings)
	}
}

func TestScanWPCronRecursesIntoSubdirs(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "subsite")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "wp-config.php"),
		[]byte("<?php "), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanWPCron(tmp, "alice", 4, &findings)
	if len(findings) != 1 {
		t.Errorf("expected nested wp-config.php to be flagged, got %d: %+v", len(findings), findings)
	}
}
