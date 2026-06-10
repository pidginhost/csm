package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestParseValiasLine(t *testing.T) {
	tests := []struct {
		line      string
		localPart string
		dest      string
	}{
		{"info: admin@example.com", "info", "admin@example.com"},
		{"*: catchall@external.com", "*", "catchall@external.com"},
		{"user: |/usr/local/bin/script.sh", "user", "|/usr/local/bin/script.sh"},
		{"blackhole: /dev/null", "blackhole", "/dev/null"},
		{"multi: user1@example.com,user2@example.com", "multi", "user1@example.com,user2@example.com"},
		{"  info :  admin@example.com  ", "info", "admin@example.com"},
		{"# comment line", "", ""},
		{"", "", ""},
		{"nocolon", "", ""},
	}

	for _, tt := range tests {
		localPart, dest := parseValiasLine(tt.line)
		if localPart != tt.localPart || dest != tt.dest {
			t.Errorf("parseValiasLine(%q) = (%q, %q), want (%q, %q)",
				tt.line, localPart, dest, tt.localPart, tt.dest)
		}
	}
}

func TestIsPipeForwarder(t *testing.T) {
	tests := []struct {
		dest string
		pipe bool
	}{
		{"|/usr/local/bin/script.sh", true},
		{"| /path/to/cmd", true},
		{"user@example.com", false},
		{"/dev/null", false},
	}

	for _, tt := range tests {
		got := isPipeForwarder(tt.dest)
		if got != tt.pipe {
			t.Errorf("isPipeForwarder(%q) = %v, want %v", tt.dest, got, tt.pipe)
		}
	}
}

func TestIsDevNull(t *testing.T) {
	tests := []struct {
		dest    string
		devnull bool
	}{
		{"/dev/null", true},
		{" /dev/null ", false}, // already trimmed by parseValiasLine
		{"user@example.com", false},
		{"|/dev/null", false}, // pipe, not devnull
	}

	for _, tt := range tests {
		got := isDevNullForwarder(tt.dest)
		if got != tt.devnull {
			t.Errorf("isDevNullForwarder(%q) = %v, want %v", tt.dest, got, tt.devnull)
		}
	}
}

func TestIsExternalDest(t *testing.T) {
	localDomains := map[string]bool{
		"example.com":  true,
		"example.org":  true,
		"mydomain.net": true,
	}

	tests := []struct {
		dest     string
		external bool
	}{
		{"admin@example.com", false},
		{"user@example.org", false},
		{"user@gmail.com", true},
		{"user@external.io", true},
		{"|/path/to/script", false}, // pipe, not email
		{"/dev/null", false},        // devnull, not email
		{"localuser", false},        // local delivery, no @
	}

	for _, tt := range tests {
		got := isExternalDest(tt.dest, localDomains)
		if got != tt.external {
			t.Errorf("isExternalDest(%q) = %v, want %v", tt.dest, got, tt.external)
		}
	}
}

func TestParseVfilterExternalDests(t *testing.T) {
	content := `# Maildrop filter
if (/^From: .*spammer/)
{
  to "admin@gmail.com"
}
if (/^Subject: .*urgent/)
{
  to "backup@example.com"
}
to "alerts@external.io"
`

	localDomains := map[string]bool{
		"example.com": true,
	}

	dests := parseVfilterExternalDests(content, localDomains)

	found := make(map[string]bool)
	for _, d := range dests {
		found[d] = true
	}

	if !found["admin@gmail.com"] {
		t.Error("should detect admin@gmail.com as external")
	}
	if found["backup@example.com"] {
		t.Error("backup@example.com is local, should not be detected")
	}
	if !found["alerts@external.io"] {
		t.Error("should detect alerts@external.io as external")
	}
}

func TestLoadLocalDomains(t *testing.T) {
	// Test the parsing logic with sample content
	content := "example.com\nexample.org\n# comment\n\nmydomain.net\n"
	domains := parseLocalDomainsContent(content)

	if !domains["example.com"] {
		t.Error("should contain example.com")
	}
	if !domains["example.org"] {
		t.Error("should contain example.org")
	}
	if !domains["mydomain.net"] {
		t.Error("should contain mydomain.net")
	}
	if domains["# comment"] {
		t.Error("should not contain comment line")
	}
}

func TestIsKnownForwarder(t *testing.T) {
	knownForwarders := []string{
		"info@example.com: admin@gmail.com",
		"*@test.org: backup@external.io",
	}

	tests := []struct {
		localPart string
		domain    string
		dest      string
		known     bool
	}{
		{"info", "example.com", "admin@gmail.com", true},
		{"*", "test.org", "backup@external.io", true},
		{"info", "example.com", "other@gmail.com", false},
		{"user", "example.com", "admin@gmail.com", false},
	}

	for _, tt := range tests {
		got := isKnownForwarder(tt.localPart, tt.domain, tt.dest, knownForwarders)
		if got != tt.known {
			t.Errorf("isKnownForwarder(%q, %q, %q) = %v, want %v",
				tt.localPart, tt.domain, tt.dest, got, tt.known)
		}
	}
}

func TestCheckForwardersCanceledDuringMtimeRankDoesNotRefreshThrottle(t *testing.T) {
	db := withTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{"/etc/valiases/example.com"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			cancel()
			return statWithMtime{name: filepath.Base(name), modTime: now}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("example.com\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckForwarders(ctx, &config.Config{}, nil)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got != "" {
		t.Fatalf("email:fwd_last_refresh = %q, want empty after canceled rank", got)
	}
}

func TestForwarderFileIsNewQuadrants(t *testing.T) {
	db := withTestStore(t)
	const baselineKey = "email:fwd_last_refresh"
	const hashKey = "valiases:quad.test"

	// No stored hash, no baseline: first-install backlog, not new.
	if forwarderFileIsNew(db, baselineKey, hashKey, "h1") {
		t.Fatal("file with no hash before baseline must not be new (install flood protection)")
	}

	// No stored hash, baseline established: file appeared after a complete
	// audit, genuinely new.
	if err := db.SetMetaString(baselineKey, "2026-05-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if !forwarderFileIsNew(db, baselineKey, hashKey, "h1") {
		t.Fatal("file appearing after baseline must be new")
	}

	// Stored hash matches: unchanged, not new.
	if err := db.SetForwarderHash(hashKey, "h1"); err != nil {
		t.Fatal(err)
	}
	if forwarderFileIsNew(db, baselineKey, hashKey, "h1") {
		t.Fatal("unchanged file must not be new")
	}

	// Stored hash differs: changed, new.
	if !forwarderFileIsNew(db, baselineKey, hashKey, "h2") {
		t.Fatal("changed file must be new")
	}
}

// A valiases file that first appears after a completed audit is a classic
// BEC indicator (new domain or new forwarder drop) and must alert; the
// old first-sight suppression silenced it forever because the second scan
// saw an unchanged hash.
func TestCheckForwardersFlagsExternalForwarderInNewFileAfterBaseline(t *testing.T) {
	db := withTestStore(t)
	if err := db.SetMetaString("email:fwd_last_refresh", "2026-05-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	path := "/etc/valiases/newdomain.test"
	content := "victim: attacker@evil.example\n"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{path}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{path: now}),
		open: func(name string) (*os.File, error) {
			if name != path {
				return nil, os.ErrNotExist
			}
			tmp := filepath.Join(t.TempDir(), "valias")
			if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(tmp)
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("newdomain.test\n"), nil
			}
			if name == path {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	var hit bool
	for _, f := range findings {
		if f.Check == "email_suspicious_forwarder" && strings.Contains(f.Message, "newly added") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("new external forwarder file after baseline produced no finding: %+v", findings)
	}
}

// Before the first complete audit, unknown files are install backlog and
// must stay silent.
func TestCheckForwardersStaysSilentForUnknownFilesBeforeBaseline(t *testing.T) {
	withTestStore(t)

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	path := "/etc/valiases/legacy.test"
	content := "victim: customer@gmail.example\n"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{path}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{path: now}),
		open: func(name string) (*os.File, error) {
			if name != path {
				return nil, os.ErrNotExist
			}
			tmp := filepath.Join(t.TempDir(), "valias")
			if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(tmp)
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("legacy.test\n"), nil
			}
			if name == path {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	for _, f := range findings {
		if f.Check == "email_suspicious_forwarder" {
			t.Fatalf("pre-baseline file must not alert as new forwarder: %+v", f)
		}
	}
}

func TestCheckForwardersDoesNotBaselinePartialScan(t *testing.T) {
	db := withTestStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	oldPath := "/etc/valiases/aaa-legacy.test"
	recentPath := "/etc/valiases/zzz-recent.test"
	contents := map[string]string{
		oldPath:    "victim: attacker@evil.example\n",
		recentPath: "victim: other@evil.example\n",
	}

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{oldPath, recentPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-time.Hour),
			recentPath: now,
		}),
		open: func(name string) (*os.File, error) {
			content, ok := contents[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			path := filepath.Join(t.TempDir(), filepath.Base(name))
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(path)
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("aaa-legacy.test\nzzz-recent.test\n"), nil
			}
			content, ok := contents[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	if findings := CheckForwarders(context.Background(), cfg, nil); len(findings) != 0 {
		t.Fatalf("partial pre-baseline scan findings = %+v, want none", findings)
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got != "" {
		t.Fatalf("partial scan set baseline marker %q, want empty", got)
	}
	storedHash, found := db.GetForwarderHash("valiases:zzz-recent.test")
	if !found {
		t.Fatal("partial scan did not store the scanned file hash")
	}
	currentHash, err := fileContentHash(recentPath)
	if err != nil {
		t.Fatal(err)
	}
	if storedHash != currentHash {
		t.Fatalf("stored scanned hash %q, want current hash %q", storedHash, currentHash)
	}

	cfg.Thresholds.AccountScanMaxFiles = 0
	findings := CheckForwarders(context.Background(), cfg, nil)
	for _, f := range findings {
		if f.Check == "email_suspicious_forwarder" {
			t.Fatalf("file skipped before first complete audit must stay silent: %+v", f)
		}
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got == "" {
		t.Fatal("complete scan did not set baseline marker")
	}
}

func TestCheckForwardersDoesNotBaselineUnreadableValias(t *testing.T) {
	db := withTestStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	path := "/etc/valiases/legacy.test"
	content := "victim: attacker@evil.example\n"
	readable := false

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{path}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{path: now}),
		open: func(name string) (*os.File, error) {
			if name != path || !readable {
				return nil, os.ErrPermission
			}
			tmp := filepath.Join(t.TempDir(), "valias")
			if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(tmp)
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("legacy.test\n"), nil
			}
			if name == path && readable {
				return []byte(content), nil
			}
			return nil, os.ErrPermission
		},
	})

	if findings := CheckForwarders(context.Background(), &config.Config{}, nil); len(findings) != 0 {
		t.Fatalf("unreadable pre-baseline valias findings = %+v, want none", findings)
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got != "" {
		t.Fatalf("unreadable valias set baseline marker %q, want empty", got)
	}

	readable = true
	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	for _, f := range findings {
		if f.Check == "email_suspicious_forwarder" {
			t.Fatalf("valias unreadable during first audit must stay silent once readable: %+v", f)
		}
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got == "" {
		t.Fatal("complete valias scan did not set baseline marker")
	}
}

func TestAuditValiasFileDoesNotStoreHashAfterScannerError(t *testing.T) {
	db := withTestStore(t)
	path := "/etc/valiases/oversized.test"
	content := strings.Repeat("x", 70*1024)

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name != path {
				return nil, os.ErrNotExist
			}
			tmp := filepath.Join(t.TempDir(), "valias")
			if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(tmp)
		},
		readFile: func(name string) ([]byte, error) {
			if name == path {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings, ok := auditValiasFileWithStatus(path, "oversized.test", map[string]bool{"oversized.test": true}, &config.Config{})
	if ok {
		t.Fatal("oversized valias scan reported complete, want incomplete")
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none from unparsable valias file", findings)
	}
	if _, found := db.GetForwarderHash("valiases:oversized.test"); found {
		t.Fatal("incomplete valias scan stored forwarder hash")
	}
}

func TestCheckForwardersDoesNotBaselineUnreadableVfilter(t *testing.T) {
	db := withTestStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	path := "/etc/vfilters/legacy.test"
	content := "to \"attacker@evil.example\"\n"
	readable := false

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/vfilters/*" {
				return []string{path}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{path: now}),
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("legacy.test\n"), nil
			}
			if name == path && readable {
				return []byte(content), nil
			}
			return nil, os.ErrPermission
		},
	})

	if findings := CheckForwarders(context.Background(), &config.Config{}, nil); len(findings) != 0 {
		t.Fatalf("unreadable pre-baseline vfilter findings = %+v, want none", findings)
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got != "" {
		t.Fatalf("unreadable vfilter set baseline marker %q, want empty", got)
	}

	readable = true
	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	for _, f := range findings {
		if f.Check == "email_suspicious_forwarder" {
			t.Fatalf("vfilter unreadable during first audit must stay silent once readable: %+v", f)
		}
	}
	if got := db.GetMetaString("email:fwd_last_refresh"); got == "" {
		t.Fatal("complete vfilter scan did not set baseline marker")
	}
}

func TestCheckForwardersFlagsExternalVfilterInNewFileAfterBaseline(t *testing.T) {
	db := withTestStore(t)
	if err := db.SetMetaString("email:fwd_last_refresh", "2026-05-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	path := "/etc/vfilters/newdomain.test"
	content := `if
 $header_subject: contains "invoice"
then
 to "attacker@evil.example"
endif
`

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/vfilters/*" {
				return []string{path}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{path: now}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("newdomain.test\n"), nil
			case path:
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	var hit bool
	for _, f := range findings {
		if f.Check == "email_suspicious_forwarder" && strings.Contains(f.Message, "newly added") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("new external vfilter file after baseline produced no finding: %+v", findings)
	}
}

func TestCheckForwardersRanksValiasesByMtime(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	oldPath := "/etc/valiases/aaa-old.test"
	recentPath := "/etc/valiases/zzz-recent.test"
	contents := map[string]string{
		oldPath:    "info: |/usr/bin/old-forwarder\n",
		recentPath: "info: |/usr/bin/recent-forwarder\n",
	}
	var opened []string

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{oldPath, recentPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-time.Hour),
			recentPath: now,
		}),
		open: func(name string) (*os.File, error) {
			content, ok := contents[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			opened = append(opened, name)
			path := filepath.Join(t.TempDir(), filepath.Base(name))
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(path)
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("old.test\nrecent.test\n"), nil
			}
			content, ok := contents[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		},
	})

	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
	if len(opened) != 2 {
		t.Fatalf("opened = %v, want two valiases files", opened)
	}
	if opened[0] != recentPath || opened[1] != oldPath {
		t.Fatalf("opened = %v, want [%s %s]", opened, recentPath, oldPath)
	}
}

func TestCheckForwardersUsesAccountScanMaxFilesAfterMtimeRank(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	oldPath := "/etc/valiases/aaa-old.test"
	recentPath := "/etc/valiases/zzz-recent.test"
	contents := map[string]string{
		oldPath:    "info: |/usr/bin/old-forwarder\n",
		recentPath: "info: |/usr/bin/recent-forwarder\n",
	}
	var opened []string

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/valiases/*" {
				return []string{oldPath, recentPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-time.Hour),
			recentPath: now,
		}),
		open: func(name string) (*os.File, error) {
			content, ok := contents[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			opened = append(opened, name)
			path := filepath.Join(t.TempDir(), filepath.Base(name))
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return os.Open(path)
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/localdomains" {
				return []byte("old.test\nrecent.test\n"), nil
			}
			content, ok := contents[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckForwarders(context.Background(), cfg, nil)

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
	}
	if len(opened) != 1 || opened[0] != recentPath {
		t.Fatalf("opened = %v, want only %s", opened, recentPath)
	}
	if !strings.Contains(findings[0].Message, "recent-forwarder") {
		t.Fatalf("finding = %+v, want recent valiases file", findings[0])
	}
}
