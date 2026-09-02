package checks

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// The target of auto_prepend_file is text the account owner writes. Judging
// it by substrings ("litespeed", ".ttf") or by a short list of always-bad
// locations lets an attacker pick any path that contains a safe word or sits
// outside /tmp. Anything inside an account tree that is not a known security
// plugin prelude is suspicious; a root-owned system path is not.
func TestDetectorAutoPrependFlagsAccountTargets(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"font file under uploads", "/home/victim/public_html/wp-content/uploads/fonts/x.ttf", 1},
		{"php under a dir named litespeed", "/home/u/public_html/wp-content/litespeed/x.php", 1},
		{"php inside wp-includes", "/home/u/public_html/wp-includes/class-wp-hook-x.php", 1},
		{"relative to docroot", "x.php", 1},
		{"no extension", "/home/u/.cache/prelude", 1},
		{"wordfence prelude by basename", "/home/u/public_html/wp-content/plugins/wordfence/../../wordfence-waf.php", 0},
		{"wordfence prelude relative", "wordfence-waf.php", 0},
		{"really simple ssl prelude", "/home/u/public_html/wp-content/advanced-headers.php", 0},
		{"disabling an inherited prelude", "none", 0},
		{"root-owned system prelude", "/etc/csm-prelude.php", 0},
		{"quoted root-owned system prelude", `"/etc/csm/prelude file.php"`, 0},
		{"single-quoted root-owned system prelude", `'/etc/csm/prelude file.php'`, 0},
		{"quoted traversal into home", `"/etc/../home/alice/prelude file.php"`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeHtaccess(t, dir, "site", "php_value auto_prepend_file "+c.target+"\n")
			findings, _ := AuditHtaccessFile(path)
			if got := countByCheck(findings, "htaccess_auto_prepend"); got != c.want {
				t.Errorf("target %q: htaccess_auto_prepend = %d, want %d", c.target, got, c.want)
			}
		})
	}
}

// Apache accepts quoted directive arguments. The legacy scanner must parse
// the complete target, including spaces, before deciding whether its location
// is account-controlled.
func TestCheckHtaccessFileAutoPrependParsesQuotedTarget(t *testing.T) {
	for _, tc := range []struct {
		directive string
		target    string
		want      int
	}{
		{"auto_prepend_file", `"/etc/csm/prelude file.php"`, 0},
		{"auto_prepend_file", `"/home/victim/prelude file.php"`, 1},
		{"auto_append_file", `"/etc/csm/append file.php"`, 0},
		{"auto_append_file", `"/home/victim/append file.php"`, 1},
	} {
		tmp := t.TempDir() + "/.htaccess"
		if err := os.WriteFile(tmp, []byte("php_value "+tc.directive+" "+tc.target+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(tmp) }})

		var findings []alert.Finding
		checkHtaccessFile(tmp, []string{"auto_prepend_file", "auto_append_file"}, nil, &findings)
		if len(findings) != tc.want {
			t.Errorf("%s target %q: findings = %d, want %d", tc.directive, tc.target, len(findings), tc.want)
		}
	}
}

// An uncontinued newline terminates an Apache directive. The detector must
// not consume the next directive as the missing target and then remove both
// lines during cleaning.
func TestDetectAutoPrependDoesNotCrossUncontinuedLine(t *testing.T) {
	content := []byte("php_value auto_prepend_file\nphp_value memory_limit 256M\n")
	if got := detectAutoPrepend(content, "/home/alice/public_html/.htaccess"); len(got) != 0 {
		t.Fatalf("target parser crossed a directive boundary: %+v", got)
	}
}

func TestDetectAutoPrependAcceptsExplicitContinuation(t *testing.T) {
	content := []byte("php_value auto_prepend_file \\\n  \"/home/alice/prelude file.php\"\n")
	if got := detectAutoPrepend(content, "/home/alice/public_html/.htaccess"); len(got) != 1 {
		t.Fatalf("continued target findings = %+v, want one", got)
	}
}

func TestDetectAutoAppendUsesParsedTarget(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   int
	}{
		{target: `"/etc/csm/append file.php"`, want: 0},
		{target: `"/home/alice/append file.php"`, want: 1},
	} {
		content := []byte("php_admin_value auto_append_file " + tc.target + "\n")
		if got := detectAutoPrepend(content, "/home/alice/public_html/.htaccess"); len(got) != tc.want {
			t.Errorf("auto_append_file target %q: findings = %+v, want %d", tc.target, got, tc.want)
		}
	}
}

// The same account-tree rule applies when the .htaccess itself lives outside
// /home (Plesk, custom account roots): a target in the same tree as the file
// is attacker-reachable.
func TestDetectorAutoPrependFlagsSameTreeTarget(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "php_value auto_prepend_file "+dir+"/site/prelude.php\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_auto_prepend"); got != 1 {
		t.Errorf("same-tree target: htaccess_auto_prepend = %d, want 1", got)
	}
}

// PHP resolves dot segments before opening the target. Classification must do
// the same or an account-controlled file can be spelled through an apparently
// root-owned prefix and evade the home, scratch, and account-tree checks.
func TestAutoPrependTargetNormalizesBeforeClassification(t *testing.T) {
	htaccessPath := "/srv/accounts/alice/public/.htaccess"
	for _, target := range []string{
		"/etc/../home/alice/prelude.php",
		"/etc/../tmp/prelude.php",
		"/opt/../srv/accounts/alice/prelude.php",
	} {
		if !autoPrependTargetSuspicious(target, htaccessPath) {
			t.Errorf("normalized account-controlled target %q was treated as safe", target)
		}
	}
}

// The legacy htaccess_injection scanner carries a line-wide safe-substring
// list. It must not apply to the prelude directives, whose only trusted part
// is the target file itself.
func TestCheckHtaccessFileAutoPrependIgnoresSafeSubstringsInTarget(t *testing.T) {
	for _, target := range []string{
		"/home/victim/public_html/wp-content/uploads/fonts/x.ttf",
		"/home/u/public_html/wp-content/litespeed/x.php",
	} {
		tmp := t.TempDir() + "/.htaccess"
		if err := os.WriteFile(tmp, []byte("php_value auto_prepend_file "+target+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(tmp) }})

		var findings []alert.Finding
		checkHtaccessFile(tmp, []string{"auto_prepend_file"}, []string{"litespeed", ".ttf", "wordfence-waf.php"}, &findings)
		if len(findings) == 0 {
			t.Errorf("target %q: no htaccess_injection finding; a safe substring in the target must not exempt it", target)
		}
	}
}
