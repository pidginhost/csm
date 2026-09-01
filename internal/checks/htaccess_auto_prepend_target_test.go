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
