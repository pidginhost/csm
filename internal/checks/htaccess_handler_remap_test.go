package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// htaccessFindingsFor runs CheckHtaccess against a single user's .htaccess with
// the given content and returns the resulting findings.
func htaccessFindingsFor(t *testing.T, content string) []findingForTest {
	t.Helper()
	dir := t.TempDir()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: ".htaccess", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".htaccess") {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, ".htaccess") {
				tmp := dir + "/.htaccess"
				if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
					return nil, err
				}
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	raw := CheckHtaccess(context.Background(), &config.Config{}, nil)
	out := make([]findingForTest, 0, len(raw))
	for _, f := range raw {
		out = append(out, findingForTest{check: f.Check, msg: f.Message})
	}
	return out
}

type findingForTest struct {
	check string
	msg   string
}

func hasInjectionFinding(findings []findingForTest) bool {
	for _, f := range findings {
		if f.check == "htaccess_injection" {
			return true
		}
	}
	return false
}

// A PHP execution handler mapped onto an image extension is the handler-remap
// webshell technique: an uploaded .jpg then executes as PHP. It must flag even
// though the handler name itself is a normal PHP handler.
func TestCheckHtaccessFlagsImageExtensionMappedToPHP(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php .jpg\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for .jpg mapped to PHP handler, got %+v", findings)
	}
}

// Apache accepts AddHandler/AddType extension tokens without a leading dot.
// A dotless image extension must still be treated as the mapped extension.
func TestCheckHtaccessFlagsDotlessImageExtensionMappedToPHP(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddType application/x-httpd-php jpg\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for dotless jpg mapped to PHP handler, got %+v", findings)
	}
}

// Quoted extension tokens are still Apache extension tokens. The parser must
// normalize them before deciding whether the mapping is safe.
func TestCheckHtaccessFlagsQuotedImageExtensionMappedToPHP(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php \".jpg\"\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for quoted .jpg mapped to PHP handler, got %+v", findings)
	}
}

// Attackers append a malicious extension to an otherwise legitimate-looking
// handler line. The non-PHP extension must still flag.
func TestCheckHtaccessFlagsAppendedAttackExtension(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php .php .jpg\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for mixed .php/.jpg mapping, got %+v", findings)
	}
}

// php-fpm wiring via a proxy handler is a PHP execution path too; remapping a
// static extension onto it must flag.
func TestCheckHtaccessFlagsProxyFcgiRemap(t *testing.T) {
	findings := htaccessFindingsFor(t,
		"AddHandler \"proxy:unix:/opt/cpanel/ea-php74/root/usr/var/run/php-fpm/x.sock|fcgi://localhost\" .ico\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for .ico mapped to php-fpm proxy handler, got %+v", findings)
	}
}

// Custom php-fpm socket aliases do not always contain the literal "php". A
// proxy-fcgi handler mapped to a static extension is still an execution remap.
func TestCheckHtaccessFlagsProxyFcgiRemapWithoutPHPToken(t *testing.T) {
	findings := htaccessFindingsFor(t,
		"AddHandler \"proxy:unix:/run/site.sock|fcgi://localhost\" .ico\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for .ico mapped to proxy-fcgi handler, got %+v", findings)
	}
}

// FilesMatch-scoped SetHandler is the common php-fpm shape. If the context
// targets a non-PHP extension, the SetHandler line must not be suppressed by
// the generic proxy:unix safe pattern.
func TestCheckHtaccessFlagsFilesMatchProxyFcgiRemap(t *testing.T) {
	findings := htaccessFindingsFor(t, `<FilesMatch "\.jpg$">
  SetHandler "proxy:unix:/run/site.sock|fcgi://localhost"
</FilesMatch>
`)
	if !hasInjectionFinding(findings) {
		t.Fatalf("expected htaccess_injection finding for FilesMatch .jpg proxy-fcgi remap, got %+v", findings)
	}
}

// .phps is normally source-display, .phar is an archive, and .phpx is not a
// stock PHP extension. Mapping any of them to an executing PHP handler is not
// the same as cPanel MultiPHP's normal .php/.php7/.phtml mapping.
func TestCheckHtaccessFlagsNonExecutablePHPLikeExtensions(t *testing.T) {
	for _, ext := range []string{".phps", ".phar", ".phpx"} {
		findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php "+ext+"\n")
		if !hasInjectionFinding(findings) {
			t.Fatalf("expected htaccess_injection finding for %s mapped to PHP handler, got %+v", ext, findings)
		}
	}
}

// The source-view handler does not execute PHP. Mapping .phps to it is the
// normal source-display shape and must not be treated as a handler-remap shell.
func TestCheckHtaccessAllowsPHPSourceHandler(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddType application/x-httpd-php-source .phps\n")
	if hasInjectionFinding(findings) {
		t.Fatalf("PHP source-display handler must not flag, got %+v", findings)
	}
}

// Regression guard: cPanel MultiPHP writes legitimate handler lines mapping PHP
// extensions to a PHP handler into user .htaccess files. These must NOT flag,
// or every cPanel account produces a false positive.
func TestCheckHtaccessAllowsLegitMultiPHPHandler(t *testing.T) {
	findings := htaccessFindingsFor(t,
		"AddHandler application/x-httpd-ea-php74___lsphp .php .php7 .phtml\n")
	if hasInjectionFinding(findings) {
		t.Fatalf("legit cPanel MultiPHP handler must not flag, got %+v", findings)
	}
}

// Regression guard: a plain PHP handler for .php alone is the normal case.
func TestCheckHtaccessAllowsPlainPHPHandler(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php .php\n")
	if hasInjectionFinding(findings) {
		t.Fatalf("plain .php handler must not flag, got %+v", findings)
	}
}

// Regression guard for the #1 production false-positive risk: cPanel writes a
// php-fpm FilesMatch SetHandler block into nearly every account's .htaccess.
// Mapping PHP extensions through a proxy-fcgi handler is the normal shape and
// must never flag.
func TestCheckHtaccessAllowsLegitFPMFilesMatch(t *testing.T) {
	for _, body := range []string{
		"<FilesMatch \"\\.php$\">\n  SetHandler \"proxy:unix:/opt/cpanel/ea-php74/root/usr/var/run/php-fpm/x.sock|fcgi://localhost\"\n</FilesMatch>\n",
		"<FilesMatch \"\\.(php[0-9]?|phtml)$\">\n  SetHandler \"proxy:unix:/opt/cpanel/ea-php82/root/usr/var/run/php-fpm/y.sock|fcgi://localhost\"\n</FilesMatch>\n",
		"<FilesMatch \"\\.(php|php7|phtml)$\">\n  SetHandler application/x-httpd-ea-php74___lsphp\n</FilesMatch>\n",
	} {
		findings := htaccessFindingsFor(t, body)
		if hasInjectionFinding(findings) {
			t.Fatalf("legit php-fpm FilesMatch must not flag; body=%q findings=%+v", body, findings)
		}
	}
}

// Apache joins a physical line ending in a backslash with the next line, so
// this maps .jpg to PHP across two physical lines. Per-line scanning must not
// be evaded by splitting the directive.
func TestCheckHtaccessFlagsContinuationSplitRemap(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php \\\n.jpg\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("continuation-split handler remap not flagged; got %+v", findings)
	}
}

// A legit PHP handler mapped to a PHP extension across a continuation must
// still not flag.
func TestCheckHtaccessAllowsContinuationLegitPHP(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php \\\n.php .php7\n")
	if hasInjectionFinding(findings) {
		t.Fatalf("legit continued PHP handler must not flag; got %+v", findings)
	}
}

// The file-index handler overlay must also honor continuation so a webshell
// planted under a continuation-mapped extension is content-scanned.
func TestParsePHPHandlerDirectivesHonorsContinuation(t *testing.T) {
	overlay := parsePHPHandlerDirectives([]byte("AddHandler application/x-httpd-php \\\n.jpg\n"))
	if _, ok := overlay.exts[".jpg"]; !ok {
		t.Fatalf("continuation-mapped .jpg not in overlay; exts=%v", overlay.exts)
	}
}

// joinHtaccessContinuations groups physical lines into logical Apache
// directives, honoring trailing-backslash continuation.
func TestJoinHtaccessContinuations(t *testing.T) {
	in := []string{
		"AddHandler application/x-httpd-php \\",
		".jpg",
		"RewriteEngine On",
		"trailing-backslash-on-last \\",
	}
	got := joinHtaccessContinuations(in)
	if len(got) != 3 {
		t.Fatalf("logical line count = %d, want 3: %+v", len(got), got)
	}
	if got[0].text != "AddHandler application/x-httpd-php .jpg" {
		t.Errorf("join text = %q", got[0].text)
	}
	if len(got[0].lines) != 2 || got[0].start != 0 {
		t.Errorf("span wrong: lines=%v start=%d", got[0].lines, got[0].start)
	}
	if got[1].text != "RewriteEngine On" || got[1].start != 2 {
		t.Errorf("second logical wrong: %+v", got[1])
	}
	// A backslash on the final physical line has no successor and stays literal.
	if got[2].text != "trailing-backslash-on-last \\" {
		t.Errorf("trailing backslash should be literal on last line, got %q", got[2].text)
	}
}

func TestJoinHtaccessContinuationsChainsAndPreservesCRSpan(t *testing.T) {
	in := []string{
		"AddHandler application/x-httpd-php \\\r",
		".jpg \\\r",
		".png\r",
		"final-literal \\\r",
	}
	got := joinHtaccessContinuations(in)
	if len(got) != 2 {
		t.Fatalf("logical line count = %d, want 2: %+v", len(got), got)
	}
	if got[0].text != "AddHandler application/x-httpd-php .jpg .png" {
		t.Errorf("chained join text = %q", got[0].text)
	}
	if got[0].start != 0 || len(got[0].lines) != 3 {
		t.Errorf("chained span wrong: start=%d lines=%q", got[0].start, got[0].lines)
	}
	if got[0].lines[0] != "AddHandler application/x-httpd-php \\\r" || got[0].lines[2] != ".png\r" {
		t.Errorf("physical CR lines not preserved: %q", got[0].lines)
	}
	if got[1].text != "final-literal \\" {
		t.Errorf("final EOF backslash should stay literal after CR strip, got %q", got[1].text)
	}
}

func TestJoinHtaccessContinuationsLeavesNormalLinesUnchanged(t *testing.T) {
	in := []string{
		"AddHandler application/x-httpd-php .php",
		"RewriteEngine On",
		"Header set X-Frame-Options \"SAMEORIGIN\"",
	}
	got := joinHtaccessContinuations(in)
	if len(got) != len(in) {
		t.Fatalf("logical line count = %d, want %d: %+v", len(got), len(in), got)
	}
	for i := range in {
		if got[i].text != in[i] {
			t.Errorf("line %d text = %q, want %q", i, got[i].text, in[i])
		}
		if got[i].start != i || len(got[i].lines) != 1 || got[i].lines[0] != in[i] {
			t.Errorf("line %d span changed: %+v", i, got[i])
		}
	}
}

func TestCheckHtaccessFlagsContinuationSplitCGIHandlerAbuse(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler cgi-script \\\n.haxor\n")
	for _, f := range findings {
		if f.check == "htaccess_handler_abuse" {
			return
		}
	}
	t.Fatalf("continuation-split CGI handler abuse not flagged; got %+v", findings)
}

func TestCheckHtaccessContainerBackslashDoesNotEatSetHandler(t *testing.T) {
	findings := htaccessFindingsFor(t, `<FilesMatch "\.jpg$">\
  SetHandler "proxy:unix:/run/site.sock|fcgi://localhost"
</FilesMatch>
`)
	if !hasInjectionFinding(findings) {
		t.Fatalf("FilesMatch context with stray backslash ate SetHandler; got %+v", findings)
	}
}

// fixHtaccess must remove every physical line of a continuation-split remap and
// preserve the legit handler. Portable variant so it also runs off Linux.
func TestFixHtaccessRemovesContinuationRemapPortable(t *testing.T) {
	saved := fixHtaccessAllowedRoots
	dir, evalErr := filepath.EvalSymlinks(t.TempDir())
	if evalErr != nil {
		t.Fatal(evalErr)
	}
	fixHtaccessAllowedRoots = []string{dir}
	t.Cleanup(func() { fixHtaccessAllowedRoots = saved })

	path := dir + "/.htaccess"
	content := "AddHandler application/x-httpd-php .php\nAddHandler application/x-httpd-php \\\n.jpg\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	res := fixHtaccess(path, "htaccess injection at "+path)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	cs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cs), ".jpg") {
		t.Errorf("continuation-split remap not fully stripped:\n%s", cs)
	}
	if !strings.Contains(string(cs), "AddHandler application/x-httpd-php .php") {
		t.Errorf("plain PHP handler should be preserved:\n%s", cs)
	}
}

func TestFixHtaccessPreservesLegitContinuationAndRemovesFullDangerousSpan(t *testing.T) {
	saved := fixHtaccessAllowedRoots
	dir, evalErr := filepath.EvalSymlinks(t.TempDir())
	if evalErr != nil {
		t.Fatal(evalErr)
	}
	fixHtaccessAllowedRoots = []string{dir}
	t.Cleanup(func() { fixHtaccessAllowedRoots = saved })

	path := filepath.Join(dir, ".htaccess")
	content := "AddHandler application/x-httpd-php \\\n.php .php7\n" +
		"AddHandler application/x-httpd-php \\\n.jpg \\\n.png\n" +
		"RewriteEngine On\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	res := fixHtaccess(path, "htaccess injection at "+path)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	cs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(cs)
	if strings.Contains(got, ".jpg") || strings.Contains(got, ".png") {
		t.Fatalf("dangerous continuation span not fully stripped:\n%s", got)
	}
	wantLegit := "AddHandler application/x-httpd-php \\\n.php .php7\n"
	if !strings.Contains(got, wantLegit) {
		t.Errorf("legit continuation not preserved with both physical lines:\n%s", got)
	}
	if !strings.Contains(got, "RewriteEngine On\n") {
		t.Errorf("ordinary directive was not preserved:\n%s", got)
	}
}

func TestFixHtaccessPreservesCRLFLegitContinuationWriteBack(t *testing.T) {
	saved := fixHtaccessAllowedRoots
	dir, evalErr := filepath.EvalSymlinks(t.TempDir())
	if evalErr != nil {
		t.Fatal(evalErr)
	}
	fixHtaccessAllowedRoots = []string{dir}
	t.Cleanup(func() { fixHtaccessAllowedRoots = saved })

	path := filepath.Join(dir, ".htaccess")
	content := "AddHandler application/x-httpd-php \\\r\n.php .php7\r\n" +
		"AddHandler application/x-httpd-php \\\r\n.jpg\r\n" +
		"Header set X-Frame-Options \"SAMEORIGIN\"\r\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	res := fixHtaccess(path, "htaccess injection at "+path)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	cs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(cs)
	wantLegit := "AddHandler application/x-httpd-php \\\r\n.php .php7\r\n"
	if !strings.Contains(got, wantLegit) {
		t.Errorf("CRLF legit continuation corrupted:\n%q", got)
	}
	if strings.Contains(got, ".jpg") {
		t.Errorf("dangerous CRLF continuation span not stripped:\n%q", got)
	}
	if !strings.Contains(got, "Header set X-Frame-Options \"SAMEORIGIN\"\r\n") {
		t.Errorf("CRLF ordinary directive corrupted:\n%q", got)
	}
}

// A CRLF .htaccess splits to lines ending in "\r"; the continuation backslash
// then sits before the CR. Apache still joins it, so the join must tolerate a
// trailing carriage return.
func TestCheckHtaccessFlagsCRLFContinuationRemap(t *testing.T) {
	findings := htaccessFindingsFor(t, "AddHandler application/x-httpd-php \\\r\n.jpg\r\n")
	if !hasInjectionFinding(findings) {
		t.Fatalf("CRLF continuation-split remap not flagged; got %+v", findings)
	}
}

// The overlay/remediation read sites use strings.Split on "\n", which keeps a
// trailing "\r" on CRLF files. The continuation join must still recognize a
// backslash that precedes the carriage return.
func TestParsePHPHandlerDirectivesHonorsCRLFContinuation(t *testing.T) {
	overlay := parsePHPHandlerDirectives([]byte("AddHandler application/x-httpd-php \\\r\n.jpg\r\n"))
	if _, ok := overlay.exts[".jpg"]; !ok {
		t.Fatalf("CRLF continuation-mapped .jpg not in overlay; exts=%v", overlay.exts)
	}
}
