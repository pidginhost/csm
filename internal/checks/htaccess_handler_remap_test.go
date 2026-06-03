package checks

import (
	"context"
	"os"
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
