//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// A .user.ini whose disable_functions is set to junk that disables nothing
// (the 0xNix camouflage, 2026-07-23) must alert in real time -- the old check
// only fired when the value was literally empty.
func TestCheckUserININeutralizedDisableFunctions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("disable_functions = bypassed by 0xnix(seobarbar)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check != "php_config_realtime" {
			t.Errorf("check = %q, want php_config_realtime", a.Check)
		}
	default:
		t.Error("neutralized disable_functions should alert in real time")
	}
}

func TestCheckUserINIParsesEffectiveDirectiveNamesAndValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "prefixed directive is ignored",
			content: "disable_functions_backup = none\nallow_url_include_backup = on\n",
		},
		{
			name:    "later value overrides earlier value",
			content: "allow_url_include = on\nallow_url_include = off\n",
		},
		{
			name:    "quoted mixed-case function list is effective",
			content: `disable_functions = "EXEC, system" ; generated`,
		},
		{
			name:    "truthy value is detected",
			content: "allow_url_include = yes\n",
			want:    true,
		},
		{
			name:    "unrestricted path is detected",
			content: "open_basedir = /srv/www:/\n",
			want:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".user.ini")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)

			ch := make(chan alert.Finding, 1)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			fm.checkUserINI(fd, path, "pi")

			if got := len(ch) > 0; got != tc.want {
				t.Fatalf("alerted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckUserINIReadsPastLegacyPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.ini")
	content := strings.Repeat("; harmless padding\n", 300) + "allow_url_include = on\n"
	if len(content) <= 4096 {
		t.Fatal("test fixture does not exceed the legacy realtime read limit")
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(fd, path, "pi")

	if len(ch) != 1 {
		t.Fatal("dangerous directive after the legacy prefix was not detected")
	}
}

func TestCheckUserINIAlertsWhenConfigExceedsReadLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.ini")
	content := append(make([]byte, checks.PHPConfigMaxBytes), '\n')
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(fd, path, "pi")

	select {
	case finding := <-ch:
		if finding.Check != "php_config_realtime" ||
			finding.Severity != alert.High ||
			!strings.Contains(finding.Message, "too large") {
			t.Fatalf("oversized PHP configuration finding = %+v", finding)
		}
	default:
		t.Fatal("oversized PHP configuration did not produce a coverage alert")
	}
}

// Realtime .htaccess handling must run the full detector registry, not just
// the auto_prepend/eval inline checks, so a CGI-handler webshell arming
// (AddHandler cgi-script .alfa) is caught on write.
func TestCheckHtaccessCGIHandlerRealtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte("AddHandler cgi-script .alfa\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(fd, path, "pi")

	found := false
	for {
		select {
		case a := <-ch:
			if a.Check == "htaccess_cgi_handler_abuse" {
				found = true
			}
			continue
		default:
		}
		break
	}
	if !found {
		t.Error("realtime .htaccess should flag CGI-handler webshell arming")
	}
}

// Realtime .htaccess handling must flag a ModSecurity-disabling directive.
func TestCheckHtaccessSecurityDisabledRealtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte("SecFilterEngine Off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(fd, path, "pi")

	found := false
	for {
		select {
		case a := <-ch:
			if a.Check == "htaccess_security_disabled" {
				found = true
			}
			continue
		default:
		}
		break
	}
	if !found {
		t.Error("realtime .htaccess should flag ModSecurity disable")
	}
}

// A php.ini planted under a web root must be watched in real time.
func TestIsInterestingPhpIni(t *testing.T) {
	fm := &FileMonitor{}
	if !fm.isInteresting("/home/victim/public_html/wp-includes/assets/php.ini") {
		t.Error("php.ini under /home should be interesting to the realtime watcher")
	}
}
