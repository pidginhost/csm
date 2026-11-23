package checks

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func TestRewriteSSHDConfigPrependsBlockAndDisablesGlobals(t *testing.T) {
	in := strings.Join([]string{
		"Include /etc/ssh/sshd_config.d/*.conf",
		"UseDNS yes",
		"MaxAuthTries=6",
		"PasswordAuthentication no",
		"Match User backup",
		"    X11Forwarding yes",
	}, "\n")
	got, _ := rewriteSSHDConfig(in, []keyValue{{"UseDNS", "no"}, {"MaxAuthTries", "4"}})
	lines := strings.Split(got, "\n")
	want := []string{sshdBlockBegin, "MaxAuthTries 4", "UseDNS no", sshdBlockEnd, "Include /etc/ssh/sshd_config.d/*.conf"}
	for i, w := range want {
		if lines[i] != w {
			t.Fatalf("line %d = %q, want %q\n%s", i, lines[i], w, got)
		}
	}
	for _, w := range []string{sshdDisabledBy + "UseDNS yes", sshdDisabledBy + "MaxAuthTries=6", "PasswordAuthentication no", "    X11Forwarding yes"} {
		if !strings.Contains(got, w+"\n") && !strings.HasSuffix(got, w) {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
}

func TestRewriteSSHDConfigMergesExistingBlock(t *testing.T) {
	first, _ := rewriteSSHDConfig("Port 2222\n", []keyValue{{"UseDNS", "no"}})
	second, _ := rewriteSSHDConfig(first, []keyValue{{"X11Forwarding", "no"}})
	if strings.Count(second, sshdBlockBegin) != 1 {
		t.Fatalf("block duplicated:\n%s", second)
	}
	for _, w := range []string{"UseDNS no", "X11Forwarding no", "Port 2222"} {
		if !strings.Contains(second, w) {
			t.Errorf("missing %q in\n%s", w, second)
		}
	}
	if third, _ := rewriteSSHDConfig(second, []keyValue{{"X11Forwarding", "no"}}); third != second {
		t.Errorf("rewrite not idempotent:\n%s\n---\n%s", second, third)
	}
}

func TestAutoFixDescriptionOnlyForSafeChecks(t *testing.T) {
	installs := []phpInstall{
		{shortID: "82", scanDir: "/opt/cpanel/ea-php82/root/etc/php.d"},
		{shortID: "81"}, // alt-php: no scan dir
	}
	fixable := []string{"ssh_use_dns", "ssh_max_auth_tries", "os_sysctl_aslr", "os_tmp_permissions",
		"os_shadow_permissions", "cp_ssl_only", "cp_compilers", "cp_updates", "php_expose_82", "php_upload_progress_82"}
	for _, n := range fixable {
		if autoFixDescription(store.AuditResult{Name: n}, installs) == "" {
			t.Errorf("%s should be auto-fixable", n)
		}
	}
	manual := []string{"ssh_port", "ssh_password_auth", "ssh_root_login", "ssh_protocol", "os_swap",
		"php_disable_functions_82", "php_allow_url_fopen_82", "php_expose_81", "php_expose_99",
		"fw_active", "mail_root_forwarder", "cp_ftp_anonymous", "cl_cagefs", "web_directory_listing"}
	for _, n := range manual {
		if d := autoFixDescription(store.AuditResult{Name: n}, installs); d != "" {
			t.Errorf("%s should stay manual, got %q", n, d)
		}
	}
}

func TestAnnotateAutoFixesSkipsPassing(t *testing.T) {
	results := []store.AuditResult{
		{Name: "ssh_use_dns", Status: "pass"},
		{Name: "ssh_use_dns", Status: "warn"},
	}
	annotateAutoFixes(results, nil)
	if results[0].AutoFix != "" || results[1].AutoFix == "" {
		t.Fatalf("AutoFix = %q / %q", results[0].AutoFix, results[1].AutoFix)
	}
}

func TestSetKeyValueFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpupdate.conf")
	if err := os.WriteFile(path, []byte("CPANEL=release\n# UPDATES=daily\nUPDATES=manual\nRPMUP=daily\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := setKeyValueFile(path, "UPDATES", "daily"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if got, want := string(data), "CPANEL=release\n# UPDATES=daily\nUPDATES=daily\nRPMUP=daily\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}
}

func TestApplySysctlFixesPersistsOnlyAcceptedKeys(t *testing.T) {
	// The fixer writes into an existing system configuration directory.
	sysctlDir := filepath.Join(t.TempDir(), "sysctl.d")
	if err := os.Mkdir(sysctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hardeningSysctlConfPath = filepath.Join(sysctlDir, "99-zz-csm-hardening.conf")
	t.Cleanup(func() { hardeningSysctlConfPath = "/etc/sysctl.d/99-zz-csm-hardening.conf" })
	var calls []string
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), "enforce_symlinksifowner") {
			return []byte("sysctl: cannot stat /proc/sys/fs/enforce_symlinksifowner"), errors.New("exit status 255")
		}
		return nil, nil
	}})
	out := applySysctlFixes([]store.AuditResult{
		{Name: "os_sysctl_aslr", Title: "ASLR"},
		{Name: "cl_symlink_protection", Title: "Symlinks"},
	})
	status := map[string]string{}
	for _, o := range out {
		status[o.Name] = o.Status
	}
	if status["os_sysctl_aslr"] != "applied" || status["cl_symlink_protection"] != "failed" {
		t.Fatalf("statuses = %v", status)
	}
	data, err := os.ReadFile(hardeningSysctlConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "kernel.randomize_va_space = 2") || strings.Contains(string(data), "enforce_symlinksifowner") {
		t.Fatalf("drop-in = %q", data)
	}
	if len(calls) != 2 {
		t.Errorf("calls = %v", calls)
	}
}

func withTempSSHDConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := sshdConfigPath
	sshdConfigPath = path
	t.Cleanup(func() { sshdConfigPath = old })
	return path
}

func TestApplySSHFixesValidatesAndReloads(t *testing.T) {
	path := withTempSSHDConfig(t, "UseDNS yes\n")
	var calls []string
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, filepath.Base(name)+" "+strings.Join(args, " "))
		return nil, nil
	}})
	out := applySSHFixes([]store.AuditResult{{Name: "ssh_use_dns"}})
	if out[0].Status != "applied" {
		t.Fatalf("result = %+v", out[0])
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), sshdBlockBegin+"\nUseDNS no\n") {
		t.Fatalf("config = %q", data)
	}
	if got := parseSSHDConfig().Value("usedns"); got != "no" {
		t.Errorf("effective UseDNS = %q", got)
	}
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "sshd -t -f ") || calls[1] != "systemctl reload sshd" {
		t.Errorf("calls = %v", calls)
	}
	if bak, _ := os.ReadFile(path + ".csm-bak"); string(bak) != "UseDNS yes\n" {
		t.Errorf("backup = %q", bak)
	}
}

func TestApplySSHFixesRestoresOnValidationFailure(t *testing.T) {
	path := withTempSSHDConfig(t, "UseDNS yes\n")
	reloaded := false
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			reloaded = true
			return nil, nil
		}
		return []byte("bad configuration option"), errors.New("exit status 255")
	}})
	out := applySSHFixes([]store.AuditResult{{Name: "ssh_use_dns"}})
	if out[0].Status != "failed" || !strings.Contains(out[0].Message, "original restored") {
		t.Fatalf("result = %+v", out[0])
	}
	if data, _ := os.ReadFile(path); string(data) != "UseDNS yes\n" {
		t.Errorf("config not restored: %q", data)
	}
	if reloaded {
		t.Error("sshd reloaded after a failed validation")
	}
}

func TestWritePHPDropInMerges(t *testing.T) {
	path := filepath.Join(t.TempDir(), hardeningPHPIniName)
	if _, err := writePHPDropIn(path, []string{"expose_php"}); err != nil {
		t.Fatal(err)
	}
	if _, err := writePHPDropIn(path, []string{"enable_dl", "expose_php"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	got := string(data)
	if strings.Count(got, "expose_php") != 1 || !strings.Contains(got, "enable_dl = Off") {
		t.Fatalf("drop-in = %q", got)
	}
	ini := phpAuditINI{"": {}}
	ini.merge(got, false)
	if !phpAuditBoolDisabled(ini[""]["expose_php"]) {
		t.Errorf("audit parser does not read expose_php as off: %q", got)
	}
}

func TestApplyPHPFixesSkipsInstallWithoutScanDir(t *testing.T) {
	dir := t.TempDir()
	hardeningPHPFPMRestart = filepath.Join(dir, "missing-restart-script")
	t.Cleanup(func() { hardeningPHPFPMRestart = "/scripts/restartsrv_apache_php_fpm" })
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
	installs := []phpInstall{{shortID: "82", scanDir: dir}, {shortID: "81"}}
	out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82"}, {Name: "php_expose_81"}}, installs)
	status := map[string]string{}
	for _, o := range out {
		status[o.Name] = o.Status
	}
	if status["php_expose_82"] != "applied" || status["php_expose_81"] != "skipped" {
		t.Fatalf("statuses = %v", status)
	}
	if _, err := os.Stat(filepath.Join(dir, hardeningPHPIniName)); err != nil {
		t.Fatal(err)
	}
}

func TestApplyHardeningRejectsUnknownCategory(t *testing.T) {
	if _, err := ApplyHardening(nil, "nope", nil); err == nil {
		t.Fatal("want error for unknown category")
	}
}

func TestChmodRegularRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := chmodRegular(link, 0o600); err == nil {
		t.Fatal("chmod followed a symlink")
	}
	if _, err := chmodRegular(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestPersistSysctlDoesNotCreateTheDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "sysctl.d")
	hardeningSysctlConfPath = filepath.Join(missing, "99-zz-csm-hardening.conf")
	t.Cleanup(func() { hardeningSysctlConfPath = "/etc/sysctl.d/99-zz-csm-hardening.conf" })
	if _, err := persistSysctl([]keyValue{{"kernel.randomize_va_space", "2"}}); err == nil {
		t.Fatal("persisted into a directory that does not exist")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("the fixer created %s: %v", missing, err)
	}
}

// Debian and Ubuntu let the shadow group read /etc/shadow (unix_chkpwd is
// setgid shadow); taking that away breaks password checks by non-root
// programs. Both 0600 and 0640 pass the audit.
func TestShadowFixModeKeepsShadowGroupRead(t *testing.T) {
	lookup := func(name string) (*user.Group, error) {
		if name != "shadow" {
			t.Fatalf("group queried: %s", name)
		}
		return &user.Group{Gid: "42", Name: "shadow"}, nil
	}
	for gid, want := range map[uint32]os.FileMode{42: 0o640, 0: 0o600, 7: 0o600} {
		if got, err := shadowFixMode(gid, lookup); err != nil || got != want {
			t.Errorf("gid %d: mode %04o, %v; want %04o", gid, got, err, want)
		}
	}
	if _, err := shadowFixMode(42, func(string) (*user.Group, error) { return nil, errors.New("lookup failed") }); err == nil {
		t.Fatal("ignored group lookup failure")
	}
}

func TestFixShadowPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte("root:*:1::::::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	old := hardeningShadowPath
	hardeningShadowPath = path
	t.Cleanup(func() { hardeningShadowPath = old })
	out := applyHardeningSingle(store.AuditResult{Name: "os_shadow_permissions"})
	if out.Status != "applied" {
		t.Fatalf("result = %+v", out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := shadowFixMode(info.Sys().(*syscall.Stat_t).Gid, user.LookupGroup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode = %04o, want %04o", info.Mode().Perm(), want)
	}
}

// debianPHPTree builds <root>/php/8.2/<sapi>/conf.d for each SAPI.
func debianPHPTree(t *testing.T, sapis ...string) (string, []string) {
	t.Helper()
	ver := filepath.Join(t.TempDir(), "php", "8.2")
	var dirs []string
	for _, s := range sapis {
		d := filepath.Join(ver, s, "conf.d")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, d)
	}
	// A SAPI directory without conf.d gets nothing.
	if err := os.MkdirAll(filepath.Join(ver, "mods-available"), 0o755); err != nil {
		t.Fatal(err)
	}
	slices.Sort(dirs)
	return ver, dirs
}

// php -i reports the CLI scan directory, but on Debian PHP-FPM and mod_php
// read their own; a drop-in in the CLI one alone passes the audit and leaves
// the web server unchanged.
func TestPHPInstallScanDirsCoverEveryDebianSAPI(t *testing.T) {
	ver, dirs := debianPHPTree(t, "cli", "fpm", "apache2")
	got := phpInstallScanDirs(phpInstall{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")})
	if !slices.Equal(got, dirs) {
		t.Fatalf("dirs = %v, want %v", got, dirs)
	}
	ea := filepath.Join(t.TempDir(), "ea-php82", "root", "etc", "php.d")
	if got := phpInstallScanDirs(phpInstall{shortID: "82", scanDir: ea}); !slices.Equal(got, []string{ea}) {
		t.Fatalf("EA4 dirs = %v", got)
	}
	if got := phpInstallScanDirs(phpInstall{shortID: "81"}); got != nil {
		t.Fatalf("no scan dir: %v", got)
	}
}

func TestApplyPHPFixesWritesEverySAPIAndReloadsIt(t *testing.T) {
	ver, dirs := debianPHPTree(t, "cli", "fpm", "apache2")
	hardeningPHPFPMRestart = filepath.Join(t.TempDir(), "missing-restart-script")
	t.Cleanup(func() { hardeningPHPFPMRestart = "/scripts/restartsrv_apache_php_fpm" })
	var calls []string
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}})
	installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
	out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82"}}, installs)
	if len(out) != 1 || out[0].Status != "applied" {
		t.Fatalf("results = %+v", out)
	}
	for _, d := range dirs {
		data, err := os.ReadFile(filepath.Join(d, hardeningPHPIniName))
		if err != nil || !strings.Contains(string(data), "expose_php = Off") {
			t.Fatalf("%s: %q %v", d, data, err)
		}
		if !strings.Contains(out[0].Message, d) {
			t.Errorf("message does not name %s: %q", d, out[0].Message)
		}
	}
	for _, want := range []string{"systemctl try-reload-or-restart php*-fpm.service", "systemctl try-reload-or-restart apache2.service"} {
		if !slices.Contains(calls, want) {
			t.Errorf("calls = %v, missing %q", calls, want)
		}
	}
}

func TestApplyPHPFixesReloadsNoWebServerWithoutModPHP(t *testing.T) {
	dir := t.TempDir()
	hardeningPHPFPMRestart = filepath.Join(dir, "missing-restart-script")
	t.Cleanup(func() { hardeningPHPFPMRestart = "/scripts/restartsrv_apache_php_fpm" })
	var calls []string
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}})
	applyPHPFixes([]store.AuditResult{{Name: "php_expose_82"}}, []phpInstall{{shortID: "82", scanDir: dir}})
	for _, c := range calls {
		if strings.Contains(c, "apache2") || strings.Contains(c, "httpd") {
			t.Errorf("reloaded a web server: %v", calls)
		}
	}
}

// LiteSpeed keeps detached lsphp processes running; they load a new drop-in
// only when LiteSpeed is told to restart them.
func TestApplyPHPFixesRestartsLiteSpeedPHP(t *testing.T) {
	dir := t.TempDir()
	lsws := t.TempDir()
	ctrl := filepath.Join(lsws, "lswsctrl")
	if err := os.WriteFile(ctrl, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(lsws, ".lsphp_restart.txt")
	oldCtrl, oldMarker, oldFPM := hardeningLSWSCtrl, hardeningLSPHPRestartMarker, hardeningPHPFPMRestart
	hardeningLSWSCtrl, hardeningLSPHPRestartMarker = ctrl, marker
	hardeningPHPFPMRestart = filepath.Join(dir, "missing-restart-script")
	t.Cleanup(func() {
		hardeningLSWSCtrl, hardeningLSPHPRestartMarker, hardeningPHPFPMRestart = oldCtrl, oldMarker, oldFPM
	})
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
	out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82"}}, []phpInstall{{shortID: "82", scanDir: dir}})
	if out[0].Status != "applied" || !strings.Contains(out[0].Message, "LiteSpeed") {
		t.Fatalf("result = %+v", out[0])
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("LiteSpeed PHP restart not requested: %v", err)
	}
}

func TestApplyPHPFixesWithoutLiteSpeedLeavesNoMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), ".lsphp_restart.txt")
	oldCtrl, oldMarker, oldFPM := hardeningLSWSCtrl, hardeningLSPHPRestartMarker, hardeningPHPFPMRestart
	hardeningLSWSCtrl, hardeningLSPHPRestartMarker = filepath.Join(dir, "no-lswsctrl"), marker
	hardeningPHPFPMRestart = filepath.Join(dir, "missing-restart-script")
	t.Cleanup(func() {
		hardeningLSWSCtrl, hardeningLSPHPRestartMarker, hardeningPHPFPMRestart = oldCtrl, oldMarker, oldFPM
	})
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
	applyPHPFixes([]store.AuditResult{{Name: "php_expose_82"}}, []phpInstall{{shortID: "82", scanDir: dir}})
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker written without LiteSpeed: %v", err)
	}
}

// whmapi1 can print warnings on stderr; only stdout is the JSON reply.
func TestSetWHMTweakReadsStdoutOnly(t *testing.T) {
	reply := `{"metadata":{"result":1,"reason":"OK"}}`
	withMockCmd(t, &mockCmd{
		runContext: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("Warning: locale not set\n" + reply), nil
		},
		runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(reply), nil
		},
	})
	if err := setWHMTweak("skipboxtrapper", "1"); err != nil {
		t.Fatal(err)
	}
}

func TestAutoFixDescriptionNamesEverySAPI(t *testing.T) {
	ver, dirs := debianPHPTree(t, "cli", "fpm")
	d := autoFixDescription(store.AuditResult{Name: "php_expose_82"}, []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}})
	for _, dir := range dirs {
		if !strings.Contains(d, filepath.Join(dir, hardeningPHPIniName)) {
			t.Errorf("description %q does not name %s", d, dir)
		}
	}
}

func TestLiteSpeedMarkerRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, ".lsphp_restart.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := touchNoFollow(link); err == nil {
		t.Fatal("followed a symlink")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target was created: %v", err)
	}
}

func TestExistingLiteSpeedMarkerGetsFreshTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lsphp_restart.txt")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(946684800, 0)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := touchNoFollow(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().After(old) {
		t.Fatalf("marker still dated %v", info.ModTime())
	}
}

func TestPHPFixKeepsCLIFindingWhenAnotherSAPIFails(t *testing.T) {
	ver, _ := debianPHPTree(t, "cli", "fpm")
	cli := filepath.Join(ver, "cli", "conf.d")
	fpm := filepath.Join(ver, "fpm", "conf.d")
	if err := os.Mkdir(filepath.Join(fpm, hardeningPHPIniName), 0o700); err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
	out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82"}}, []phpInstall{{shortID: "82", scanDir: cli}})
	if len(out) != 1 || out[0].Status != "failed" {
		t.Fatalf("results: %+v", out)
	}
	if _, err := os.Stat(filepath.Join(cli, hardeningPHPIniName)); !os.IsNotExist(err) {
		t.Fatalf("CLI changed before FPM succeeded: %v", err)
	}
}

func TestPHPScanDirsRefuseLinkedSAPI(t *testing.T) {
	ver, _ := debianPHPTree(t, "cli")
	// A linked file has no SAPI scan directory.
	file := filepath.Join(ver, "note")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(ver, "note-link")); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(ver, "cli", "conf.d")
	if got := phpInstallScanDirs(phpInstall{scanDir: cli}); !slices.Equal(got, []string{cli}) {
		t.Fatalf("unrelated link disabled CLI fix: %v", got)
	}
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(outside, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ver, "fpm")); err != nil {
		t.Fatal(err)
	}
	if dirs := phpInstallScanDirs(phpInstall{scanDir: filepath.Join(ver, "cli", "conf.d")}); len(dirs) != 0 {
		t.Fatalf("offered automatic fix with unverified SAPI: %v", dirs)
	}
}

type shadowAuditInfo struct {
	os.FileInfo
	gid uint32
}

func (f shadowAuditInfo) Sys() any { return &syscall.Stat_t{Gid: f.gid} }

func TestAuditShadowRejectsUnrelatedGroupRead(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{stat: func(name string) (os.FileInfo, error) {
		if name == "/etc/shadow" {
			return shadowAuditInfo{fakeFileInfoWithMode{mode: 0o640}, 4294967294}, nil
		}
		return nil, os.ErrNotExist
	}})
	for _, result := range auditOS() {
		if result.Name == "os_shadow_permissions" {
			if result.Status != "fail" {
				t.Errorf("group-readable shadow passed: %+v", result)
			}
			return
		}
	}
	t.Fatal("missing shadow result")
}

func TestWritePHPDropInRejectsLinkedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.ini")
	if err := os.WriteFile(target, []byte("precision = 10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, hardeningPHPIniName)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := writePHPDropIn(link, []string{"expose_php"}); err == nil {
		t.Fatal("merged a symlink target into the drop-in")
	}
	if dest, err := os.Readlink(link); err != nil || dest != target {
		t.Fatalf("changed existing link: %q, %v", dest, err)
	}
}

func TestSysctlMissingDirectoryLeavesRuntimeUntouched(t *testing.T) {
	old := hardeningSysctlConfPath
	hardeningSysctlConfPath = filepath.Join(t.TempDir(), "missing", "hardening.conf")
	t.Cleanup(func() { hardeningSysctlConfPath = old })
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) {
		t.Fatal("changed runtime before checking persistence directory")
		return nil, nil
	}})
	out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_aslr"}})
	if len(out) != 1 || out[0].Status != "failed" || !strings.Contains(out[0].Message, "missing") {
		t.Fatalf("outcome: %+v", out)
	}
}

func TestLiteSpeedMarkerRefusesHardLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "other")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "marker")
	if err := os.Link(target, marker); err != nil {
		t.Fatal(err)
	}
	if err := touchNoFollow(marker); err == nil {
		t.Fatal("touched a file shared with another path")
	}
}

// Five fixes can disrupt a working host; each carries what it can break, and
// the Hardening page leaves those unticked.
func TestAnnotateAutoFixesCautions(t *testing.T) {
	if len(autoFixCautions) != 5 {
		t.Fatalf("cautioned fixes = %d, want exactly five", len(autoFixCautions))
	}
	results := []store.AuditResult{
		{Name: "os_sysctl_rp_filter", Status: "warn"},
		{Name: "cp_max_emails_hour", Status: "warn"},
		{Name: "cp_nobodyspam", Status: "warn"},
		{Name: "cp_cookie_validation", Status: "warn"},
		{Name: "ssh_max_auth_tries", Status: "warn"},
		{Name: "os_sysctl_aslr", Status: "warn"},
		{Name: "ssh_max_auth_tries", Status: "pass"},
	}
	annotateAutoFixes(results, nil)
	for i, r := range results {
		wantCaution := i < 5
		if (r.AutoFixCaution != "") != wantCaution {
			t.Errorf("%s (%s): caution %q, want caution %v", r.Name, r.Status, r.AutoFixCaution, wantCaution)
		}
		if wantCaution && r.AutoFix == "" {
			t.Errorf("%s: a caution without a fix", r.Name)
		}
	}
}
