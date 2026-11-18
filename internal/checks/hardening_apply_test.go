package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	got := rewriteSSHDConfig(in, []keyValue{{"UseDNS", "no"}, {"MaxAuthTries", "4"}})
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
	first := rewriteSSHDConfig("Port 2222\n", []keyValue{{"UseDNS", "no"}})
	second := rewriteSSHDConfig(first, []keyValue{{"X11Forwarding", "no"}})
	if strings.Count(second, sshdBlockBegin) != 1 {
		t.Fatalf("block duplicated:\n%s", second)
	}
	for _, w := range []string{"UseDNS no", "X11Forwarding no", "Port 2222"} {
		if !strings.Contains(second, w) {
			t.Errorf("missing %q in\n%s", w, second)
		}
	}
	if third := rewriteSSHDConfig(second, []keyValue{{"X11Forwarding", "no"}}); third != second {
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
	if err := setKeyValueFile(path, "UPDATES", "daily"); err != nil {
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
	hardeningSysctlConfPath = filepath.Join(t.TempDir(), "sysctl.d", "99-zz-csm-hardening.conf")
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
	if err := writePHPDropIn(path, []string{"expose_php"}); err != nil {
		t.Fatal(err)
	}
	if err := writePHPDropIn(path, []string{"enable_dl", "expose_php"}); err != nil {
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
