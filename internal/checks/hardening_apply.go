package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// Hardening apply: the operator picks a section (category) of the hardening
// page and CSM applies the checks in it that have a safe, mechanical fix.
// Fixes that can lock the operator out (SSH port, password auth, root login),
// break sites (disable_functions, allow_url_fopen), or need a judgement call
// (swap size, firewall policy, mail forwarders) stay manual and keep only
// their Fix text.

// Paths the fixers write. Package variables so tests can redirect them.
var (
	hardeningSysctlConfPath  = "/etc/sysctl.d/99-zz-csm-hardening.conf"
	hardeningCPUpdateConf    = "/etc/cpupdate.conf"
	hardeningCompilerPath    = "/usr/bin/cc"
	hardeningCompilersScript = "/scripts/compilers"
	hardeningShadowPath      = "/etc/shadow"
	hardeningPHPFPMRestart   = "/scripts/restartsrv_apache_php_fpm"
	hardeningTmpDirs         = map[string]string{
		"os_tmp_permissions":     "/tmp",
		"os_var_tmp_permissions": "/var/tmp",
	}
)

// hardeningPHPIniName sorts after the stock scan-dir files, so its values
// win over anything earlier in the directory.
const hardeningPHPIniName = "zz-csm-hardening.ini"

// hardeningApplyTimeout bounds each command a fixer runs.
const hardeningApplyTimeout = 60 * time.Second

const (
	sshdBlockBegin = "# BEGIN CSM hardening (managed by csm; applied from the hardening page)"
	sshdBlockEnd   = "# END CSM hardening"
	sshdDisabledBy = "# Disabled by CSM hardening: "
)

// HardeningFixResult is the outcome of applying one check.
type HardeningFixResult struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Status  string `json:"status"` // applied, failed, skipped
	Message string `json:"message"`
}

// HardeningCategories lists the sections of the hardening report.
var HardeningCategories = []string{"ssh", "php", "webserver", "mail", "cpanel", "os", "firewall"}

type keyValue struct{ key, value string }

var sshFixDirectives = map[string]keyValue{
	"ssh_max_auth_tries": {"MaxAuthTries", "4"},
	"ssh_x11_forwarding": {"X11Forwarding", "no"},
	"ssh_use_dns":        {"UseDNS", "no"},
}

var sysctlFixes = map[string]keyValue{
	"os_sysctl_syncookies":     {"net.ipv4.tcp_syncookies", "1"},
	"os_sysctl_aslr":           {"kernel.randomize_va_space", "2"},
	"os_sysctl_rp_filter":      {"net.ipv4.conf.all.rp_filter", "1"},
	"os_sysctl_icmp_broadcast": {"net.ipv4.icmp_echo_ignore_broadcasts", "1"},
	"os_sysctl_symlinks":       {"fs.protected_symlinks", "1"},
	"os_sysctl_hardlinks":      {"fs.protected_hardlinks", "1"},
	"cl_symlink_protection":    {"fs.enforce_symlinksifowner", "1"},
	"cl_proc_virtualization":   {"fs.proc_can_see_other_uid", "0"},
}

var cpTweakFixes = map[string]keyValue{
	"cp_ssl_only":           {"alwaysredirecttossl", "1"},
	"cp_boxtrapper":         {"skipboxtrapper", "1"},
	"cp_password_reset":     {"resetpass", "0"},
	"cp_password_reset_sub": {"resetpass_sub", "0"},
	"cp_email_passwords":    {"emailpasswords", "0"},
	"cp_cookie_validation":  {"cookieipvalidation", "strict"},
	"cp_remote_domains":     {"allowremotedomains", "0"},
	"cp_core_dumps":         {"coredump", "0"},
	"cp_nobodyspam":         {"nobodyspam", "1"},
	"cp_max_emails_hour":    {"maxemailsperhour", "200"},
}

// phpOffFixes maps a PHP check name prefix to the ini key it turns off.
var phpOffFixes = []keyValue{
	{"php_expose_", "expose_php"},
	{"php_enable_dl_", "enable_dl"},
	{"php_upload_progress_", phpUploadProgressKey},
	{"php_fatal_error_backtraces_", phpFatalErrorBacktracesKey},
}

// phpFixFor returns the ini key and install suffix for a PHP check name.
func phpFixFor(name string) (key, suffix string, ok bool) {
	for _, f := range phpOffFixes {
		if rest, found := strings.CutPrefix(name, f.key); found && rest != "" {
			return f.value, rest, true
		}
	}
	return "", "", false
}

// phpInstallScanDir returns the single scan directory a drop-in can go in.
func phpInstallScanDir(inst phpInstall) (string, bool) {
	if inst.scanDir == "" || strings.Contains(inst.scanDir, string(filepath.ListSeparator)) {
		return "", false
	}
	return inst.scanDir, true
}

func findPHPInstall(installs []phpInstall, suffix string) (phpInstall, bool) {
	for _, inst := range installs {
		if inst.shortID == suffix {
			return inst, true
		}
	}
	return phpInstall{}, false
}

// autoFixDescription says what applying check r changes, or "" when the
// check has no automatic fix on this host.
func autoFixDescription(r store.AuditResult, installs []phpInstall) string {
	if d, ok := sshFixDirectives[r.Name]; ok {
		return fmt.Sprintf("Sets '%s %s' at the top of %s, validates it with sshd -t, and reloads sshd.", d.key, d.value, sshdConfigPath)
	}
	if kv, ok := sysctlFixes[r.Name]; ok {
		return fmt.Sprintf("Sets %s = %s now and in %s.", kv.key, kv.value, hardeningSysctlConfPath)
	}
	if kv, ok := cpTweakFixes[r.Name]; ok {
		return fmt.Sprintf("Sets the WHM tweak setting %s to %s.", kv.key, kv.value)
	}
	if dir, ok := hardeningTmpDirs[r.Name]; ok {
		return fmt.Sprintf("Runs chown root:root and chmod 1777 on %s.", dir)
	}
	switch r.Name {
	case "os_shadow_permissions":
		return fmt.Sprintf("Runs chmod 0600 on %s.", hardeningShadowPath)
	case "cp_compilers":
		return "Restricts compilers to root (" + hardeningCompilersScript + " off, or chmod 0750 " + hardeningCompilerPath + ")."
	case "cp_updates":
		return "Sets UPDATES=daily in " + hardeningCPUpdateConf + "."
	}
	if key, suffix, ok := phpFixFor(r.Name); ok {
		inst, found := findPHPInstall(installs, suffix)
		if !found {
			return ""
		}
		dir, ok := phpInstallScanDir(inst)
		if !ok {
			return ""
		}
		return fmt.Sprintf("Writes %s = Off to %s and restarts PHP-FPM.", key, filepath.Join(dir, hardeningPHPIniName))
	}
	return ""
}

// annotateAutoFixes fills AutoFix on every failing check CSM can apply.
func annotateAutoFixes(results []store.AuditResult, installs []phpInstall) {
	for i := range results {
		if results[i].Status == "pass" {
			continue
		}
		results[i].AutoFix = autoFixDescription(results[i], installs)
	}
}

// ApplyHardening applies the automatic fixes for one category. names limits
// the run to those checks; empty means every fixable check in the category.
// Only checks that fail a fresh audit are touched. The caller re-runs the
// audit afterwards to show the result.
func ApplyHardening(cfg *config.Config, category string, names []string) ([]HardeningFixResult, error) {
	if !slices.Contains(HardeningCategories, category) {
		return nil, fmt.Errorf("unknown hardening category %q", category)
	}
	serverType := detectServerType()
	installs := discoverPHPInstalls(serverType)
	report := RunHardeningAudit(cfg)

	var targets []store.AuditResult
	var out []HardeningFixResult
	seen := map[string]bool{}
	for _, r := range report.Results {
		if r.Category != category {
			continue
		}
		seen[r.Name] = true
		if len(names) > 0 && !slices.Contains(names, r.Name) {
			continue
		}
		if r.Status == "pass" || r.AutoFix == "" {
			if len(names) > 0 {
				out = append(out, skipped(r, skipReason(r)))
			}
			continue
		}
		targets = append(targets, r)
	}
	for _, n := range names {
		if !seen[n] {
			out = append(out, HardeningFixResult{Name: n, Title: n, Status: "skipped", Message: "Check is not in this section of the current audit."})
		}
	}

	var ssh, sysctl, php []store.AuditResult
	for _, r := range targets {
		switch {
		case sshFixDirectives[r.Name] != (keyValue{}):
			ssh = append(ssh, r)
		case sysctlFixes[r.Name] != (keyValue{}):
			sysctl = append(sysctl, r)
		case strings.HasPrefix(r.Name, "php_"):
			php = append(php, r)
		default:
			out = append(out, applyHardeningSingle(r))
		}
	}
	if len(ssh) > 0 {
		out = append(out, applySSHFixes(ssh)...)
	}
	if len(sysctl) > 0 {
		out = append(out, applySysctlFixes(sysctl)...)
	}
	if len(php) > 0 {
		out = append(out, applyPHPFixes(php, installs)...)
	}
	return out, nil
}

func skipReason(r store.AuditResult) string {
	if r.Status == "pass" {
		return "Already passing."
	}
	return "No automatic fix; apply it manually."
}

func applied(r store.AuditResult, msg string) HardeningFixResult {
	return HardeningFixResult{Name: r.Name, Title: r.Title, Status: "applied", Message: msg}
}

func failed(r store.AuditResult, err error) HardeningFixResult {
	return HardeningFixResult{Name: r.Name, Title: r.Title, Status: "failed", Message: err.Error()}
}

func skipped(r store.AuditResult, msg string) HardeningFixResult {
	return HardeningFixResult{Name: r.Name, Title: r.Title, Status: "skipped", Message: msg}
}

func hardeningRun(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hardeningApplyTimeout)
	defer cancel()
	out, err := cmdExec.RunContext(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return out, fmt.Errorf("%s: %w: %s", name, err, firstLines(msg, 3))
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " / ")
}

func applyHardeningSingle(r store.AuditResult) HardeningFixResult {
	if kv, ok := cpTweakFixes[r.Name]; ok {
		if err := setWHMTweak(kv.key, kv.value); err != nil {
			return failed(r, err)
		}
		return applied(r, fmt.Sprintf("Tweak setting %s set to %s.", kv.key, kv.value))
	}
	if dir, ok := hardeningTmpDirs[r.Name]; ok {
		if err := fixTmpDir(dir); err != nil {
			return failed(r, err)
		}
		return applied(r, dir+" is now 1777 root:root.")
	}
	switch r.Name {
	case "os_shadow_permissions":
		if err := chmodRegular(hardeningShadowPath, 0o600); err != nil {
			return failed(r, err)
		}
		return applied(r, hardeningShadowPath+" is now 0600.")
	case "cp_compilers":
		msg, err := restrictCompilers()
		if err != nil {
			return failed(r, err)
		}
		return applied(r, msg)
	case "cp_updates":
		if err := setKeyValueFile(hardeningCPUpdateConf, "UPDATES", "daily"); err != nil {
			return failed(r, err)
		}
		return applied(r, "UPDATES=daily written to "+hardeningCPUpdateConf+".")
	}
	return skipped(r, "No automatic fix; apply it manually.")
}

// --- cPanel ---

func setWHMTweak(key, value string) error {
	out, err := hardeningRun("whmapi1", "--output=json", "set_tweaksetting", "key="+key, "value="+value)
	if err != nil {
		return err
	}
	var reply struct {
		Metadata struct {
			Result int    `json:"result"`
			Reason string `json:"reason"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return fmt.Errorf("unreadable whmapi1 reply: %w", err)
	}
	if reply.Metadata.Result != 1 {
		return fmt.Errorf("whmapi1 refused %s=%s: %s", key, value, reply.Metadata.Reason)
	}
	return nil
}

func restrictCompilers() (string, error) {
	if info, err := os.Stat(hardeningCompilersScript); err == nil && info.Mode().IsRegular() {
		if _, err := hardeningRun(hardeningCompilersScript, "off"); err != nil {
			return "", err
		}
		return "Compiler access restricted with " + hardeningCompilersScript + " off.", nil
	}
	target, err := filepath.EvalSymlinks(hardeningCompilerPath)
	if err != nil {
		return "", err
	}
	if err := chmodRegular(target, 0o750); err != nil {
		return "", err
	}
	return target + " is now 0750.", nil
}

// setKeyValueFile sets KEY=value in a shell-style config file, replacing
// the first active assignment or appending one.
func setKeyValueFile(path, key, value string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	// #nosec G304 -- fixed operator config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	done := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		k, _, ok := strings.Cut(t, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			if done {
				lines[i] = "# " + line
				continue
			}
			lines[i] = key + "=" + value
			done = true
		}
	}
	if !done {
		lines = append(lines, key+"="+value)
	}
	return atomicio.AtomicWrite(path, info.Mode().Perm(), []byte(strings.Join(lines, "\n")+"\n"))
}

// --- OS ---

func fixTmpDir(dir string) error {
	return setModeByFD(dir, os.ModeSticky|0o777, true, true)
}

func chmodRegular(path string, mode os.FileMode) error {
	return setModeByFD(path, mode, false, false)
}

// setModeByFD opens path without following a final symlink and changes the
// mode (and, with chownRoot, the owner) through the descriptor, so the
// object checked is the one changed.
func setModeByFD(path string, mode os.FileMode, chownRoot, wantDir bool) error {
	// #nosec G304 -- fixed system paths chosen by the fixer table.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if chownRoot {
		if err := f.Chown(0, 0); err != nil {
			return err
		}
	}
	return f.Chmod(mode)
}

// applySysctlFixes sets each key at runtime, then persists the ones the
// kernel accepted. A key the kernel rejects is not written, so the next
// boot does not log errors for it.
func applySysctlFixes(items []store.AuditResult) []HardeningFixResult {
	var out []HardeningFixResult
	var accepted []keyValue
	var acceptedItems []store.AuditResult
	for _, r := range items {
		kv := sysctlFixes[r.Name]
		if _, err := hardeningRun("sysctl", "-w", kv.key+"="+kv.value); err != nil {
			out = append(out, failed(r, err))
			continue
		}
		accepted = append(accepted, kv)
		acceptedItems = append(acceptedItems, r)
	}
	if len(accepted) == 0 {
		return out
	}
	if err := persistSysctl(accepted); err != nil {
		for _, r := range acceptedItems {
			out = append(out, failed(r, fmt.Errorf("set at runtime but not persisted: %w", err)))
		}
		return out
	}
	for i, r := range acceptedItems {
		out = append(out, applied(r, fmt.Sprintf("%s = %s set and saved to %s.", accepted[i].key, accepted[i].value, hardeningSysctlConfPath)))
	}
	return out
}

func persistSysctl(kvs []keyValue) error {
	if err := os.MkdirAll(filepath.Dir(hardeningSysctlConfPath), 0o755); err != nil {
		return err
	}
	var lines []string
	// #nosec G304 -- CSM-owned sysctl drop-in.
	if data, err := os.ReadFile(hardeningSysctlConfPath); err == nil {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	} else if errors.Is(err, os.ErrNotExist) {
		lines = []string{"# Managed by CSM: sysctl values applied from the hardening page."}
	} else {
		return err
	}
	for _, kv := range kvs {
		entry := kv.key + " = " + kv.value
		replaced := false
		for i, line := range lines {
			k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.TrimSpace(k) == kv.key {
				lines[i] = entry
				replaced = true
			}
		}
		if !replaced {
			lines = append(lines, entry)
		}
	}
	return atomicio.AtomicWrite(hardeningSysctlConfPath, 0o644, []byte(strings.Join(lines, "\n")+"\n"))
}

// --- SSH ---

// applySSHFixes writes the directives into one CSM block at the top of
// sshd_config, where sshd's first-value-wins rule makes them effective over
// Includes and later lines. The change is rolled back when sshd -t rejects
// the new file, so a bad edit never reaches the running daemon.
func applySSHFixes(items []store.AuditResult) []HardeningFixResult {
	var directives []keyValue
	for _, r := range items {
		directives = append(directives, sshFixDirectives[r.Name])
	}
	fail := func(err error) []HardeningFixResult {
		out := make([]HardeningFixResult, 0, len(items))
		for _, r := range items {
			out = append(out, failed(r, err))
		}
		return out
	}

	info, err := os.Lstat(sshdConfigPath)
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file", sshdConfigPath))
	}
	// #nosec G304 -- fixed sshd config path.
	orig, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fail(err)
	}
	updated := rewriteSSHDConfig(string(orig), directives)
	backup := sshdConfigPath + ".csm-bak"
	if err := atomicio.AtomicWrite(backup, info.Mode().Perm(), orig); err != nil {
		return fail(fmt.Errorf("backup: %w", err))
	}
	if err := atomicio.AtomicWrite(sshdConfigPath, info.Mode().Perm(), []byte(updated)); err != nil {
		return fail(err)
	}
	if _, err := hardeningRun(sshdBinary(), "-t", "-f", sshdConfigPath); err != nil {
		if rerr := atomicio.AtomicWrite(sshdConfigPath, info.Mode().Perm(), orig); rerr != nil {
			return fail(fmt.Errorf("sshd -t rejected the change (%v) and restoring %s failed: %v; the original is in %s", err, sshdConfigPath, rerr, backup))
		}
		return fail(fmt.Errorf("sshd -t rejected the change, original restored: %w", err))
	}

	msg := "Written to " + sshdConfigPath + " and sshd reloaded."
	if err := reloadSSHD(); err != nil {
		msg = "Written to " + sshdConfigPath + ", but reloading sshd failed (" + err.Error() + "); reload it manually."
	}
	out := make([]HardeningFixResult, 0, len(items))
	for _, r := range items {
		out = append(out, applied(r, msg))
	}
	return out
}

func sshdBinary() string {
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "sshd"
}

func reloadSSHD() error {
	var errs []error
	for _, unit := range []string{"sshd", "ssh"} {
		_, err := hardeningRun("systemctl", "reload", unit)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// rewriteSSHDConfig returns content with directives set in the CSM block
// at the top of the file. Directives already in the block are kept, and
// active global lines for the same keywords are commented out so the file
// reads the way sshd applies it.
func rewriteSSHDConfig(content string, directives []keyValue) string {
	block := map[string]keyValue{}
	var body []string
	inBlock := false
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == sshdBlockBegin:
			inBlock = true
			continue
		case inBlock && t == sshdBlockEnd:
			inBlock = false
			continue
		case inBlock:
			if f := strings.Fields(t); len(f) >= 2 && !strings.HasPrefix(t, "#") {
				block[strings.ToLower(f[0])] = keyValue{f[0], strings.Join(f[1:], " ")}
			}
			continue
		}
		body = append(body, line)
	}
	for _, d := range directives {
		block[strings.ToLower(d.key)] = d
	}

	inMatch := false
	for i, line := range body {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		kw, _, _ := splitSSHDKeyword(t)
		if kw == "match" {
			inMatch = true
		}
		if inMatch {
			continue
		}
		if _, managed := block[kw]; managed {
			body[i] = sshdDisabledBy + line
		}
	}

	keys := make([]string, 0, len(block))
	for k := range block {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	head := []string{sshdBlockBegin}
	for _, k := range keys {
		head = append(head, block[k].key+" "+block[k].value)
	}
	head = append(head, sshdBlockEnd)
	return strings.Join(append(head, body...), "\n")
}

// splitSSHDKeyword returns the lowercased keyword of an sshd_config line,
// which may be separated from its value by whitespace or '='.
func splitSSHDKeyword(line string) (string, string, bool) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), "", false
	}
	return strings.ToLower(line[:i]), strings.TrimLeft(line[i:], " \t="), true
}

// --- PHP ---

// applyPHPFixes writes one drop-in per PHP build and restarts PHP-FPM once.
func applyPHPFixes(items []store.AuditResult, installs []phpInstall) []HardeningFixResult {
	type plan struct {
		dir   string
		keys  []string
		items []store.AuditResult
	}
	plans := map[string]*plan{}
	var order []string
	var out []HardeningFixResult
	for _, r := range items {
		key, suffix, ok := phpFixFor(r.Name)
		if !ok {
			out = append(out, skipped(r, "No automatic fix; apply it manually."))
			continue
		}
		inst, found := findPHPInstall(installs, suffix)
		dir, usable := phpInstallScanDir(inst)
		if !found || !usable {
			out = append(out, skipped(r, "No PHP scan directory to write a drop-in to; apply it manually."))
			continue
		}
		p := plans[dir]
		if p == nil {
			p = &plan{dir: dir}
			plans[dir] = p
			order = append(order, dir)
		}
		p.keys = append(p.keys, key)
		p.items = append(p.items, r)
	}

	var written []store.AuditResult
	for _, dir := range order {
		p := plans[dir]
		path := filepath.Join(dir, hardeningPHPIniName)
		if err := writePHPDropIn(path, p.keys); err != nil {
			for _, r := range p.items {
				out = append(out, failed(r, err))
			}
			continue
		}
		written = append(written, p.items...)
	}
	if len(written) == 0 {
		return out
	}
	restart := "PHP-FPM restarted."
	if err := restartPHPFPM(); err != nil {
		restart = "Restart PHP-FPM manually to load it (" + err.Error() + ")."
	}
	for _, r := range written {
		key, suffix, _ := phpFixFor(r.Name)
		inst, _ := findPHPInstall(installs, suffix)
		path := filepath.Join(inst.scanDir, hardeningPHPIniName)
		out = append(out, applied(r, fmt.Sprintf("%s = Off written to %s. %s", key, path, restart)))
	}
	return out
}

func writePHPDropIn(path string, keys []string) error {
	values := map[string]string{}
	var order []string
	// #nosec G304 -- CSM-owned PHP drop-in.
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, ";") {
				continue
			}
			k, v, ok := strings.Cut(t, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			if _, dup := values[k]; !dup {
				order = append(order, k)
			}
			values[k] = strings.TrimSpace(v)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, k := range keys {
		if _, dup := values[k]; !dup {
			order = append(order, k)
		}
		values[k] = "Off"
	}
	var b strings.Builder
	b.WriteString("; Managed by CSM: PHP settings applied from the hardening page.\n")
	for _, k := range order {
		b.WriteString(k + " = " + values[k] + "\n")
	}
	return atomicio.AtomicWrite(path, 0o644, []byte(b.String()))
}

func restartPHPFPM() error {
	if info, err := os.Stat(hardeningPHPFPMRestart); err == nil && info.Mode().IsRegular() {
		_, err := hardeningRun(hardeningPHPFPMRestart)
		return err
	}
	_, err := hardeningRun("systemctl", "try-reload-or-restart", "php*-fpm.service")
	return err
}
