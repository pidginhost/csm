package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/safepath"
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
	hardeningProcSys         = "/proc/sys"
	hardeningCPUpdateConf    = "/etc/cpupdate.conf"
	hardeningCompilerPath    = "/usr/bin/cc"
	hardeningCompilersScript = "/scripts/compilers"
	hardeningShadowPath      = "/etc/shadow"
	hardeningPHPFPMRestart   = "/scripts/restartsrv_apache_php_fpm"
	// LiteSpeed restarts its detached lsphp processes when this file appears.
	hardeningLSWSCtrl           = "/usr/local/lsws/bin/lswsctrl"
	hardeningLSPHPRestartMarker = "/usr/local/lsws/admin/tmp/.lsphp_restart.txt"
	hardeningTmpDirs            = map[string]string{
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
	if !filepath.IsAbs(inst.scanDir) || strings.Contains(inst.scanDir, string(filepath.ListSeparator)) {
		return "", false
	}
	return filepath.Clean(inst.scanDir), true
}

var debianPHPVersionDir = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// phpInstallScanDirs returns every scan directory the drop-in goes in. A
// Debian-style build has one conf.d per SAPI under php/<version>/, and php -i
// reports only the CLI one, so the drop-in goes in each SAPI's conf.d or
// PHP-FPM and mod_php keep the old value while the audit passes.
func phpInstallScanDirs(inst phpInstall) []string {
	dir, ok := phpInstallScanDir(inst)
	if !ok {
		return nil
	}
	if filepath.Base(dir) != "conf.d" {
		return []string{dir}
	}
	verDir := filepath.Dir(filepath.Dir(dir))
	if !debianPHPVersionDir.MatchString(filepath.Base(verDir)) || filepath.Base(filepath.Dir(verDir)) != "php" {
		return []string{dir}
	}
	entries, err := osFS.ReadDir(verDir)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		linked := e.Type()&os.ModeSymlink != 0
		if !e.IsDir() && !linked {
			continue
		}
		confd := filepath.Join(verDir, e.Name(), "conf.d")
		info, err := osFS.Lstat(confd)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil || linked || !info.IsDir() {
			return nil
		}
		dirs = append(dirs, confd)
	}
	if !slices.Contains(dirs, dir) {
		return nil
	}
	return dirs
}

func phpDropInPaths(dirs []string) []string {
	paths := make([]string, len(dirs))
	for i, d := range dirs {
		paths[i] = filepath.Join(d, hardeningPHPIniName)
	}
	return paths
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
		return fmt.Sprintf("Sets %s to mode 0600, or 0640 when a shadow group owns it.", hardeningShadowPath)
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
		dirs := phpInstallScanDirs(inst)
		if len(dirs) == 0 {
			return ""
		}
		return fmt.Sprintf("Writes %s = Off to %s and restarts PHP.", key, strings.Join(phpDropInPaths(dirs), ", "))
	}
	return ""
}

// autoFixCautions are the fixes that can disrupt a working host, with what
// each can break. The hardening page leaves them unticked.
var autoFixCautions = map[string]string{
	"os_sysctl_rp_filter":  "Strict reverse-path filtering drops replies on hosts with asymmetric routing or several uplinks.",
	"cp_max_emails_hour":   "Caps every domain at 200 messages an hour, which stops newsletters and other legitimate bulk mail.",
	"cp_nobodyspam":        "Stops mail sent as the nobody user, which breaks PHP mail() where sites send as nobody.",
	"cp_cookie_validation": "Logs cPanel, WHM and webmail users out when their IP address changes, as on mobile networks.",
	"ssh_max_auth_tries":   "Refuses SSH clients that offer more than four keys before the right one.",
}

// annotateAutoFixes fills AutoFix on every failing check CSM can apply, and
// the caution for fixes that can disrupt a working host.
func annotateAutoFixes(results []store.AuditResult, installs []phpInstall) {
	for i := range results {
		if results[i].Status == "pass" {
			continue
		}
		results[i].AutoFix = autoFixDescription(results[i], installs)
	}
	AnnotateHardeningCautions(results)
}

// AnnotateHardeningCautions attaches current cautions without re-running the
// audit, so saved reports also require an explicit choice after an upgrade.
func AnnotateHardeningCautions(results []store.AuditResult) {
	for i := range results {
		results[i].AutoFixCaution = ""
		if results[i].Status != "pass" && results[i].AutoFix != "" {
			results[i].AutoFixCaution = autoFixCautions[results[i].Name]
		}
	}
}

// ApplyHardening applies the automatic fixes for one category. names limits
// the run to those checks; empty selects only uncautioned fixes in the category.
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
		if len(names) == 0 && r.AutoFixCaution != "" {
			out = append(out, skipped(r, "Requires explicit selection: "+r.AutoFixCaution))
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

// recordHardeningUndo stores what fix r just changed. When it cannot,
// because of captureErr (reading the previous state failed) or the write,
// it returns a note for the result instead: the change stands either way.
func recordHardeningUndo(r store.AuditResult, rec HardeningUndoRecord, captureErr error) string {
	err := captureErr
	if err == nil {
		rec.Name, rec.Category, rec.AppliedAt = r.Name, r.Category, time.Now().UTC()
		if err = writeHardeningUndo(rec); err == nil {
			return ""
		}
	}
	// An older record would undo to the state before an earlier apply.
	if derr := deleteHardeningUndo(r.Name); derr != nil {
		err = fmt.Errorf("%w; removing the older record failed: %v", err, derr)
	}
	return " Undo is unavailable (" + err.Error() + ")."
}

func hardeningRun(name string, args ...string) ([]byte, error) {
	return hardeningRunWith(cmdExec.RunContext, name, args...)
}

// hardeningRunStdout is hardeningRun for commands whose stdout is parsed.
func hardeningRunStdout(name string, args ...string) ([]byte, error) {
	return hardeningRunWith(cmdExec.RunContextStdout, name, args...)
}

func hardeningRunWith(run func(context.Context, string, ...string) ([]byte, error), name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hardeningApplyTimeout)
	defer cancel()
	out, err := run(ctx, name, args...)
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
		prev, had, readErr := getWHMTweak(kv.key)
		if err := setWHMTweak(kv.key, kv.value); err != nil {
			return failed(r, err)
		}
		undo := tweakUndoState{Key: kv.key, Previous: prev, HadValue: had, Applied: kv.value}
		return applied(r, fmt.Sprintf("Tweak setting %s set to %s.", kv.key, kv.value)+
			recordHardeningUndo(r, HardeningUndoRecord{Kind: "tweak", Tweak: &undo}, readErr))
	}
	if dir, ok := hardeningTmpDirs[r.Name]; ok {
		undo, err := fixTmpDir(dir)
		if err != nil {
			return failed(r, err)
		}
		return applied(r, dir+" is now 1777 root:root."+recordHardeningUndo(r, HardeningUndoRecord{Kind: "mode", Mode: &undo}, nil))
	}
	switch r.Name {
	case "os_shadow_permissions":
		undo, err := fixShadow(hardeningShadowPath)
		if err != nil {
			return failed(r, err)
		}
		return applied(r, fmt.Sprintf("%s is now %04o.", hardeningShadowPath, undo.AppliedMode)+
			recordHardeningUndo(r, HardeningUndoRecord{Kind: "mode", Mode: &undo}, nil))
	case "cp_compilers":
		msg, undo, err := restrictCompilers()
		if err != nil {
			return failed(r, err)
		}
		return applied(r, msg+recordHardeningUndo(r, HardeningUndoRecord{Kind: "compilers", Compilers: &undo}, nil))
	case "cp_updates":
		undo, err := setKeyValueFile(hardeningCPUpdateConf, "UPDATES", "daily")
		if err != nil {
			return failed(r, err)
		}
		return applied(r, "UPDATES=daily written to "+hardeningCPUpdateConf+"."+
			recordHardeningUndo(r, HardeningUndoRecord{Kind: "file", File: &undo}, nil))
	}
	return skipped(r, "No automatic fix; apply it manually.")
}

// --- cPanel ---

// getWHMTweak returns a WHM tweak setting's value, and false when the setting
// has none: get_tweaksetting then leaves the value out of its reply.
func getWHMTweak(key string) (string, bool, error) {
	out, err := hardeningRunStdout("whmapi1", "--output=json", "get_tweaksetting", "key="+key)
	if err != nil {
		return "", false, err
	}
	var reply struct {
		Data struct {
			Tweaksetting struct {
				Key   string  `json:"key"`
				Value *string `json:"value"`
			} `json:"tweaksetting"`
		} `json:"data"`
		Metadata struct {
			Result int    `json:"result"`
			Reason string `json:"reason"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return "", false, fmt.Errorf("unreadable whmapi1 reply: %w", err)
	}
	if reply.Metadata.Result != 1 {
		return "", false, fmt.Errorf("whmapi1 did not return %s: %s", key, reply.Metadata.Reason)
	}
	// A missing value means unset only in a reply about this key.
	if reply.Data.Tweaksetting.Key != key {
		return "", false, fmt.Errorf("whmapi1 did not return %s", key)
	}
	if reply.Data.Tweaksetting.Value == nil {
		return "", false, nil
	}
	return *reply.Data.Tweaksetting.Value, true, nil
}

func setWHMTweak(key, value string) error {
	out, err := hardeningRunStdout("whmapi1", "--output=json", "set_tweaksetting", "key="+key, "value="+value)
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

func restrictCompilers() (string, compilersUndoState, error) {
	if info, err := os.Stat(hardeningCompilersScript); err == nil && info.Mode().IsRegular() {
		if _, err := hardeningRun(hardeningCompilersScript, "off"); err != nil {
			return "", compilersUndoState{}, err
		}
		return "Compiler access restricted with " + hardeningCompilersScript + " off.", compilersUndoState{Method: "script"}, nil
	}
	target, err := filepath.EvalSymlinks(hardeningCompilerPath)
	if err != nil {
		return "", compilersUndoState{}, err
	}
	st, err := chmodRegular(target, 0o750)
	if err != nil {
		return "", compilersUndoState{}, err
	}
	return target + " is now 0750.", compilersUndoState{Method: "chmod", Path: st.Path, Mode: st.Mode, UID: st.UID, GID: st.GID,
		AppliedMode: st.AppliedMode, AppliedUID: st.AppliedUID, AppliedGID: st.AppliedGID}, nil
}

// setKeyValueFile sets KEY=value in a shell-style config file, replacing
// the first active assignment or appending one. It returns the content
// before and after.
func setKeyValueFile(path, key, value string) (fileUndoState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileUndoState{}, err
	}
	if !info.Mode().IsRegular() {
		return fileUndoState{}, fmt.Errorf("%s is not a regular file", path)
	}
	// #nosec G304 -- fixed operator config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return fileUndoState{}, err
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
	updated := strings.Join(lines, "\n") + "\n"
	if err := atomicio.AtomicWrite(path, info.Mode().Perm(), []byte(updated)); err != nil {
		return fileUndoState{}, err
	}
	return fileUndoState{Path: path, Previous: string(data), Applied: updated}, nil
}

// --- OS ---

func fixTmpDir(dir string) (modeUndoState, error) {
	return setModeByFD(dir, os.ModeSticky|0o777, true, true)
}

func chmodRegular(path string, mode os.FileMode) (modeUndoState, error) {
	return setModeByFD(path, mode, false, false)
}

// Only the system shadow group needs to read password hashes for unix_chkpwd.
func shadowFixMode(gid uint32, lookup func(string) (*user.Group, error)) (os.FileMode, error) {
	if gid == 0 {
		return 0o600, nil
	}
	group, err := lookup("shadow")
	if err != nil {
		var missing user.UnknownGroupError
		if errors.As(err, &missing) {
			return 0o600, nil
		}
		return 0, fmt.Errorf("look up shadow group: %w", err)
	}
	if group.Gid == strconv.FormatUint(uint64(gid), 10) {
		return 0o640, nil
	}
	return 0o600, nil
}

// fixShadow sets the shadow file's mode through a descriptor opened without
// following a final symlink, keeping the shadow group's read access. It
// returns the state it replaced and the one it set.
func fixShadow(path string) (modeUndoState, error) {
	// #nosec G304 -- fixed system path chosen by the fixer table.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return modeUndoState{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return modeUndoState{}, err
	}
	if !info.Mode().IsRegular() {
		return modeUndoState{}, fmt.Errorf("%s is not a regular file", path)
	}
	undo, err := modeState(path, info)
	if err != nil {
		return modeUndoState{}, err
	}
	mode, err := shadowFixMode(undo.GID, user.LookupGroup)
	if err != nil {
		return modeUndoState{}, err
	}
	if err := f.Chmod(mode); err != nil {
		return modeUndoState{}, err
	}
	undo.AppliedMode, undo.AppliedUID, undo.AppliedGID = stModeBits(mode), undo.UID, undo.GID
	return undo, nil
}

// setModeByFD opens path without following a final symlink and changes the
// mode (and, with chownRoot, the owner) through the descriptor, so the
// object checked is the one changed. It returns the state it replaced and
// the one it set.
func setModeByFD(path string, mode os.FileMode, chownRoot, wantDir bool) (modeUndoState, error) {
	// #nosec G304 -- fixed system paths chosen by the fixer table.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return modeUndoState{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return modeUndoState{}, err
	}
	if wantDir && !info.IsDir() {
		return modeUndoState{}, fmt.Errorf("%s is not a directory", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return modeUndoState{}, fmt.Errorf("%s is not a regular file", path)
	}
	undo, err := modeState(path, info)
	if err != nil {
		return modeUndoState{}, err
	}
	undo.AppliedMode, undo.AppliedUID, undo.AppliedGID = stModeBits(mode), undo.UID, undo.GID
	if chownRoot {
		if err := f.Chown(0, 0); err != nil {
			return modeUndoState{}, err
		}
		undo.AppliedUID, undo.AppliedGID = 0, 0
	}
	if err := f.Chmod(mode); err != nil {
		return modeUndoState{}, err
	}
	return undo, nil
}

// modeState is the owner and mode that info, from an fstat, reports for path.
func modeState(path string, info os.FileInfo) (modeUndoState, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return modeUndoState{}, fmt.Errorf("%s: no owner information", path)
	}
	return modeUndoState{Path: path, Mode: stModeBits(info.Mode()), UID: st.Uid, GID: st.Gid}, nil
}

// stModeBits converts mode to the st_mode permission bits records keep.
func stModeBits(mode os.FileMode) uint32 {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= syscall.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		bits |= syscall.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		bits |= syscall.S_ISVTX
	}
	return bits
}

// applySysctlFixes sets each key at runtime, then persists the ones the
// kernel accepted. A key the kernel rejects is not written, so the next
// boot does not log errors for it.
func applySysctlFixes(items []store.AuditResult) []HardeningFixResult {
	var out []HardeningFixResult
	// Detect a missing drop-in directory before changing the live kernel.
	dir := filepath.Dir(hardeningSysctlConfPath)
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		err = fmt.Errorf("%s is not a directory", dir)
	}
	if err != nil {
		for _, r := range items {
			out = append(out, failed(r, err))
		}
		return out
	}
	type change struct {
		r       store.AuditResult
		undo    sysctlUndoState
		readErr error
	}
	var changes []change
	var accepted []keyValue
	for _, r := range items {
		kv := sysctlFixes[r.Name]
		prev, readErr := sysctlRuntime(kv.key)
		if _, err := hardeningRun("sysctl", "-w", kv.key+"="+kv.value); err != nil {
			out = append(out, failed(r, err))
			continue
		}
		changes = append(changes, change{r, sysctlUndoState{Key: kv.key, PrevRuntime: prev, AppliedValue: kv.value}, readErr})
		accepted = append(accepted, kv)
	}
	if len(accepted) == 0 {
		return out
	}
	prevLines, persistErr := persistSysctl(accepted)
	for i, c := range changes {
		var res HardeningFixResult
		if persistErr != nil {
			c.undo.RuntimeOnly = true
			res = failed(c.r, fmt.Errorf("set at runtime but not persisted: %w", persistErr))
		} else {
			c.undo.PrevLines = prevLines[i]
			res = applied(c.r, fmt.Sprintf("%s = %s set and saved to %s.", accepted[i].key, accepted[i].value, hardeningSysctlConfPath))
		}
		res.Message += recordHardeningUndo(c.r, HardeningUndoRecord{Kind: "sysctl", Sysctl: &c.undo}, c.readErr)
		out = append(out, res)
	}
	return out
}

// sysctlRuntime reads a kernel parameter's current value.
func sysctlRuntime(key string) (string, error) {
	// #nosec G304 -- kernel parameter path built from the fixer table.
	data, err := os.ReadFile(filepath.Join(hardeningProcSys, strings.ReplaceAll(key, ".", "/")))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// persistSysctl writes into the existing system configuration directory. It
// returns, for each key, the drop-in's lines it replaced.
func persistSysctl(kvs []keyValue) ([][]string, error) {
	var lines []string
	// #nosec G304 -- CSM-owned sysctl drop-in.
	if data, err := os.ReadFile(hardeningSysctlConfPath); err == nil {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	} else if errors.Is(err, os.ErrNotExist) {
		lines = []string{"# Managed by CSM: sysctl values applied from the hardening page."}
	} else {
		return nil, err
	}
	prev := make([][]string, len(kvs))
	for n, kv := range kvs {
		entry := kv.key + " = " + kv.value
		for i, line := range lines {
			k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.TrimSpace(k) == kv.key {
				prev[n] = append(prev[n], line)
				lines[i] = entry
			}
		}
		if len(prev[n]) == 0 {
			lines = append(lines, entry)
		}
	}
	if err := atomicio.AtomicWrite(hardeningSysctlConfPath, 0o644, []byte(strings.Join(lines, "\n")+"\n")); err != nil {
		return nil, err
	}
	return prev, nil
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
	updated, undo := rewriteSSHDConfig(string(orig), directives)
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

	notes := make([]string, len(items))
	for i, r := range items {
		notes[i] = recordHardeningUndo(r, HardeningUndoRecord{Kind: "ssh", SSH: &undo[i]}, nil)
	}
	msg := "Written to " + sshdConfigPath + " and sshd reloaded."
	if err := reloadSSHD(); err != nil {
		msg = "Written to " + sshdConfigPath + ", but reloading sshd failed (" + err.Error() + "); reload it manually."
	}
	out := make([]HardeningFixResult, 0, len(items))
	for i, r := range items {
		out = append(out, applied(r, msg+notes[i]))
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
// at the top of the file, and what it changed for each directive. Directives
// already in the block are kept, and active global lines for the same
// keywords are commented out so the file reads the way sshd applies it.
func rewriteSSHDConfig(content string, directives []keyValue) (string, []sshUndoState) {
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
	undo := make([]sshUndoState, len(directives))
	byKeyword := map[string]int{}
	for i, d := range directives {
		kw := strings.ToLower(d.key)
		prev, had := block[kw]
		undo[i] = sshUndoState{Keyword: d.key, PrevValue: prev.value, HadValue: had, AppliedValue: d.value}
		byKeyword[kw] = i
		block[kw] = d
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
			// A keyword already in the block may disable a line too; no
			// directive of this apply owns it.
			if d, ok := byKeyword[kw]; ok {
				undo[d].DisabledLines = append(undo[d].DisabledLines, line)
			}
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
	return strings.Join(append(head, body...), "\n"), undo
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

// applyPHPFixes writes the drop-ins, one per scan directory, then restarts
// PHP once. A check is applied only when every directory of its build took
// the drop-in.
func applyPHPFixes(items []store.AuditResult, installs []phpInstall) []HardeningFixResult {
	type plan struct {
		dirs  []string
		keys  []string
		items []store.AuditResult
	}
	byScanDir := map[string]*plan{}
	var plans []*plan
	var out []HardeningFixResult
	for _, r := range items {
		key, suffix, ok := phpFixFor(r.Name)
		if !ok {
			out = append(out, skipped(r, "No PHP directive for this check."))
			continue
		}
		inst, found := findPHPInstall(installs, suffix)
		p := byScanDir[inst.scanDir]
		if p == nil {
			dirs := phpInstallScanDirs(inst)
			if !found || len(dirs) == 0 {
				out = append(out, skipped(r, "Cannot verify the PHP scan directories. Apply this change manually."))
				continue
			}
			// The audit reads the CLI configuration. Write it last so a failed
			// web SAPI remains visible and the operator can retry the same fix.
			cli := filepath.Clean(inst.scanDir)
			dirs = slices.DeleteFunc(dirs, func(d string) bool { return d == cli })
			p = &plan{dirs: append(dirs, cli)}
			byScanDir[inst.scanDir] = p
			plans = append(plans, p)
		}
		p.keys = append(p.keys, key)
		p.items = append(p.items, r)
	}

	var written []string
	var completed []HardeningFixResult
	for _, p := range plans {
		var err error
		undo := make([][]phpUndoState, len(p.items))
		for _, d := range p.dirs {
			path := filepath.Join(d, hardeningPHPIniName)
			var prev []phpUndoState
			if prev, err = writePHPDropIn(path, p.keys); err != nil {
				err = fmt.Errorf("updating %s: %w", path, err)
				break
			}
			written = append(written, d)
			for i := range undo {
				undo[i] = append(undo[i], prev[i])
			}
		}
		for i, r := range p.items {
			var note string
			// A failed write can follow others, which did change their drop-ins.
			if len(undo[i]) > 0 {
				note = recordHardeningUndo(r, HardeningUndoRecord{Kind: "php", PHP: undo[i]}, nil)
			}
			if err != nil {
				res := failed(r, err)
				res.Message += note
				out = append(out, res)
				continue
			}
			completed = append(completed, applied(r, fmt.Sprintf("%s = Off written to %s.", p.keys[i], strings.Join(phpDropInPaths(p.dirs), ", "))+note))
		}
	}
	if len(written) > 0 {
		msg := reloadPHP(written)
		for i := range completed {
			completed[i].Message += " " + msg
		}
	}
	out = append(out, completed...)
	return out
}

// writePHPDropIn sets keys Off in the drop-in at path. It returns, for each
// key, the drop-in's line for it before; the whole drop-in is rewritten in
// the "key = value" form, so that is the form recorded.
func writePHPDropIn(path string, keys []string) ([]phpUndoState, error) {
	values := map[string]string{}
	var order []string
	f, err := (realOS{}).openRegularFile(path, syscall.O_NOFOLLOW)
	if err == nil {
		defer func() { _ = f.Close() }()
		data, readErr := io.ReadAll(f)
		if readErr != nil {
			return nil, readErr
		}
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
		return nil, err
	}
	undo := make([]phpUndoState, len(keys))
	for i, k := range keys {
		undo[i] = phpUndoState{Path: path, Key: k, Applied: "Off"}
		if v, had := values[k]; had {
			undo[i].PrevLine, undo[i].HadKey = k+" = "+v, true
		}
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
	if err := atomicio.AtomicWrite(path, 0o644, []byte(b.String())); err != nil {
		return nil, err
	}
	return undo, nil
}

func restartPHPFPM() (string, error) {
	if info, err := os.Stat(hardeningPHPFPMRestart); err == nil && info.Mode().IsRegular() {
		if _, err := hardeningRun(hardeningPHPFPMRestart); err != nil {
			return "", err
		}
		return "PHP-FPM restarted.", nil
	}
	if _, err := hardeningRun("systemctl", "try-reload-or-restart", "php*-fpm.service"); err != nil {
		return "", err
	}
	return "Running PHP-FPM services restarted.", nil
}

// reloadPHP makes running PHP load the new drop-ins: PHP-FPM, Apache when a
// mod_php directory was written, and LiteSpeed's detached lsphp processes.
// It reports what it did; a failure names what to restart by hand.
func reloadPHP(dirs []string) string {
	var notes []string
	if msg, err := restartPHPFPM(); err != nil {
		notes = append(notes, "Restart PHP-FPM manually ("+err.Error()+").")
	} else {
		notes = append(notes, msg)
	}
	if slices.ContainsFunc(dirs, func(d string) bool { return filepath.Base(filepath.Dir(d)) == "apache2" }) {
		if _, err := hardeningRun("systemctl", "try-reload-or-restart", "apache2.service"); err != nil {
			notes = append(notes, "Reload Apache manually ("+err.Error()+").")
		} else {
			notes = append(notes, "Apache reloaded.")
		}
	}
	if info, err := os.Stat(hardeningLSWSCtrl); err == nil && info.Mode().IsRegular() {
		if err := touchNoFollow(hardeningLSPHPRestartMarker); err != nil {
			notes = append(notes, "Restart LiteSpeed PHP manually ("+err.Error()+").")
		} else {
			notes = append(notes, "LiteSpeed PHP restart requested.")
		}
	}
	return strings.Join(notes, " ")
}

// touchNoFollow creates path if needed without following a symlink in its
// place, so a planted link cannot point the write elsewhere.
func touchNoFollow(path string) error {
	// #nosec G304 -- fixed LiteSpeed path chosen by the fixer.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return fmt.Errorf("%s must have a single link", path)
	}
	return safepath.SetModTime(f, time.Now())
}
