package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

// withPHPInstalls makes undo derive PHP drop-in paths from installs.
func withPHPInstalls(t *testing.T, installs []phpInstall) {
	t.Helper()
	old := hardeningPHPInstalls
	hardeningPHPInstalls = func() []phpInstall { return installs }
	t.Cleanup(func() { hardeningPHPInstalls = old })
}

// fileText returns path's content, or "<absent>" when there is no file.
func fileText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// fileModeOwner describes path's permission bits and owner.
func fileModeOwner(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%04o %d:%d", stModeBits(info.Mode()), st.Uid, st.Gid)
}

func editFile(t *testing.T, path, old, replacement string) {
	t.Helper()
	data := fileText(t, path)
	edited := strings.Replace(data, old, replacement, 1)
	if edited == data {
		t.Fatalf("%q is not in %s:\n%s", old, path, data)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
}

func storedUndoRecord(t *testing.T, name string) HardeningUndoRecord {
	t.Helper()
	rec, ok, err := readHardeningUndo(name)
	if err != nil || !ok {
		t.Fatalf("record %s: ok=%v err=%v", name, ok, err)
	}
	return rec
}

func wantUndoResult(t *testing.T, res HardeningFixResult, name, status, message string) {
	t.Helper()
	if res.Name != name || res.Status != status || !strings.Contains(res.Message, message) {
		t.Fatalf("result = %+v; want %s %s with %q", res, name, status, message)
	}
}

// recordCommands answers every command with success and logs it.
func recordCommands(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, filepath.Base(name)+" "+strings.Join(args, " "))
		return nil, nil
	}})
	return &calls
}

// withPHPRestartLogged stubs out cPanel's PHP-FPM restart script and logs
// the commands a PHP reload runs.
func withPHPRestartLogged(t *testing.T) *[]string {
	t.Helper()
	old := hardeningPHPFPMRestart
	hardeningPHPFPMRestart = filepath.Join(t.TempDir(), "missing-restart-script")
	t.Cleanup(func() { hardeningPHPFPMRestart = old })
	return recordCommands(t)
}

// fakeWHMTweak stands in for whmapi1 holding one tweak setting; a nil value
// is unset. It logs the value of each set, and refuses the values in
// rejects the way cPanel's validation does, changing nothing.
type fakeWHMTweak struct {
	key     string
	value   *string
	sets    []string
	rejects []string
}

func (f *fakeWHMTweak) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if slices.Contains(args, "get_tweaksetting") {
		if f.value == nil {
			return []byte(`{"data":{"tweaksetting":{"key":"` + f.key + `"}},"metadata":{"result":1,"reason":"OK"}}`), nil
		}
		return []byte(`{"data":{"tweaksetting":{"key":"` + f.key + `","value":"` + *f.value + `"}},"metadata":{"result":1,"reason":"OK"}}`), nil
	}
	set := strings.TrimPrefix(args[len(args)-1], "value=")
	f.sets = append(f.sets, set)
	if slices.Contains(f.rejects, set) {
		return []byte(`{"metadata":{"result":0,"reason":"The value is not valid."}}`), nil
	}
	f.value = &set
	return []byte(`{"metadata":{"result":1,"reason":"OK"}}`), nil
}

func withFakeWHMTweak(t *testing.T, key string, value *string) *fakeWHMTweak {
	t.Helper()
	f := &fakeWHMTweak{key: key, value: value}
	withMockCmd(t, &mockCmd{runContextStdout: f.run})
	return f
}

func applyOK(t *testing.T, out []HardeningFixResult) {
	t.Helper()
	for _, res := range out {
		if res.Status != "applied" || strings.Contains(res.Message, "Undo is unavailable") {
			t.Fatalf("apply = %+v", out)
		}
	}
}

func TestHardeningUndoRestoresSSH(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"absent from the block", "Port 2222\nMaxAuthTries 6\n  MaxAuthTries 8\nUseDNS yes\nMatch User backup\n    MaxAuthTries 10\n"},
		{"block value", strings.Join([]string{sshdBlockBegin, "MaxAuthTries 6", "UseDNS no", sshdBlockEnd, "Port 2222", "MaxAuthTries 3", ""}, "\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			path := withTempSSHDConfig(t, tc.config)
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			applied := fileText(t, path)
			*calls = nil
			wantUndoResult(t, UndoHardening("ssh_max_auth_tries"), "ssh_max_auth_tries", "undone", "")
			if got := fileText(t, path); got != tc.config {
				t.Fatalf("config after undo = %q, want %q", got, tc.config)
			}
			// The file is checked before sshd reloads it, as on apply.
			if want := []string{"sshd -t -f " + path, "systemctl reload sshd"}; !slices.Equal(*calls, want) {
				t.Errorf("calls = %q, want %q", *calls, want)
			}
			if got := fileText(t, path+".csm-bak"); got != applied {
				t.Errorf("backup = %q, want the file before the undo %q", got, applied)
			}
			wantNoUndoRecord(t, "ssh_max_auth_tries")
		})
	}
}

// A later apply of another fix disables new global lines for a keyword
// already in the block without recording them; undo re-enables every line
// CSM disabled for the keyword.
func TestHardeningUndoSSHReenablesEveryDisabledLine(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
	recordCommands(t)
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("MaxAuthTries 8\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_use_dns", Category: "ssh"}}))
	if want := sshdDisabledBy + "MaxAuthTries 8\n"; !strings.Contains(fileText(t, path), want) {
		t.Fatalf("the second apply did not disable the new line:\n%s", fileText(t, path))
	}
	wantUndoResult(t, UndoHardening("ssh_max_auth_tries"), "ssh_max_auth_tries", "undone", "")
	want := strings.Join([]string{sshdBlockBegin, "UseDNS no", sshdBlockEnd, "MaxAuthTries 6", "MaxAuthTries 8", ""}, "\n")
	if got := fileText(t, path); got != want {
		t.Fatalf("config = %q, want %q", got, want)
	}
}

func TestHardeningUndoRestoresSysctl(t *testing.T) {
	for _, tc := range []struct{ name, dropIn string }{
		{"existing drop-in", "# Managed by CSM\nnet.ipv4.conf.all.rp_filter=2\nfs.protected_hardlinks = 1\n net.ipv4.conf.all.rp_filter = 0 \n"},
		{"drop-in created by the apply", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			conf := withTempSysctl(t, tc.dropIn, map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
			wantUndoResult(t, UndoHardening("os_sysctl_rp_filter"), "os_sysctl_rp_filter", "undone", "")
			want := tc.dropIn
			if want == "" {
				want = "<absent>"
			}
			if got := fileText(t, conf); got != want {
				t.Fatalf("drop-in after undo = %q, want %q", got, want)
			}
			if got, err := sysctlRuntime("net.ipv4.conf.all.rp_filter"); err != nil || got != "2" {
				t.Fatalf("runtime = %q, %v; want 2", got, err)
			}
			wantNoUndoRecord(t, "os_sysctl_rp_filter")
		})
	}
}

// cPanel takes skipboxtrapper=0 back; maxemailsperhour accepts no 0.
func TestHardeningUndoRestoresTweak(t *testing.T) {
	withHardeningUndoDir(t)
	before := "0"
	whm := withFakeWHMTweak(t, "skipboxtrapper", &before)
	if res := applyHardeningSingle(store.AuditResult{Name: "cp_boxtrapper", Category: "cpanel"}); res.Status != "applied" {
		t.Fatalf("apply = %+v", res)
	}
	wantUndoResult(t, UndoHardening("cp_boxtrapper"), "cp_boxtrapper", "undone", "")
	if whm.value == nil || *whm.value != "0" || !slices.Equal(whm.sets, []string{"1", "0"}) {
		t.Fatalf("tweak = %v, sets = %q", whm.value, whm.sets)
	}
	wantNoUndoRecord(t, "cp_boxtrapper")
}

// An earlier value whmapi1 cannot set back, empty or one cPanel's validation
// refuses, leaves the applied value and the record, and the refusal says to
// use WHM Tweak Settings instead of failing the same way on every retry.
func TestHardeningUndoTweakWHMWillNotTakeBack(t *testing.T) {
	for _, tc := range []struct {
		name, before string
		sets         []string
	}{
		// cPanel saves a setting only when given a value, so it is not sent.
		{"empty", "", []string{"200"}},
		{"refused by cPanel", "0", []string{"200", "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			before := tc.before
			whm := withFakeWHMTweak(t, "maxemailsperhour", &before)
			whm.rejects = []string{"", "0"}
			if res := applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"}); res.Status != "applied" {
				t.Fatalf("apply = %+v", res)
			}
			rec := storedUndoRecord(t, "cp_max_emails_hour")
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "refused", "WHM Tweak Settings")
			if *whm.value != "200" || !slices.Equal(whm.sets, tc.sets) {
				t.Fatalf("tweak = %q, sets = %q, want 200 and %q", *whm.value, whm.sets, tc.sets)
			}
			if got := storedUndoRecord(t, rec.Name); !reflect.DeepEqual(got, rec) {
				t.Fatalf("record = %+v, want it kept as %+v", got, rec)
			}
		})
	}
}

// whmapi1 set_tweaksetting saves only settings given a value, so it cannot
// put back a tweak that had none. Undo says how to clear it instead of
// reporting a restore that did not happen.
func TestHardeningUndoTweakRecordedUnset(t *testing.T) {
	withHardeningUndoDir(t)
	whm := withFakeWHMTweak(t, "maxemailsperhour", nil)
	if res := applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"}); res.Status != "applied" {
		t.Fatalf("apply = %+v", res)
	}
	rec := storedUndoRecord(t, "cp_max_emails_hour")
	wantUndoResult(t, UndoHardening("cp_max_emails_hour"), "cp_max_emails_hour", "refused", "WHM Tweak Settings")
	if *whm.value != "200" || len(whm.sets) != 1 {
		t.Fatalf("tweak = %q, sets = %q", *whm.value, whm.sets)
	}
	if got := storedUndoRecord(t, "cp_max_emails_hour"); !reflect.DeepEqual(got, rec) {
		t.Fatalf("record = %+v, want it kept as %+v", got, rec)
	}
}

func TestHardeningUndoRestoresPHP(t *testing.T) {
	withHardeningUndoDir(t)
	calls := withPHPRestartLogged(t)
	ver, _ := debianPHPTree(t, "cli", "fpm", "apache2")
	ini := func(sapi string) string { return filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName) }
	const before = "; Managed by CSM: PHP settings applied from the hardening page.\nexpose_php = On\nenable_dl = Off\n"
	if err := os.WriteFile(ini("fpm"), []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
	withPHPInstalls(t, installs)
	applyOK(t, applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, installs))
	*calls = nil
	wantUndoResult(t, UndoHardening("php_expose_82"), "php_expose_82", "undone", "")
	for sapi, want := range map[string]string{"fpm": before, "cli": "<absent>", "apache2": "<absent>"} {
		if got := fileText(t, ini(sapi)); got != want {
			t.Errorf("%s drop-in = %q, want %q", sapi, got, want)
		}
	}
	for _, want := range []string{"systemctl try-reload-or-restart php*-fpm.service", "systemctl try-reload-or-restart apache2.service"} {
		if !slices.Contains(*calls, want) {
			t.Errorf("calls = %q, missing %q", *calls, want)
		}
	}
	wantNoUndoRecord(t, "php_expose_82")
}

func TestHardeningUndoRestoresMode(t *testing.T) {
	t.Run("shadow", func(t *testing.T) {
		withHardeningUndoDir(t)
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
		before := fileModeOwner(t, path)
		if res := applyHardeningSingle(store.AuditResult{Name: "os_shadow_permissions", Category: "os"}); res.Status != "applied" {
			t.Fatalf("apply = %+v", res)
		}
		wantUndoResult(t, UndoHardening("os_shadow_permissions"), "os_shadow_permissions", "undone", "")
		if got := fileModeOwner(t, path); got != before {
			t.Fatalf("shadow = %s, want %s", got, before)
		}
		wantNoUndoRecord(t, "os_shadow_permissions")
	})
	t.Run("tmp dir", func(t *testing.T) {
		withHardeningUndoDir(t)
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		root := os.Geteuid() == 0
		if root {
			if err := os.Chown(dir, 1001, 1002); err != nil {
				t.Fatal(err)
			}
		}
		old := hardeningTmpDirs
		hardeningTmpDirs = map[string]string{"os_tmp_permissions": dir}
		t.Cleanup(func() { hardeningTmpDirs = old })
		before := fileModeOwner(t, dir)
		if root {
			if res := applyHardeningSingle(store.AuditResult{Name: "os_tmp_permissions", Category: "os"}); res.Status != "applied" {
				t.Fatalf("apply = %+v", res)
			}
		} else {
			// Only root can give the directory to root: record what the apply
			// does apart from the owner change.
			uid, gid := fileOwner(t, dir)
			if err := writeHardeningUndo(HardeningUndoRecord{Name: "os_tmp_permissions", Category: "os", Kind: "mode", Mode: &modeUndoState{
				Path: dir, Mode: 0o755, UID: uid, GID: gid, AppliedMode: 0o1777, AppliedUID: uid, AppliedGID: gid,
			}}); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
				t.Fatal(err)
			}
		}
		wantUndoResult(t, UndoHardening("os_tmp_permissions"), "os_tmp_permissions", "undone", "")
		if got := fileModeOwner(t, dir); got != before {
			t.Fatalf("dir = %s, want %s", got, before)
		}
		wantNoUndoRecord(t, "os_tmp_permissions")
	})
}

func TestHardeningUndoRestoresCompilers(t *testing.T) {
	t.Run("chmod", func(t *testing.T) {
		withHardeningUndoDir(t)
		dir := t.TempDir()
		gcc := filepath.Join(dir, "gcc")
		if err := os.WriteFile(gcc, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(gcc, 0o755); err != nil {
			t.Fatal(err)
		}
		cc := filepath.Join(dir, "cc")
		if err := os.Symlink(gcc, cc); err != nil {
			t.Fatal(err)
		}
		withCompilerPaths(t, cc, filepath.Join(dir, "missing-compilers-script"))
		before := fileModeOwner(t, gcc)
		if res := applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"}); res.Status != "applied" {
			t.Fatalf("apply = %+v", res)
		}
		wantUndoResult(t, UndoHardening("cp_compilers"), "cp_compilers", "undone", "")
		if got := fileModeOwner(t, gcc); got != before {
			t.Fatalf("compiler = %s, want %s", got, before)
		}
		wantNoUndoRecord(t, "cp_compilers")
	})
	t.Run("script", func(t *testing.T) {
		withHardeningUndoDir(t)
		dir := t.TempDir()
		script := filepath.Join(dir, "compilers")
		if err := os.WriteFile(script, nil, 0o700); err != nil {
			t.Fatal(err)
		}
		cc := filepath.Join(dir, "cc")
		if err := os.WriteFile(cc, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(cc, 0o755); err != nil {
			t.Fatal(err)
		}
		withCompilerPaths(t, cc, script)
		calls := compilersScript(t, cc)
		if res := applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"}); res.Status != "applied" {
			t.Fatalf("apply = %+v", res)
		}
		wantUndoResult(t, UndoHardening("cp_compilers"), "cp_compilers", "undone", "")
		// cPanel's own restore runs; it sets modes, not the exact earlier ones.
		if want := []string{"compilers off", "compilers on"}; !slices.Equal(*calls, want) {
			t.Fatalf("calls = %q, want %q", *calls, want)
		}
		wantNoUndoRecord(t, "cp_compilers")
	})
}

// compilersScript stands in for cPanel's /scripts/compilers: off restricts
// cc to 0750, on opens it to 0755.
func compilersScript(t *testing.T, cc string) *[]string {
	t.Helper()
	var calls []string
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, filepath.Base(name)+" "+strings.Join(args, " "))
		mode := os.FileMode(0o755)
		if args[0] == "off" {
			mode = 0o750
		}
		return nil, os.Chmod(cc, mode)
	}})
	return &calls
}

func TestHardeningUndoRestoresFile(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempCPUpdateConf(t)
	const before = "CPANEL=release\nUPDATES=manual\nRPMUP=daily\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	mode := fileModeOwner(t, path)
	if res := applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"}); res.Status != "applied" {
		t.Fatalf("apply = %+v", res)
	}
	wantUndoResult(t, UndoHardening("cp_updates"), "cp_updates", "undone", "")
	if got := fileText(t, path); got != before {
		t.Fatalf("file = %q, want %q", got, before)
	}
	if got := fileModeOwner(t, path); got != mode {
		t.Fatalf("file mode = %s, want %s", got, mode)
	}
	wantNoUndoRecord(t, "cp_updates")
}

// cPanel rewrites cpupdate.conf when its update preferences are saved. Undo
// puts back only the UPDATES lines the apply changed, the duplicates it
// commented out included, and keeps every other line as it is now.
func TestHardeningUndoFileRestoresOnlyUpdatesLines(t *testing.T) {
	for _, tc := range []struct {
		name, before string
		// now replaces the applied file before the undo, unless empty.
		now, want string
	}{
		// Sorted keys, no comments, RPMUP changed: how a WHM save writes it.
		{"other lines rewritten", "CPANEL=release\n# local note\nUPDATES=manual\nRPMUP=daily\n",
			"CPANEL=release\nRPMUP=manual\nSARULESUP=daily\nUPDATES=daily\n",
			"CPANEL=release\nRPMUP=manual\nSARULESUP=daily\nUPDATES=manual\n"},
		{"duplicates uncommented in place", "UPDATES=manual\nRPMUP=daily\nupdates = never\n",
			"UPDATES=daily\nRPMUP=manual\n# updates = never\n",
			"UPDATES=manual\nRPMUP=manual\nupdates = never\n"},
		{"duplicates after the comments were dropped", "UPDATES=manual\nRPMUP=daily\nupdates = never\n",
			"RPMUP=manual\nUPDATES=daily\n",
			"RPMUP=manual\nUPDATES=manual\nupdates = never\n"},
		{"line the apply added", "CPANEL=release\n",
			"CPANEL=edge\nUPDATES=daily\n",
			"CPANEL=edge\n"},
		// The comment before the first line was there already and stays.
		{"same comment before the apply", "# UPDATES=never\nUPDATES=manual\nUPDATES=never\n",
			"",
			"# UPDATES=never\nUPDATES=manual\nUPDATES=never\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte(tc.before), 0o640); err != nil {
				t.Fatal(err)
			}
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})})
			if tc.now != "" {
				if err := os.WriteFile(path, []byte(tc.now), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			wantUndoResult(t, UndoHardening("cp_updates"), "cp_updates", "undone", "UPDATES restored in "+path)
			if got := fileText(t, path); got != tc.want {
				t.Fatalf("file = %q, want %q", got, tc.want)
			}
			wantNoUndoRecord(t, "cp_updates")
		})
	}
}

// Undo refuses, keeping the record and the host as they are, when the
// setting no longer holds what the apply wrote.
func TestHardeningUndoRefusesChangedSetting(t *testing.T) {
	for _, tc := range []struct {
		name, fix string
		// setup applies the fix, changes its setting by hand, and returns
		// the state undo must leave alone.
		setup func(t *testing.T) func() string
	}{
		{"ssh block value", "ssh_max_auth_tries", func(t *testing.T) func() string {
			path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, "\nMaxAuthTries 4\n", "\nMaxAuthTries 5\n")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		{"ssh block line removed", "ssh_max_auth_tries", func(t *testing.T) func() string {
			path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, "\nMaxAuthTries 4\n", "\n")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		{"ssh block end removed", "ssh_max_auth_tries", func(t *testing.T) func() string {
			path := withTempSSHDConfig(t, "Port 2222\n")
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, sshdBlockEnd+"\n", "")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		// Enabled there, the line would apply to that Match block only.
		{"ssh disabled line now under a Match block", "ssh_max_auth_tries", func(t *testing.T) func() string {
			path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, sshdDisabledBy+"MaxAuthTries 6\n", "Match User backup\n"+sshdDisabledBy+"MaxAuthTries 6\n")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		{"ssh disabled line removed", "ssh_max_auth_tries", func(t *testing.T) func() string {
			path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, sshdDisabledBy+"MaxAuthTries 6\n", "")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		{"sysctl runtime", "os_sysctl_rp_filter", func(t *testing.T) func() string {
			conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
			if _, err := kernelSysctl("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileText(t, conf) + runtimeValue(t, "net.ipv4.conf.all.rp_filter") }
		}},
		// The runtime value is back, but the drop-in would set it again at boot.
		{"sysctl runtime set back by hand", "os_sysctl_rp_filter", func(t *testing.T) func() string {
			conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
			if _, err := kernelSysctl("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileText(t, conf) + runtimeValue(t, "net.ipv4.conf.all.rp_filter") }
		}},
		{"sysctl drop-in", "os_sysctl_rp_filter", func(t *testing.T) func() string {
			conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
			editFile(t, conf, "net.ipv4.conf.all.rp_filter = 1", "net.ipv4.conf.all.rp_filter = 0")
			return func() string { return fileText(t, conf) + runtimeValue(t, "net.ipv4.conf.all.rp_filter") }
		}},
		{"tweak", "cp_max_emails_hour", func(t *testing.T) func() string {
			before := "0"
			whm := withFakeWHMTweak(t, "maxemailsperhour", &before)
			if res := applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"}); res.Status != "applied" {
				t.Fatalf("apply = %+v", res)
			}
			changed := "300"
			whm.value, whm.sets = &changed, nil
			return func() string { return *whm.value + strings.Join(whm.sets, ";") }
		}},
		{"php", "php_expose_82", func(t *testing.T) func() string {
			calls := withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli", "fpm")
			ini := func(sapi string) string { return filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName) }
			installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
			withPHPInstalls(t, installs)
			applyOK(t, applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, installs))
			// The record lists fpm first: a changed CLI drop-in must stop the
			// fpm restore too.
			editFile(t, ini("cli"), "expose_php = Off", "expose_php = On")
			*calls = nil
			return func() string { return fileText(t, ini("fpm")) + fileText(t, ini("cli")) + strings.Join(*calls, ";") }
		}},
		{"shadow mode", "os_shadow_permissions", func(t *testing.T) func() string {
			path := filepath.Join(t.TempDir(), "shadow")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			old := hardeningShadowPath
			hardeningShadowPath = path
			t.Cleanup(func() { hardeningShadowPath = old })
			if res := applyHardeningSingle(store.AuditResult{Name: "os_shadow_permissions", Category: "os"}); res.Status != "applied" {
				t.Fatalf("apply = %+v", res)
			}
			if err := os.Chmod(path, 0o604); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileModeOwner(t, path) }
		}},
		{"tmp dir mode", "os_tmp_permissions", func(t *testing.T) func() string {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			old := hardeningTmpDirs
			hardeningTmpDirs = map[string]string{"os_tmp_permissions": dir}
			t.Cleanup(func() { hardeningTmpDirs = old })
			uid, gid := fileOwner(t, dir)
			// The apply's 1777 was changed back to 0755 by hand.
			if err := writeHardeningUndo(HardeningUndoRecord{Name: "os_tmp_permissions", Category: "os", Kind: "mode", Mode: &modeUndoState{
				Path: dir, Mode: 0o700, UID: uid, GID: gid, AppliedMode: 0o1777, AppliedUID: uid, AppliedGID: gid,
			}}); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileModeOwner(t, dir) }
		}},
		{"compilers chmod", "cp_compilers", func(t *testing.T) func() string {
			dir := t.TempDir()
			gcc := filepath.Join(dir, "gcc")
			if err := os.WriteFile(gcc, nil, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(gcc, 0o755); err != nil {
				t.Fatal(err)
			}
			withCompilerPaths(t, gcc, filepath.Join(dir, "missing-compilers-script"))
			if res := applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"}); res.Status != "applied" {
				t.Fatalf("apply = %+v", res)
			}
			if err := os.Chmod(gcc, 0o700); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileModeOwner(t, gcc) }
		}},
		{"file", "cp_updates", func(t *testing.T) func() string {
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte("UPDATES=manual\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			if res := applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"}); res.Status != "applied" {
				t.Fatalf("apply = %+v", res)
			}
			if err := os.WriteFile(path, []byte("UPDATES=never\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileText(t, path) + fileModeOwner(t, path) }
		}},
		{"file line removed", "cp_updates", func(t *testing.T) func() string {
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte("CPANEL=release\nUPDATES=manual\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})})
			if err := os.WriteFile(path, []byte("CPANEL=release\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileText(t, path) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			state := tc.setup(t)
			rec := storedUndoRecord(t, tc.fix)
			before := state()
			wantUndoResult(t, UndoHardening(tc.fix), tc.fix, "refused", "changed since the apply")
			if after := state(); after != before {
				t.Errorf("undo changed the host:\n%s\nwant\n%s", after, before)
			}
			if got := storedUndoRecord(t, tc.fix); !reflect.DeepEqual(got, rec) {
				t.Errorf("record = %+v, want it kept as %+v", got, rec)
			}
		})
	}
}

// A setting put back by hand, as the refusal for a WHM value asks, holds the
// state from before the apply: undo removes the record and reports it done,
// changing nothing, so the page stops offering an Undo that would refuse.
func TestHardeningUndoAlreadyBack(t *testing.T) {
	for _, tc := range []struct {
		name, fix string
		// setup applies the fix, puts its setting back by hand, and returns
		// the state undo must leave alone.
		setup func(t *testing.T) func() string
	}{
		{"ssh", "ssh_max_auth_tries", func(t *testing.T) func() string {
			const original = "MaxAuthTries 6\nUseDNS yes\n"
			path := withTempSSHDConfig(t, original)
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}, {Name: "ssh_use_dns", Category: "ssh"}}))
			editFile(t, path, "MaxAuthTries 4\n", "")
			editFile(t, path, sshdDisabledBy+"MaxAuthTries 6\n", "MaxAuthTries 6\n")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		{"ssh block value", "ssh_max_auth_tries", func(t *testing.T) func() string {
			path := withTempSSHDConfig(t, strings.Join([]string{sshdBlockBegin, "MaxAuthTries 6", sshdBlockEnd, "Port 2222", ""}, "\n"))
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, "MaxAuthTries 4", "MaxAuthTries 6")
			*calls = nil
			return func() string { return fileText(t, path) + strings.Join(*calls, ";") }
		}},
		{"sysctl", "os_sysctl_rp_filter", func(t *testing.T) func() string {
			conf := withTempSysctl(t, "fs.protected_hardlinks = 1\nnet.ipv4.conf.all.rp_filter=2\n", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
			editFile(t, conf, "net.ipv4.conf.all.rp_filter = 1", "net.ipv4.conf.all.rp_filter = 2")
			if _, err := kernelSysctl("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"); err != nil {
				t.Fatal(err)
			}
			var calls []string
			withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				return nil, nil
			}})
			return func() string {
				return fileText(t, conf) + runtimeValue(t, "net.ipv4.conf.all.rp_filter") + strings.Join(calls, ";")
			}
		}},
		{"sysctl runtime only", "os_sysctl_rp_filter", func(t *testing.T) func() string {
			conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			if err := os.Mkdir(conf, 0o755); err != nil {
				t.Fatal(err)
			}
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			if out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}); out[0].Status != "failed" {
				t.Fatalf("apply = %+v", out)
			}
			if _, err := kernelSysctl("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"); err != nil {
				t.Fatal(err)
			}
			return func() string { return runtimeValue(t, "net.ipv4.conf.all.rp_filter") }
		}},
		// WHM's own reset leaves the tweak with no value, as before the apply.
		{"tweak had no value", "cp_max_emails_hour", func(t *testing.T) func() string {
			whm := withFakeWHMTweak(t, "maxemailsperhour", nil)
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"})})
			whm.value, whm.sets = nil, nil
			return func() string { return fmt.Sprint(whm.value, whm.sets) }
		}},
		{"tweak empty", "cp_max_emails_hour", func(t *testing.T) func() string {
			empty := ""
			whm := withFakeWHMTweak(t, "maxemailsperhour", &empty)
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"})})
			whm.value, whm.sets = nil, nil
			return func() string { return fmt.Sprint(whm.value, whm.sets) }
		}},
		{"tweak value", "cp_boxtrapper", func(t *testing.T) func() string {
			before := "0"
			whm := withFakeWHMTweak(t, "skipboxtrapper", &before)
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_boxtrapper", Category: "cpanel"})})
			again := "0"
			whm.value, whm.sets = &again, nil
			return func() string { return *whm.value + strings.Join(whm.sets, ";") }
		}},
		{"php", "php_expose_82", func(t *testing.T) func() string {
			calls := withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli", "fpm")
			ini := func(sapi string) string { return filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName) }
			if err := os.WriteFile(ini("fpm"), []byte(phpDropInHeader+"\nexpose_php = On\nenable_dl = Off\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
			withPHPInstalls(t, installs)
			applyOK(t, applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, installs))
			editFile(t, ini("fpm"), "expose_php = Off", "expose_php=On")
			if err := os.Remove(ini("cli")); err != nil {
				t.Fatal(err)
			}
			*calls = nil
			return func() string { return fileText(t, ini("fpm")) + fileText(t, ini("cli")) + strings.Join(*calls, ";") }
		}},
		{"shadow mode", "os_shadow_permissions", func(t *testing.T) func() string {
			path := filepath.Join(t.TempDir(), "shadow")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			old := hardeningShadowPath
			hardeningShadowPath = path
			t.Cleanup(func() { hardeningShadowPath = old })
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "os_shadow_permissions", Category: "os"})})
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileModeOwner(t, path) }
		}},
		{"compilers chmod", "cp_compilers", func(t *testing.T) func() string {
			dir := t.TempDir()
			gcc := filepath.Join(dir, "gcc")
			if err := os.WriteFile(gcc, nil, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(gcc, 0o755); err != nil {
				t.Fatal(err)
			}
			withCompilerPaths(t, gcc, filepath.Join(dir, "missing-compilers-script"))
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"})})
			if err := os.Chmod(gcc, 0o755); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileModeOwner(t, gcc) }
		}},
		{"compilers script", "cp_compilers", func(t *testing.T) func() string {
			dir := t.TempDir()
			script := filepath.Join(dir, "compilers")
			if err := os.WriteFile(script, nil, 0o700); err != nil {
				t.Fatal(err)
			}
			cc := filepath.Join(dir, "cc")
			if err := os.WriteFile(cc, nil, 0o755); err != nil {
				t.Fatal(err)
			}
			withCompilerPaths(t, cc, script)
			calls := compilersScript(t, cc)
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"})})
			// Compilers opened again by hand, as "compilers on" does.
			if err := os.Chmod(cc, 0o755); err != nil {
				t.Fatal(err)
			}
			*calls = nil
			return func() string { return fileModeOwner(t, cc) + strings.Join(*calls, ";") }
		}},
		// cPanel's Update Preferences rewrote the file, other keys changed.
		{"file", "cp_updates", func(t *testing.T) func() string {
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte("CPANEL=release\nUPDATES=manual\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})})
			if err := os.WriteFile(path, []byte("CPANEL=release\nRPMUP=daily\nUPDATES=manual\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return func() string { return fileText(t, path) + fileModeOwner(t, path) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			state := tc.setup(t)
			storedUndoRecord(t, tc.fix)
			before := state()
			wantUndoResult(t, UndoHardening(tc.fix), tc.fix, "undone", "already back to its earlier state")
			if after := state(); after != before {
				t.Errorf("undo changed the host:\n%s\nwant\n%s", after, before)
			}
			wantNoUndoRecord(t, tc.fix)
		})
	}
}

func runtimeValue(t *testing.T, key string) string {
	t.Helper()
	value, err := sysctlRuntime(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// A record whose state, key or path is not the one the fix name gives is
// never acted on, even when the host holds its applied state.
func TestHardeningUndoRefusesMismatchedRecord(t *testing.T) {
	const phpHeader = "; Managed by CSM: PHP settings applied from the hardening page.\n"
	for _, tc := range []struct {
		name string
		// setup writes the record and returns the state undo must leave alone.
		setup func(t *testing.T) (HardeningUndoRecord, func() string)
	}{
		{"ssh keyword", func(t *testing.T) (HardeningUndoRecord, func() string) {
			path := withTempSSHDConfig(t, strings.Join([]string{sshdBlockBegin, "PermitRootLogin no", sshdBlockEnd, sshdDisabledBy + "PermitRootLogin yes", ""}, "\n"))
			calls := recordCommands(t)
			return HardeningUndoRecord{Name: "ssh_max_auth_tries", Kind: "ssh", SSH: &sshUndoState{
				Keyword: "PermitRootLogin", AppliedValue: "no", DisabledLines: []string{"PermitRootLogin yes"},
			}}, func() string {
				return fileText(t, path) + strings.Join(*calls, ";")
			}
		}},
		{"no ssh state", func(t *testing.T) (HardeningUndoRecord, func() string) {
			path := withTempSSHDConfig(t, strings.Join([]string{sshdBlockBegin, "MaxAuthTries 4", sshdBlockEnd, ""}, "\n"))
			calls := recordCommands(t)
			return HardeningUndoRecord{Name: "ssh_max_auth_tries", Kind: "file", File: &fileUndoState{
				Path: path, Previous: "MaxAuthTries 6\n", Applied: fileText(t, path),
			}}, func() string {
				return fileText(t, path) + strings.Join(*calls, ";")
			}
		}},
		{"sysctl key", func(t *testing.T) (HardeningUndoRecord, func() string) {
			conf := withTempSysctl(t, "kernel.modprobe = /sbin/modprobe\n", map[string]string{"kernel.modprobe": "/sbin/modprobe"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			return HardeningUndoRecord{Name: "os_sysctl_rp_filter", Kind: "sysctl", Sysctl: &sysctlUndoState{
				Key: "kernel.modprobe", PrevRuntime: "/var/tmp/x", PrevLines: []string{"kernel.modprobe = /var/tmp/x"}, AppliedValue: "/sbin/modprobe",
			}}, func() string {
				return fileText(t, conf) + runtimeValue(t, "kernel.modprobe")
			}
		}},
		{"tweak key", func(t *testing.T) (HardeningUndoRecord, func() string) {
			value := "0"
			whm := withFakeWHMTweak(t, "resetpass", &value)
			return HardeningUndoRecord{Name: "cp_max_emails_hour", Kind: "tweak", Tweak: &tweakUndoState{
				Key: "resetpass", Previous: "1", HadValue: true, Applied: "0",
			}}, func() string {
				return *whm.value + strings.Join(whm.sets, ";")
			}
		}},
		{"php path", func(t *testing.T) (HardeningUndoRecord, func() string) {
			withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli")
			withPHPInstalls(t, []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}})
			other := filepath.Join(t.TempDir(), hardeningPHPIniName)
			if err := os.WriteFile(other, []byte(phpHeader+"expose_php = Off\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return HardeningUndoRecord{Name: "php_expose_82", Kind: "php", PHP: []phpUndoState{
				{Path: other, Key: "expose_php", PrevLine: "expose_php = On", HadKey: true, Applied: "Off"},
			}}, func() string {
				return fileText(t, other)
			}
		}},
		{"php key", func(t *testing.T) (HardeningUndoRecord, func() string) {
			withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli")
			ini := filepath.Join(ver, "cli", "conf.d", hardeningPHPIniName)
			withPHPInstalls(t, []phpInstall{{shortID: "82", scanDir: filepath.Dir(ini)}})
			if err := os.WriteFile(ini, []byte(phpHeader+"allow_url_fopen = Off\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return HardeningUndoRecord{Name: "php_expose_82", Kind: "php", PHP: []phpUndoState{
				{Path: ini, Key: "allow_url_fopen", PrevLine: "allow_url_fopen = On", HadKey: true, Applied: "Off"},
			}}, func() string {
				return fileText(t, ini)
			}
		}},
		{"shadow path", func(t *testing.T) (HardeningUndoRecord, func() string) {
			dir := t.TempDir()
			other := filepath.Join(dir, "passwd")
			if err := os.WriteFile(other, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			old := hardeningShadowPath
			hardeningShadowPath = filepath.Join(dir, "shadow")
			t.Cleanup(func() { hardeningShadowPath = old })
			uid, gid := fileOwner(t, other)
			return HardeningUndoRecord{Name: "os_shadow_permissions", Kind: "mode", Mode: &modeUndoState{
				Path: other, Mode: 0o644, UID: uid, GID: gid, AppliedMode: 0o600, AppliedUID: uid, AppliedGID: gid,
			}}, func() string {
				return fileModeOwner(t, other)
			}
		}},
		{"compiler path", func(t *testing.T) (HardeningUndoRecord, func() string) {
			dir := t.TempDir()
			gcc, other := filepath.Join(dir, "gcc"), filepath.Join(dir, "other")
			for _, path := range []string{gcc, other} {
				if err := os.WriteFile(path, nil, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			withCompilerPaths(t, gcc, filepath.Join(dir, "missing-compilers-script"))
			uid, gid := fileOwner(t, other)
			return HardeningUndoRecord{Name: "cp_compilers", Kind: "compilers", Compilers: &compilersUndoState{
				Method: "chmod", Path: other, Mode: 0o755, UID: uid, GID: gid, AppliedMode: 0o750, AppliedUID: uid, AppliedGID: gid,
			}}, func() string {
				return fileModeOwner(t, other) + fileModeOwner(t, gcc)
			}
		}},
		{"compiler method", func(t *testing.T) (HardeningUndoRecord, func() string) {
			dir := t.TempDir()
			cc, script := filepath.Join(dir, "cc"), filepath.Join(dir, "compilers")
			for _, path := range []string{cc, script} {
				if err := os.WriteFile(path, nil, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			withCompilerPaths(t, cc, script)
			calls := compilersScript(t, cc)
			return HardeningUndoRecord{Name: "cp_compilers", Kind: "compilers", Compilers: &compilersUndoState{Method: "make"}},
				func() string { return fileModeOwner(t, cc) + strings.Join(*calls, ";") }
		}},
		// The apply changes UPDATES lines only; a record changing another key
		// would have undo rewrite it.
		{"file content", func(t *testing.T) (HardeningUndoRecord, func() string) {
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte("RPMUP=daily\nUPDATES=daily\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return HardeningUndoRecord{Name: "cp_updates", Kind: "file", File: &fileUndoState{
				Path: path, Previous: "RPMUP=never\nUPDATES=manual\n", Applied: "RPMUP=daily\nUPDATES=daily\n",
			}}, func() string {
				return fileText(t, path)
			}
		}},
		// The apply always sets or adds the line; undo would drop it here.
		{"file without the line the apply sets", func(t *testing.T) (HardeningUndoRecord, func() string) {
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte("UPDATES=daily\n# UPDATES=never\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return HardeningUndoRecord{Name: "cp_updates", Kind: "file", File: &fileUndoState{
				Path: path, Previous: "UPDATES=manual\nUPDATES=never\n", Applied: "# UPDATES=manual\n# UPDATES=never\n",
			}}, func() string {
				return fileText(t, path)
			}
		}},
		// Undo would put RPMUP=never in place of the UPDATES line.
		{"file line taken over", func(t *testing.T) (HardeningUndoRecord, func() string) {
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte("RPMUP=daily\nUPDATES=daily\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return HardeningUndoRecord{Name: "cp_updates", Kind: "file", File: &fileUndoState{
				Path: path, Previous: "RPMUP=daily\nRPMUP=never\n", Applied: "RPMUP=daily\nUPDATES=daily\n",
			}}, func() string {
				return fileText(t, path)
			}
		}},
		{"file path", func(t *testing.T) (HardeningUndoRecord, func() string) {
			withTempCPUpdateConf(t)
			other := filepath.Join(t.TempDir(), "other.conf")
			if err := os.WriteFile(other, []byte("UPDATES=daily\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return HardeningUndoRecord{Name: "cp_updates", Kind: "file", File: &fileUndoState{
				Path: other, Previous: "UPDATES=manual\n", Applied: "UPDATES=daily\n",
			}}, func() string {
				return fileText(t, other)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			rec, state := tc.setup(t)
			if err := writeHardeningUndo(rec); err != nil {
				t.Fatal(err)
			}
			rec = storedUndoRecord(t, rec.Name)
			before := state()
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "refused", "does not match")
			if after := state(); after != before {
				t.Errorf("undo acted on the record:\n%s\nwant\n%s", after, before)
			}
			if got := storedUndoRecord(t, rec.Name); !reflect.DeepEqual(got, rec) {
				t.Errorf("record = %+v, want it kept as %+v", got, rec)
			}
		})
	}
}

// Undoing one fix leaves a fix sharing its file applied, in either order.
func TestHardeningUndoSharedFiles(t *testing.T) {
	for _, order := range [][2]string{{"ssh_max_auth_tries", "ssh_x11_forwarding"}, {"ssh_x11_forwarding", "ssh_max_auth_tries"}} {
		t.Run("ssh/"+order[0]+" first", func(t *testing.T) {
			withHardeningUndoDir(t)
			const original = "Port 2222\nMaxAuthTries 6\nX11Forwarding yes\nUseDNS yes\n"
			path := withTempSSHDConfig(t, original)
			recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}, {Name: "ssh_x11_forwarding", Category: "ssh"}}))
			wantUndoResult(t, UndoHardening(order[0]), order[0], "undone", "")
			want := map[string]string{
				"ssh_max_auth_tries": strings.Join([]string{sshdBlockBegin, "X11Forwarding no", sshdBlockEnd, "Port 2222", "MaxAuthTries 6", sshdDisabledBy + "X11Forwarding yes", "UseDNS yes", ""}, "\n"),
				"ssh_x11_forwarding": strings.Join([]string{sshdBlockBegin, "MaxAuthTries 4", sshdBlockEnd, "Port 2222", sshdDisabledBy + "MaxAuthTries 6", "X11Forwarding yes", "UseDNS yes", ""}, "\n"),
			}[order[0]]
			if got := fileText(t, path); got != want {
				t.Fatalf("config after undoing %s = %q, want %q", order[0], got, want)
			}
			storedUndoRecord(t, order[1])
			wantUndoResult(t, UndoHardening(order[1]), order[1], "undone", "")
			if got := fileText(t, path); got != original {
				t.Fatalf("config after both undos = %q, want %q", got, original)
			}
		})
	}
	const sysctlHeader = "# Managed by CSM: sysctl values applied from the hardening page.\n"
	for _, order := range [][2]string{{"os_sysctl_rp_filter", "os_sysctl_aslr"}, {"os_sysctl_aslr", "os_sysctl_rp_filter"}} {
		t.Run("sysctl/"+order[0]+" first", func(t *testing.T) {
			withHardeningUndoDir(t)
			conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2", "kernel.randomize_va_space": "1"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}, {Name: "os_sysctl_aslr", Category: "os"}}))
			wantUndoResult(t, UndoHardening(order[0]), order[0], "undone", "")
			want := map[string][3]string{
				"os_sysctl_rp_filter": {sysctlHeader + "kernel.randomize_va_space = 2\n", "2", "2"},
				"os_sysctl_aslr":      {sysctlHeader + "net.ipv4.conf.all.rp_filter = 1\n", "1", "1"},
			}[order[0]]
			got := [3]string{fileText(t, conf), runtimeValue(t, "net.ipv4.conf.all.rp_filter"), runtimeValue(t, "kernel.randomize_va_space")}
			if got != want {
				t.Fatalf("drop-in, rp_filter, randomize_va_space after undoing %s = %q, want %q", order[0], got, want)
			}
			wantUndoResult(t, UndoHardening(order[1]), order[1], "undone", "")
			got = [3]string{fileText(t, conf), runtimeValue(t, "net.ipv4.conf.all.rp_filter"), runtimeValue(t, "kernel.randomize_va_space")}
			if want := [3]string{"<absent>", "2", "1"}; got != want {
				t.Fatalf("after both undos = %q, want %q", got, want)
			}
		})
	}
	const phpHeader = "; Managed by CSM: PHP settings applied from the hardening page.\n"
	for _, order := range [][2]string{{"php_expose_82", "php_enable_dl_82"}, {"php_enable_dl_82", "php_expose_82"}} {
		t.Run("php/"+order[0]+" first", func(t *testing.T) {
			withHardeningUndoDir(t)
			withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli", "fpm")
			installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
			withPHPInstalls(t, installs)
			applyOK(t, applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}, {Name: "php_enable_dl_82", Category: "php"}}, installs))
			wantUndoResult(t, UndoHardening(order[0]), order[0], "undone", "")
			want := map[string]string{
				"php_expose_82":    phpHeader + "enable_dl = Off\n",
				"php_enable_dl_82": phpHeader + "expose_php = Off\n",
			}[order[0]]
			for _, sapi := range []string{"cli", "fpm"} {
				if got := fileText(t, filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName)); got != want {
					t.Fatalf("%s drop-in after undoing %s = %q, want %q", sapi, order[0], got, want)
				}
			}
			wantUndoResult(t, UndoHardening(order[1]), order[1], "undone", "")
			for _, sapi := range []string{"cli", "fpm"} {
				if got := fileText(t, filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName)); got != "<absent>" {
					t.Fatalf("%s drop-in after both undos = %q", sapi, got)
				}
			}
		})
	}
}

// The kernel took the value but the drop-in write failed: undo restores the
// runtime value and leaves the drop-in alone.
func TestHardeningUndoPartialSysctl(t *testing.T) {
	withHardeningUndoDir(t)
	conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
	if err := os.Mkdir(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, &mockCmd{run: kernelSysctl})
	if out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}); out[0].Status != "failed" {
		t.Fatalf("apply = %+v", out)
	}
	wantUndoResult(t, UndoHardening("os_sysctl_rp_filter"), "os_sysctl_rp_filter", "undone", "")
	if got := runtimeValue(t, "net.ipv4.conf.all.rp_filter"); got != "2" {
		t.Fatalf("runtime = %q, want 2", got)
	}
	if info, err := os.Lstat(conf); err != nil || !info.IsDir() {
		t.Fatalf("drop-in path touched: %v, %v", info, err)
	}
	wantNoUndoRecord(t, "os_sysctl_rp_filter")
}

// A runtime failure must leave the applied drop-in and record available
// for a retry, including when undo had removed the last managed setting.
func TestHardeningUndoSysctlRuntimeFailure(t *testing.T) {
	withHardeningUndoDir(t)
	conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
	withMockCmd(t, &mockCmd{run: kernelSysctl})
	applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
	rec := storedUndoRecord(t, "os_sysctl_rp_filter")
	applied := fileText(t, conf)
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) {
		return []byte("sysctl: permission denied on key"), errors.New("exit status 255")
	}})
	wantUndoResult(t, UndoHardening("os_sysctl_rp_filter"), "os_sysctl_rp_filter", "failed", "permission denied")
	if got := fileText(t, conf); got != applied {
		t.Errorf("drop-in = %q, want applied state %q", got, applied)
	}
	if got := runtimeValue(t, "net.ipv4.conf.all.rp_filter"); got != "1" {
		t.Errorf("runtime = %q, want the applied 1", got)
	}
	if got := storedUndoRecord(t, "os_sysctl_rp_filter"); !reflect.DeepEqual(got, rec) {
		t.Errorf("record = %+v, want it kept as %+v", got, rec)
	}
	withMockCmd(t, &mockCmd{run: kernelSysctl})
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "undone", "")
	if got := runtimeValue(t, rec.Sysctl.Key); got != "2" {
		t.Fatalf("runtime after retry = %q", got)
	}
	wantNoUndoRecord(t, rec.Name)
}

// The apply wrote some drop-ins before one failed: undo restores those and
// touches no other.
func TestHardeningUndoPartialPHP(t *testing.T) {
	withHardeningUndoDir(t)
	calls := withPHPRestartLogged(t)
	ver, _ := debianPHPTree(t, "cli", "fpm", "apache2")
	ini := func(sapi string) string { return filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName) }
	if err := os.Mkdir(ini("fpm"), 0o700); err != nil {
		t.Fatal(err)
	}
	installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
	withPHPInstalls(t, installs)
	if out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, installs); out[0].Status != "failed" {
		t.Fatalf("apply = %+v", out)
	}
	if got := fileText(t, ini("apache2")); !strings.Contains(got, "expose_php = Off") {
		t.Fatalf("apache2 drop-in after the partial apply = %q", got)
	}
	*calls = nil
	wantUndoResult(t, UndoHardening("php_expose_82"), "php_expose_82", "undone", "")
	if got := fileText(t, ini("apache2")); got != "<absent>" {
		t.Errorf("apache2 drop-in = %q, want it removed", got)
	}
	if got := fileText(t, ini("cli")); got != "<absent>" {
		t.Errorf("cli drop-in = %q, want none", got)
	}
	if info, err := os.Lstat(ini("fpm")); err != nil || !info.IsDir() {
		t.Errorf("fpm drop-in path touched: %v, %v", info, err)
	}
	if !slices.Contains(*calls, "systemctl try-reload-or-restart apache2.service") {
		t.Errorf("calls = %q, want Apache reloaded", *calls)
	}
	wantNoUndoRecord(t, "php_expose_82")
}

func TestHardeningUndoSSHDCheckFailureRestores(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
	recordCommands(t)
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
	applied := fileText(t, path)
	rec := storedUndoRecord(t, "ssh_max_auth_tries")
	reloaded := false
	withMockCmd(t, &mockCmd{run: func(name string, _ ...string) ([]byte, error) {
		if name == "systemctl" {
			reloaded = true
			return nil, nil
		}
		return []byte("bad configuration option"), errors.New("exit status 255")
	}})
	wantUndoResult(t, UndoHardening("ssh_max_auth_tries"), "ssh_max_auth_tries", "failed", "sshd -t rejected")
	if got := fileText(t, path); got != applied {
		t.Fatalf("config = %q, want it restored to %q", got, applied)
	}
	if reloaded {
		t.Error("sshd reloaded after a failed check")
	}
	if got := storedUndoRecord(t, "ssh_max_auth_tries"); !reflect.DeepEqual(got, rec) {
		t.Fatalf("record = %+v, want it kept as %+v", got, rec)
	}
}

// A failed reload keeps the checked, restored file, as on apply: undo is
// done, says to reload sshd by hand, and the record goes. On a host where
// the reload always fails, undo works wherever apply works.
func TestHardeningUndoSSHReloadFailure(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
	recordCommands(t)
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
	withMockCmd(t, &mockCmd{run: func(name string, _ ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("Unit not found."), errors.New("exit status 5")
		}
		return nil, nil
	}})
	res := UndoHardening("ssh_max_auth_tries")
	wantUndoResult(t, res, "ssh_max_auth_tries", "undone", ", but reloading sshd failed (")
	if !strings.HasSuffix(res.Message, "; reload it manually.") {
		t.Errorf("message = %q, want the apply's manual reload note", res.Message)
	}
	if got := fileText(t, path); got != "MaxAuthTries 6\n" {
		t.Fatalf("config = %q, want the restored file", got)
	}
	wantNoUndoRecord(t, "ssh_max_auth_tries")
}

func TestHardeningUndoNoRecord(t *testing.T) {
	for _, tc := range []struct{ name, message string }{
		{"ssh_max_auth_tries", "no undo record"},
		{"os_sysctl_rp_filter", "no undo record"},
		{"cp_max_emails_hour", "no undo record"},
		{"php_expose_82", "no undo record"},
		{"os_shadow_permissions", "no undo record"},
		{"cp_compilers", "no undo record"},
		{"cp_updates", "no undo record"},
		{"ssh_port", "Unknown hardening fix"},
		{"../cp_updates", "Unknown hardening fix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := withHardeningUndoDir(t)
			path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
			calls := recordCommands(t)
			wantUndoResult(t, UndoHardening(tc.name), tc.name, "refused", tc.message)
			if got := fileText(t, path); got != "MaxAuthTries 6\n" {
				t.Errorf("config = %q", got)
			}
			if len(*calls) != 0 {
				t.Errorf("commands run: %q", *calls)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("record directory touched: %v", err)
			}
		})
	}
}

// A failed PHP reload keeps the restored drop-ins, as on apply: undo is done
// and names what to restart by hand, in the apply's words.
func TestHardeningUndoPHPReloadFailure(t *testing.T) {
	for failingUnit, note := range map[string]string{
		"php*-fpm.service": "Restart PHP-FPM manually (systemctl: reload failed).",
		"apache2.service":  "Reload Apache manually (systemctl: reload failed).",
	} {
		t.Run(failingUnit, func(t *testing.T) {
			withHardeningUndoDir(t)
			withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli", "fpm", "apache2")
			installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
			withPHPInstalls(t, installs)
			applyOK(t, applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}, {Name: "php_enable_dl_82", Category: "php"}}, installs))
			rec := storedUndoRecord(t, "php_expose_82")
			withMockCmd(t, &mockCmd{run: func(_ string, args ...string) ([]byte, error) {
				if slices.Contains(args, failingUnit) {
					return nil, errors.New("reload failed")
				}
				return nil, nil
			}})
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "undone", note)
			for _, p := range rec.PHP {
				if got, want := fileText(t, p.Path), phpDropInHeader+"\nenable_dl = Off\n"; got != want {
					t.Errorf("%s = %q, want the restored %q", p.Path, got, want)
				}
			}
			wantNoUndoRecord(t, rec.Name)
			storedUndoRecord(t, "php_enable_dl_82")
		})
	}
}

func TestHardeningUndoRefusesChangedSSHBlockStructure(t *testing.T) {
	for name, replacement := range map[string]string{
		"scoped":       "Match User backup\n" + sshdBlockBegin,
		"nested":       sshdBlockBegin + "\n" + sshdBlockBegin,
		"match inside": sshdBlockBegin + "\nMatch User backup",
		"second block": sshdBlockBegin + "\n" + sshdBlockEnd + "\n" + sshdBlockBegin,
	} {
		t.Run(name, func(t *testing.T) {
			withHardeningUndoDir(t)
			path := withTempSSHDConfig(t, "Port 2222\n")
			calls := recordCommands(t)
			applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
			editFile(t, path, sshdBlockBegin, replacement)
			before := fileText(t, path)
			*calls = nil
			wantUndoResult(t, UndoHardening("ssh_max_auth_tries"), "ssh_max_auth_tries", "refused", "changed since")
			if got := fileText(t, path); got != before || len(*calls) != 0 {
				t.Fatalf("changed block touched: %q, commands %q", got, *calls)
			}
			storedUndoRecord(t, "ssh_max_auth_tries")
		})
	}
}

func TestHardeningUndoPHPWriteFailureIsRetryable(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprint("after write=", afterWrite), func(t *testing.T) {
			withHardeningUndoDir(t)
			withPHPRestartLogged(t)
			ver, _ := debianPHPTree(t, "cli", "fpm")
			installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
			withPHPInstalls(t, installs)
			applyOK(t, applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, installs))
			rec := storedUndoRecord(t, "php_expose_82")
			before := map[string]string{}
			for _, p := range rec.PHP {
				if err := os.Chmod(p.Path, 0o600); err != nil {
					t.Fatal(err)
				}
				before[p.Path] = fileText(t, p.Path)
			}
			old := hardeningUndoWriteDropIn
			t.Cleanup(func() { hardeningUndoWriteDropIn = old })
			calls := 0
			hardeningUndoWriteDropIn = func(path, header string, lines []string) error {
				calls++
				if calls == 2 {
					if afterWrite {
						if err := old(path, header, lines); err != nil {
							t.Fatal(err)
						}
					}
					return errors.New("injected write failure")
				}
				return old(path, header, lines)
			}
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "failed", "injected write failure")
			for path, want := range before {
				if info, err := os.Stat(path); err == nil && info.Mode().Perm() != 0o600 {
					t.Errorf("%s mode = %04o, want 0600", path, info.Mode().Perm())
				}
				if got := fileText(t, path); got != want {
					t.Errorf("%s = %q, want applied state %q", path, got, want)
				}
			}
			if got := storedUndoRecord(t, rec.Name); !reflect.DeepEqual(got, rec) {
				t.Fatalf("record changed: %+v", got)
			}
			hardeningUndoWriteDropIn = old
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "undone", "")
			for path := range before {
				if got := fileText(t, path); got != "<absent>" {
					t.Errorf("%s after retry = %q", path, got)
				}
			}
			wantNoUndoRecord(t, rec.Name)
		})
	}
}

func TestHardeningUndoSysctlRefusesSymlink(t *testing.T) {
	withHardeningUndoDir(t)
	conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
	withMockCmd(t, &mockCmd{run: kernelSysctl})
	applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
	target := conf + ".original"
	if err := os.Rename(conf, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, conf); err != nil {
		t.Fatal(err)
	}
	before := fileText(t, target)
	wantUndoResult(t, UndoHardening("os_sysctl_rp_filter"), "os_sysctl_rp_filter", "failed", "")
	if got, err := os.Readlink(conf); err != nil || got != target {
		t.Fatalf("symlink changed: %q, %v", got, err)
	}
	if got := fileText(t, target); got != before {
		t.Fatalf("target changed: %q", got)
	}
	if got := runtimeValue(t, "net.ipv4.conf.all.rp_filter"); got != "1" {
		t.Fatalf("runtime changed: %q", got)
	}
	storedUndoRecord(t, "os_sysctl_rp_filter")
}

func TestHardeningUndoSysctlLateCommandFailureIsRetryable(t *testing.T) {
	for _, runtimeOnly := range []bool{false, true} {
		t.Run(fmt.Sprint("runtime only=", runtimeOnly), func(t *testing.T) {
			withHardeningUndoDir(t)
			conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			applyOK(t, applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}))
			rec := storedUndoRecord(t, "os_sysctl_rp_filter")
			rec.Sysctl.RuntimeOnly = runtimeOnly
			if err := writeHardeningUndo(rec); err != nil {
				t.Fatal(err)
			}
			before := fileText(t, conf)
			withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
				out, err := kernelSysctl(name, args...)
				if err == nil && slices.Contains(args, "net.ipv4.conf.all.rp_filter=2") {
					return out, errors.New("command failed after write")
				}
				return out, err
			}})
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "failed", "command failed after write")
			if got := runtimeValue(t, rec.Sysctl.Key); got != "1" {
				t.Errorf("runtime after failure = %q, want applied 1", got)
			}
			if got := fileText(t, conf); got != before {
				t.Errorf("drop-in after failure = %q, want %q", got, before)
			}
			storedUndoRecord(t, rec.Name)
			withMockCmd(t, &mockCmd{run: kernelSysctl})
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "undone", "")
			if got := runtimeValue(t, rec.Sysctl.Key); got != "2" {
				t.Errorf("runtime after retry = %q, want 2", got)
			}
			wantNoUndoRecord(t, rec.Name)
		})
	}
}

func TestHardeningUndoModeFailureRestoresOwner(t *testing.T) {
	withHardeningUndoDir(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	uid, gid := fileOwner(t, dir)
	oldDirs, oldChown, oldChmod := hardeningTmpDirs, hardeningUndoChown, hardeningUndoChmod
	t.Cleanup(func() {
		hardeningTmpDirs, hardeningUndoChown, hardeningUndoChmod = oldDirs, oldChown, oldChmod
	})
	hardeningTmpDirs = map[string]string{"os_tmp_permissions": dir}
	rec := HardeningUndoRecord{Name: "os_tmp_permissions", Kind: "mode", Mode: &modeUndoState{
		Path: dir, UID: uid + 1, GID: gid + 1, Mode: 0o755,
		AppliedUID: uid, AppliedGID: gid, AppliedMode: 0o1777,
	}}
	if err := writeHardeningUndo(rec); err != nil {
		t.Fatal(err)
	}
	// Model ownership without requiring root in the test runner.
	owner, group := int(uid), int(gid)
	hardeningUndoChown = func(_ *os.File, u, g int) error {
		owner, group = u, g
		return nil
	}
	fail := true
	hardeningUndoChmod = func(f *os.File, mode uint32) error {
		if fail {
			fail = false
			return errors.New("chmod failed")
		}
		return oldChmod(f, mode)
	}
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "failed", "chmod failed")
	if owner != int(uid) || group != int(gid) {
		t.Fatalf("owner after failure = %d:%d, want %d:%d", owner, group, uid, gid)
	}
	if got := fileModeOwner(t, dir); got != fmt.Sprintf("1777 %d:%d", uid, gid) {
		t.Fatalf("mode after failure = %s", got)
	}
	storedUndoRecord(t, rec.Name)
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "undone", "")
	if owner != int(uid+1) || group != int(gid+1) {
		t.Fatalf("owner after retry = %d:%d", owner, group)
	}
	if got := fileModeOwner(t, dir); got != fmt.Sprintf("0755 %d:%d", uid, gid) {
		t.Fatalf("mode after retry = %s", got)
	}
	wantNoUndoRecord(t, rec.Name)
}

func TestHardeningUndoLateConfigWriteFailureIsRetryable(t *testing.T) {
	for _, name := range []string{"ssh_max_auth_tries", "cp_updates"} {
		t.Run(name, func(t *testing.T) {
			withHardeningUndoDir(t)
			calls := recordCommands(t)
			var path string
			if name == "cp_updates" {
				path = withTempCPUpdateConf(t)
				if err := os.WriteFile(path, []byte("UPDATES=manual\n"), 0o640); err != nil {
					t.Fatal(err)
				}
				applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: name, Category: "cpanel"})})
			} else {
				path = withTempSSHDConfig(t, "MaxAuthTries 6\n")
				applyOK(t, applySSHFixes([]store.AuditResult{{Name: name, Category: "ssh"}}))
			}
			rec := storedUndoRecord(t, name)
			before := fileText(t, path)
			*calls = nil
			old := hardeningConfigWrite
			t.Cleanup(func() { hardeningConfigWrite = old })
			hardeningConfigWrite = func(path string, perm os.FileMode, data []byte) error {
				if err := old(path, perm, data); err != nil {
					return err
				}
				return errors.New("directory sync failed after rename")
			}
			wantUndoResult(t, UndoHardening(name), name, "failed", "directory sync failed")
			if got := fileText(t, path); got != before {
				t.Errorf("configuration after failure = %q, want applied %q", got, before)
			}
			if len(*calls) != 0 {
				t.Errorf("commands after failed write = %q", *calls)
			}
			if got := storedUndoRecord(t, name); !reflect.DeepEqual(got, rec) {
				t.Fatalf("record changed: %+v", got)
			}
			hardeningConfigWrite = old
			wantUndoResult(t, UndoHardening(name), name, "undone", "")
			wantNoUndoRecord(t, name)
		})
	}
}

func TestHardeningUndoTweakLateFailureIsRetryable(t *testing.T) {
	withHardeningUndoDir(t)
	previous := "0"
	whm := withFakeWHMTweak(t, "skipboxtrapper", &previous)
	applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_boxtrapper", Category: "cpanel"})})
	rec := storedUndoRecord(t, "cp_boxtrapper")
	withMockCmd(t, &mockCmd{runContextStdout: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := whm.run(ctx, name, args...)
		if slices.Contains(args, "value=0") {
			return nil, errors.New("reply lost after setting tweak")
		}
		return out, err
	}})
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "failed", "reply lost")
	if *whm.value != rec.Tweak.Applied {
		t.Errorf("value after failure = %s, want %s", *whm.value, rec.Tweak.Applied)
	}
	storedUndoRecord(t, rec.Name)
	withMockCmd(t, &mockCmd{runContextStdout: whm.run})
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "undone", "")
	if *whm.value != previous {
		t.Errorf("value after retry = %s, want %s", *whm.value, previous)
	}
	wantNoUndoRecord(t, rec.Name)
}

func TestHardeningUndoCompilerScriptFailureIsRetryable(t *testing.T) {
	withHardeningUndoDir(t)
	dir := t.TempDir()
	cc, script := filepath.Join(dir, "cc"), filepath.Join(dir, "compilers")
	for _, path := range []string{cc, script} {
		if err := os.WriteFile(path, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	withCompilerPaths(t, cc, script)
	compilersScript(t, cc)
	applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"})})
	fail := true
	withMockCmd(t, &mockCmd{run: func(_ string, args ...string) ([]byte, error) {
		mode := os.FileMode(0o750)
		if args[0] == "on" {
			mode = 0o755
		}
		if err := os.Chmod(cc, mode); err != nil {
			return nil, err
		}
		if args[0] == "on" && fail {
			fail = false
			return nil, errors.New("script failed after opening access")
		}
		return nil, nil
	}})
	wantUndoResult(t, UndoHardening("cp_compilers"), "cp_compilers", "failed", "script failed")
	info, err := os.Stat(cc)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("compiler after failure: %v, %v", info, err)
	}
	storedUndoRecord(t, "cp_compilers")
	wantUndoResult(t, UndoHardening("cp_compilers"), "cp_compilers", "undone", "")
	info, err = os.Stat(cc)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("compiler after retry: %v, %v", info, err)
	}
	wantNoUndoRecord(t, "cp_compilers")
}
