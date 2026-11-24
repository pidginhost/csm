package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// wantUndoRecord fails unless the stored record for want.Name equals want,
// apart from AppliedAt, which must fall between since and now.
func wantUndoRecord(t *testing.T, since time.Time, want HardeningUndoRecord) {
	t.Helper()
	got, ok, err := readHardeningUndo(want.Name)
	if err != nil || !ok {
		t.Fatalf("record %s: ok=%v err=%v", want.Name, ok, err)
	}
	if got.AppliedAt.Before(since) || got.AppliedAt.After(time.Now()) {
		t.Errorf("record %s applied at %v, outside the apply", want.Name, got.AppliedAt)
	}
	got.AppliedAt = time.Time{}
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		t.Errorf("record %s =\n%s\nwant\n%s", want.Name, g, w)
	}
}

func wantNoUndoRecord(t *testing.T, name string) {
	t.Helper()
	if rec, ok, err := readHardeningUndo(name); ok || err != nil {
		t.Errorf("record %s = %+v, %v, %v; want none", name, rec, ok, err)
	}
}

func fileOwner(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

// withTempSysctl points the drop-in at a fresh sysctl.d, holding content
// unless it is empty, and the runtime values at a /proc/sys tree.
func withTempSysctl(t *testing.T, content string, runtime map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sysctl.d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "99-zz-csm-hardening.conf")
	if content != "" {
		if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	procSys := t.TempDir()
	for key, value := range runtime {
		path := filepath.Join(procSys, strings.ReplaceAll(key, ".", "/"))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldConf, oldProcSys := hardeningSysctlConfPath, hardeningProcSys
	hardeningSysctlConfPath, hardeningProcSys = conf, procSys
	t.Cleanup(func() { hardeningSysctlConfPath, hardeningProcSys = oldConf, oldProcSys })
	return conf
}

// kernelSysctl stands in for sysctl -w: it writes the value into the
// /proc/sys tree, so reading it after the change would see the new value.
func kernelSysctl(_ string, args ...string) ([]byte, error) {
	key, value, _ := strings.Cut(args[len(args)-1], "=")
	path := filepath.Join(hardeningProcSys, strings.ReplaceAll(key, ".", "/"))
	return nil, os.WriteFile(path, []byte(value+"\n"), 0o644)
}

func withTempCPUpdateConf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cpupdate.conf")
	old := hardeningCPUpdateConf
	hardeningCPUpdateConf = path
	t.Cleanup(func() { hardeningCPUpdateConf = old })
	return path
}

func withCompilerPaths(t *testing.T, compiler, script string) {
	t.Helper()
	oldCompiler, oldScript := hardeningCompilerPath, hardeningCompilersScript
	hardeningCompilerPath, hardeningCompilersScript = compiler, script
	t.Cleanup(func() { hardeningCompilerPath, hardeningCompilersScript = oldCompiler, oldScript })
}

func withPHPReloadStubbed(t *testing.T) {
	t.Helper()
	old := hardeningPHPFPMRestart
	hardeningPHPFPMRestart = filepath.Join(t.TempDir(), "missing-restart-script")
	t.Cleanup(func() { hardeningPHPFPMRestart = old })
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
}

// Applying a fix writes its undo record, so the package's tests must never
// reach the real store.
func TestHardeningUndoTestsUseTempStore(t *testing.T) {
	if !strings.HasPrefix(hardeningUndoDir, filepath.Clean(os.TempDir())+string(filepath.Separator)) {
		t.Fatalf("tests write undo records to %s", hardeningUndoDir)
	}
}

func TestHardeningUndoCaptureSSH(t *testing.T) {
	withHardeningUndoDir(t)
	withTempSSHDConfig(t, strings.Join([]string{
		sshdBlockBegin, "UseDNS no", sshdBlockEnd,
		"Port 2222",
		"MaxAuthTries 6",
		"  X11Forwarding yes",
		"UseDNS yes",
		"Match User backup",
		"    MaxAuthTries 10",
		"",
	}, "\n"))
	withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
	since := time.Now()
	for _, res := range applySSHFixes([]store.AuditResult{
		{Name: "ssh_max_auth_tries", Category: "ssh"},
		{Name: "ssh_x11_forwarding", Category: "ssh"},
	}) {
		if res.Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
	}
	// Each record holds only its own keyword; Match sections stay untouched.
	wantUndoRecord(t, since, HardeningUndoRecord{Name: "ssh_max_auth_tries", Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
		Keyword: "MaxAuthTries", AppliedValue: "4", DisabledLines: []string{"MaxAuthTries 6"},
	}})
	wantUndoRecord(t, since, HardeningUndoRecord{Name: "ssh_x11_forwarding", Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
		Keyword: "X11Forwarding", AppliedValue: "no", DisabledLines: []string{"  X11Forwarding yes"},
	}})
	// UseDNS was in the block before, and its fix was not part of this apply.
	wantNoUndoRecord(t, "ssh_use_dns")
}

func TestHardeningUndoCaptureSSHBlockSyntax(t *testing.T) {
	for _, setting := range []string{
		"MaxAuthTries=6",
		"MaxAuthTries =6",
		"MaxAuthTries = 6",
		"MaxAuthTries 6\nMaxAuthTries 7",
	} {
		t.Run(setting, func(t *testing.T) {
			withHardeningUndoDir(t)
			path := withTempSSHDConfig(t, strings.Join([]string{
				sshdBlockBegin, setting, "UseDNS no", sshdBlockEnd, "Port 2222", "",
			}, "\n"))
			withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
			since := time.Now()
			out := applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}})
			if len(out) != 1 || out[0].Status != "applied" || strings.Contains(out[0].Message, " Undo is unavailable") {
				t.Fatalf("results = %+v", out)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: "ssh_max_auth_tries", Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
				Keyword: "MaxAuthTries", PrevValue: "6", HadValue: true, AppliedValue: "4",
			}})
			wantNoUndoRecord(t, "ssh_use_dns")
			want := strings.Join([]string{sshdBlockBegin, "MaxAuthTries 4", "UseDNS no", sshdBlockEnd, "Port 2222", ""}, "\n")
			if data, err := os.ReadFile(path); err != nil || string(data) != want {
				t.Fatalf("applied config = %q, %v; want %q", data, err, want)
			}
		})
	}
}

func TestHardeningUndoCaptureSysctl(t *testing.T) {
	t.Run("saved", func(t *testing.T) {
		withHardeningUndoDir(t)
		withTempSysctl(t, "# Managed by CSM\nnet.ipv4.conf.all.rp_filter=2\nfs.protected_hardlinks = 1\n net.ipv4.conf.all.rp_filter = 0 \n",
			map[string]string{"net.ipv4.conf.all.rp_filter": "2", "kernel.randomize_va_space": "1", "fs.protected_symlinks": "0"})
		withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
			if strings.Contains(strings.Join(args, " "), "protected_symlinks") {
				return []byte("sysctl: permission denied on key"), errors.New("exit status 255")
			}
			return kernelSysctl(name, args...)
		}})
		since := time.Now()
		statuses := map[string]string{}
		for _, res := range applySysctlFixes([]store.AuditResult{
			{Name: "os_sysctl_rp_filter", Category: "os"},
			{Name: "os_sysctl_aslr", Category: "os"},
			{Name: "os_sysctl_symlinks", Category: "os"},
		}) {
			statuses[res.Name] = res.Status
		}
		if statuses["os_sysctl_rp_filter"] != "applied" || statuses["os_sysctl_aslr"] != "applied" || statuses["os_sysctl_symlinks"] != "failed" {
			t.Fatalf("statuses = %v", statuses)
		}
		// The drop-in's lines for the key are kept exactly as they were.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_rp_filter", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "2",
			PrevLines:    []string{"net.ipv4.conf.all.rp_filter=2", " net.ipv4.conf.all.rp_filter = 0 "},
			AppliedValue: "1",
		}})
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_aslr", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "kernel.randomize_va_space", PrevRuntime: "1", AppliedValue: "2",
		}})
		// The kernel refused this key, so nothing changed.
		wantNoUndoRecord(t, "os_sysctl_symlinks")
	})
	t.Run("runtime only", func(t *testing.T) {
		withHardeningUndoDir(t)
		conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
		// A directory in the drop-in's place fails the save after the runtime change.
		if err := os.Mkdir(conf, 0o755); err != nil {
			t.Fatal(err)
		}
		withMockCmd(t, &mockCmd{run: kernelSysctl})
		since := time.Now()
		out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}})
		if len(out) != 1 || out[0].Status != "failed" || !strings.Contains(out[0].Message, "set at runtime but not persisted") {
			t.Fatalf("results = %+v", out)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_rp_filter", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "2", AppliedValue: "1", RuntimeOnly: true,
		}})
	})
}

func TestHardeningUndoSysctlRecordsBeforeNextCommand(t *testing.T) {
	withHardeningUndoDir(t)
	withTempSysctl(t, "", map[string]string{"kernel.randomize_va_space": "1", "fs.protected_symlinks": "0"})
	since := time.Now()
	var calls int
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
		calls++
		if calls == 2 {
			// The next command can stall until the worker is killed. The
			// completed runtime change must already have a usable record.
			wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_aslr", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
				Key: "kernel.randomize_va_space", PrevRuntime: "1", AppliedValue: "2", RuntimeOnly: true,
			}})
			return nil, errors.New("kernel refused the next key")
		}
		return kernelSysctl(name, args...)
	}})
	out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_aslr", Category: "os"}, {Name: "os_sysctl_symlinks", Category: "os"}})
	if calls != 2 || len(out) != 2 || out[0].Status != "failed" || out[1].Status != "applied" {
		t.Fatalf("calls = %d, results = %+v", calls, out)
	}
	wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_aslr", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
		Key: "kernel.randomize_va_space", PrevRuntime: "1", AppliedValue: "2",
	}})
	wantNoUndoRecord(t, "os_sysctl_symlinks")
}

func TestHardeningUndoPHPRecordsBeforeNextDirectory(t *testing.T) {
	dir := withHardeningUndoDir(t)
	withPHPReloadStubbed(t)
	ver, _ := debianPHPTree(t, "cli", "fpm")
	cli := filepath.Join(ver, "cli", "conf.d")
	cliIni := filepath.Join(cli, hardeningPHPIniName)
	oldSync := hardeningUndoSync
	t.Cleanup(func() { hardeningUndoSync = oldSync })
	recordWrites := 0
	hardeningUndoSync = func(f *os.File) error {
		if filepath.Dir(f.Name()) == dir && strings.HasSuffix(f.Name(), ".tmp") {
			recordWrites++
			if recordWrites == 1 {
				if _, err := os.Stat(cliIni); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("next drop-in touched before recording the completed write: %v", err)
				}
			}
		}
		return f.Sync()
	}
	since := time.Now()
	out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, []phpInstall{{shortID: "82", scanDir: cli}})
	if len(out) != 1 || out[0].Status != "applied" || recordWrites != 2 {
		t.Fatalf("results = %+v, record writes = %d", out, recordWrites)
	}
	wantUndoRecord(t, since, HardeningUndoRecord{Name: "php_expose_82", Category: "php", Kind: "php", PHP: []phpUndoState{
		{Path: filepath.Join(ver, "fpm", "conf.d", hardeningPHPIniName), Key: "expose_php", Applied: "Off"},
		{Path: cliIni, Key: "expose_php", Applied: "Off"},
	}})
}

func TestHardeningUndoBatchRecordFailureRemovesInterimRecord(t *testing.T) {
	for _, kind := range []string{"sysctl", "php"} {
		t.Run(kind, func(t *testing.T) {
			dir := withHardeningUndoDir(t)
			oldSync := hardeningUndoSync
			t.Cleanup(func() { hardeningUndoSync = oldSync })
			recordWrites := 0
			hardeningUndoSync = func(f *os.File) error {
				if filepath.Dir(f.Name()) == dir && strings.HasSuffix(f.Name(), ".tmp") {
					recordWrites++
					if recordWrites == 2 {
						return errors.New("record sync failed")
					}
				}
				return f.Sync()
			}
			var out []HardeningFixResult
			var appliedPath, wantContent string
			if kind == "sysctl" {
				appliedPath = withTempSysctl(t, "kernel.randomize_va_space=1\n", map[string]string{"kernel.randomize_va_space": "1"})
				wantContent = "kernel.randomize_va_space = 2\n"
				withMockCmd(t, &mockCmd{run: kernelSysctl})
				out = applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_aslr", Category: "os"}})
			} else {
				withPHPReloadStubbed(t)
				ver, _ := debianPHPTree(t, "cli", "fpm")
				cli := filepath.Join(ver, "cli", "conf.d")
				appliedPath = filepath.Join(cli, hardeningPHPIniName)
				wantContent = "; Managed by CSM: PHP settings applied from the hardening page.\nexpose_php = Off\n"
				out = applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, []phpInstall{{shortID: "82", scanDir: cli}})
			}
			if recordWrites != 2 || len(out) != 1 || out[0].Status != "applied" || !strings.Contains(out[0].Message, " Undo is unavailable") {
				t.Fatalf("record writes = %d, results = %+v", recordWrites, out)
			}
			wantNoUndoRecord(t, out[0].Name)
			if data, err := os.ReadFile(appliedPath); err != nil || string(data) != wantContent {
				t.Fatalf("applied content = %q, %v; want %q", data, err, wantContent)
			}
		})
	}
}

func TestHardeningUndoCaptureTweak(t *testing.T) {
	kv := cpTweakFixes["cp_max_emails_hour"]
	for _, tc := range []struct {
		name, reply string
		want        tweakUndoState
		// whmapi1 cannot clear a value, so the result says undo needs WHM.
		whmNote bool
	}{
		{"set", `{"data":{"tweaksetting":{"key":"maxemailsperhour","value":"0"}},"metadata":{"result":1,"reason":"OK"}}`,
			tweakUndoState{Key: kv.key, Previous: "0", HadValue: true, Applied: kv.value}, false},
		// cPanel leaves the value out for a tweak that has none.
		{"unset", `{"data":{"tweaksetting":{"key":"maxemailsperhour"}},"metadata":{"result":1,"reason":"OK"}}`,
			tweakUndoState{Key: kv.key, Applied: kv.value}, true},
		{"empty", `{"data":{"tweaksetting":{"key":"maxemailsperhour","value":""}},"metadata":{"result":1,"reason":"OK"}}`,
			tweakUndoState{Key: kv.key, HadValue: true, Applied: kv.value}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			var calls []string
			withMockCmd(t, &mockCmd{
				// whmapi1 can print warnings on stderr; only stdout is the reply.
				runContext: func(context.Context, string, ...string) ([]byte, error) {
					return []byte("Warning: locale not set\n"), nil
				},
				runContextStdout: func(_ context.Context, name string, args ...string) ([]byte, error) {
					calls = append(calls, name+" "+strings.Join(args, " "))
					if slices.Contains(args, "get_tweaksetting") {
						return []byte(tc.reply), nil
					}
					return []byte(`{"metadata":{"result":1,"reason":"OK"}}`), nil
				},
			})
			since := time.Now()
			res := applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"})
			if res.Status != "applied" || strings.Contains(res.Message, "Undo is unavailable") ||
				strings.Contains(res.Message, "Undo") != tc.whmNote || strings.Contains(res.Message, "WHM Tweak Settings") != tc.whmNote {
				t.Fatalf("result = %+v, want a WHM Tweak Settings note %v", res, tc.whmNote)
			}
			// The previous value is read before the change.
			want := []string{
				"whmapi1 --output=json get_tweaksetting key=maxemailsperhour",
				"whmapi1 --output=json set_tweaksetting key=maxemailsperhour value=" + kv.value,
			}
			if !slices.Equal(calls, want) {
				t.Fatalf("calls = %q, want %q", calls, want)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: "cp_max_emails_hour", Category: "cpanel", Kind: "tweak", Tweak: &tc.want})
		})
	}
}

// A reply that is not about the asked key, or not readable, must not pass
// for an unset tweak: undo would then remove a value that was there.
func TestHardeningUndoCaptureTweakRefusesOtherReplies(t *testing.T) {
	for _, reply := range []string{
		`not json`,
		`{"metadata":{"result":1}}`,
		`{"metadata":{"result":0,"reason":"Invalid tweaksetting key"}}`,
		`{"data":{"tweaksetting":{"key":"skipboxtrapper","value":"1"}},"metadata":{"result":1}}`,
		`{"data":{"tweaksetting":{"key":"maxemailsperhour","value":200}},"metadata":{"result":1}}`,
	} {
		withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return []byte(reply), nil }})
		if value, had, err := getWHMTweak("maxemailsperhour"); err == nil {
			t.Errorf("reply %s read as %q, %v", reply, value, had)
		}
	}
}

func TestHardeningUndoCapturePHP(t *testing.T) {
	const header = "; Managed by CSM: PHP settings applied from the hardening page.\n"
	t.Run("batch", func(t *testing.T) {
		withHardeningUndoDir(t)
		withPHPReloadStubbed(t)
		ver, _ := debianPHPTree(t, "cli", "fpm")
		cli := filepath.Join(ver, "cli", "conf.d")
		cliIni := filepath.Join(cli, hardeningPHPIniName)
		fpmIni := filepath.Join(ver, "fpm", "conf.d", hardeningPHPIniName)
		if err := os.WriteFile(fpmIni, []byte(header+"expose_php = On\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cliIni, []byte(header+"enable_dl = Off\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		for _, res := range applyPHPFixes([]store.AuditResult{
			{Name: "php_expose_82", Category: "php"},
			{Name: "php_enable_dl_82", Category: "php"},
		}, []phpInstall{{shortID: "82", scanDir: cli}}) {
			if res.Status != "applied" {
				t.Fatalf("result = %+v", res)
			}
		}
		// Each record holds only its own key, per drop-in, in write order.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "php_expose_82", Category: "php", Kind: "php", PHP: []phpUndoState{
			{Path: fpmIni, Key: "expose_php", PrevLine: "expose_php = On", HadKey: true, Applied: "Off"},
			{Path: cliIni, Key: "expose_php", Applied: "Off"},
		}})
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "php_enable_dl_82", Category: "php", Kind: "php", PHP: []phpUndoState{
			{Path: fpmIni, Key: "enable_dl", Applied: "Off"},
			{Path: cliIni, Key: "enable_dl", PrevLine: "enable_dl = Off", HadKey: true, Applied: "Off"},
		}})
	})
	t.Run("partial", func(t *testing.T) {
		withHardeningUndoDir(t)
		withPHPReloadStubbed(t)
		ver, _ := debianPHPTree(t, "cli", "fpm", "apache2")
		cli := filepath.Join(ver, "cli", "conf.d")
		if err := os.Mkdir(filepath.Join(ver, "fpm", "conf.d", hardeningPHPIniName), 0o700); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		out := applyPHPFixes([]store.AuditResult{{Name: "php_expose_82", Category: "php"}}, []phpInstall{{shortID: "82", scanDir: cli}})
		if len(out) != 1 || out[0].Status != "failed" {
			t.Fatalf("results = %+v", out)
		}
		// Only the drop-in written before the failure is recorded.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "php_expose_82", Category: "php", Kind: "php", PHP: []phpUndoState{
			{Path: filepath.Join(ver, "apache2", "conf.d", hardeningPHPIniName), Key: "expose_php", Applied: "Off"},
		}})
	})
}

func TestHardeningUndoCaptureMode(t *testing.T) {
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
		uid, gid := fileOwner(t, path)
		applied, err := shadowFixMode(gid, user.LookupGroup)
		if err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		res := applyHardeningSingle(store.AuditResult{Name: "os_shadow_permissions", Category: "os"})
		if res.Status != "applied" || res.Message != fmt.Sprintf("%s is now %04o.", path, applied) {
			t.Fatalf("result = %+v", res)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_shadow_permissions", Category: "os", Kind: "mode", Mode: &modeUndoState{
			Path: path, Mode: 0o644, UID: uid, GID: gid, AppliedMode: uint32(applied), AppliedUID: uid, AppliedGID: gid,
		}})
	})
	t.Run("previous state", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		uid, gid := fileOwner(t, dir)
		got, err := setModeByFD(dir, os.ModeSticky|0o777, false, true)
		if err != nil {
			t.Fatal(err)
		}
		want := modeUndoState{Path: dir, Mode: 0o755, UID: uid, GID: gid, AppliedMode: 0o1777, AppliedUID: uid, AppliedGID: gid}
		if got != want {
			t.Fatalf("state = %+v, want %+v", got, want)
		}
		if info, err := os.Stat(dir); err != nil || info.Mode()&(os.ModePerm|os.ModeSticky) != os.ModeSticky|0o777 {
			t.Fatalf("mode after = %v, %v", info, err)
		}
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
		uid, gid := fileOwner(t, dir)
		old := hardeningTmpDirs
		hardeningTmpDirs = map[string]string{"os_tmp_permissions": dir}
		t.Cleanup(func() { hardeningTmpDirs = old })
		since := time.Now()
		res := applyHardeningSingle(store.AuditResult{Name: "os_tmp_permissions", Category: "os"})
		if !root {
			// Only root can give the directory to root, and nothing else changed.
			if res.Status != "failed" {
				t.Fatalf("result = %+v", res)
			}
			wantNoUndoRecord(t, "os_tmp_permissions")
			return
		}
		if res.Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_tmp_permissions", Category: "os", Kind: "mode", Mode: &modeUndoState{
			Path: dir, Mode: 0o755, UID: uid, GID: gid, AppliedMode: 0o1777,
		}})
	})
}

func TestHardeningUndoCaptureCompilers(t *testing.T) {
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
		target, err := filepath.EvalSymlinks(cc)
		if err != nil {
			t.Fatal(err)
		}
		uid, gid := fileOwner(t, target)
		since := time.Now()
		if res := applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"}); res.Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "cp_compilers", Category: "cpanel", Kind: "compilers", Compilers: &compilersUndoState{
			Method: "chmod", Path: target, Mode: 0o755, UID: uid, GID: gid, AppliedMode: 0o750, AppliedUID: uid, AppliedGID: gid,
		}})
	})
	t.Run("script", func(t *testing.T) {
		withHardeningUndoDir(t)
		dir := t.TempDir()
		script := filepath.Join(dir, "compilers")
		if err := os.WriteFile(script, nil, 0o700); err != nil {
			t.Fatal(err)
		}
		withCompilerPaths(t, filepath.Join(dir, "cc"), script)
		var calls []string
		withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil, nil
		}})
		since := time.Now()
		if res := applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"}); res.Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		if !slices.Equal(calls, []string{script + " off"}) {
			t.Fatalf("calls = %q", calls)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "cp_compilers", Category: "cpanel", Kind: "compilers", Compilers: &compilersUndoState{
			Method: "script",
		}})
	})
}

func TestHardeningUndoCaptureFile(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempCPUpdateConf(t)
	// An absent file stays an apply error and records nothing.
	if res := applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"}); res.Status != "failed" {
		t.Fatalf("result for an absent file = %+v", res)
	}
	wantNoUndoRecord(t, "cp_updates")

	const before = "CPANEL=release\nUPDATES=manual\nRPMUP=daily\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	if res := applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"}); res.Status != "applied" {
		t.Fatalf("result = %+v", res)
	}
	wantUndoRecord(t, since, HardeningUndoRecord{Name: "cp_updates", Category: "cpanel", Kind: "file", File: &fileUndoState{
		Path: path, Previous: before, Applied: "CPANEL=release\nUPDATES=daily\nRPMUP=daily\n",
	}})
}

// Apply, change the setting back by hand, apply again: the record holds the
// state before the second apply.
func TestHardeningUndoNewestApplyWins(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		withHardeningUndoDir(t)
		path := withTempCPUpdateConf(t)
		r := store.AuditResult{Name: "cp_updates", Category: "cpanel"}
		for _, content := range []string{"UPDATES=manual\n", "UPDATES=never\n"} {
			if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
				t.Fatal(err)
			}
			since := time.Now()
			if res := applyHardeningSingle(r); res.Status != "applied" {
				t.Fatalf("result = %+v", res)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: r.Name, Category: r.Category, Kind: "file", File: &fileUndoState{
				Path: path, Previous: content, Applied: "UPDATES=daily\n",
			}})
		}
	})
	t.Run("ssh", func(t *testing.T) {
		withHardeningUndoDir(t)
		path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
		withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
		r := []store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}
		if res := applySSHFixes(r); res[0].Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(data), "\nMaxAuthTries 4\n", "\nMaxAuthTries 5\n", 1)
		if edited == string(data) {
			t.Fatalf("no CSM block value to edit in %q", data)
		}
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		if res := applySSHFixes(r); res[0].Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		// The block value set by hand is the state to restore. The global
		// line the first apply disabled is still disabled, so it stays in the
		// record.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "ssh_max_auth_tries", Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
			Keyword: "MaxAuthTries", PrevValue: "5", HadValue: true, AppliedValue: "4", DisabledLines: []string{"MaxAuthTries 6"},
		}})
	})
	t.Run("ssh block line removed", func(t *testing.T) {
		withHardeningUndoDir(t)
		path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
		withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
		r := []store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}
		if res := applySSHFixes(r); res[0].Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(data), "\nMaxAuthTries 4\n", "\n", 1)
		if edited == string(data) {
			t.Fatalf("no CSM block value to remove in %q", data)
		}
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		if res := applySSHFixes(r); res[0].Status != "applied" {
			t.Fatalf("result = %+v", res)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "ssh_max_auth_tries", Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
			Keyword: "MaxAuthTries", AppliedValue: "4", DisabledLines: []string{"MaxAuthTries 6"},
		}})
	})
}

// Applying a fix again, as a retry after a partial apply or over a setting
// that still holds what CSM set, must not record CSM's own earlier change as
// the state to restore. Settings changed by hand since take the state found
// now.
func TestHardeningUndoReapplyKeepsOriginalState(t *testing.T) {
	ok := func(string, ...string) ([]byte, error) { return nil, nil }
	t.Run("php retry after a partial apply", func(t *testing.T) {
		withHardeningUndoDir(t)
		withPHPReloadStubbed(t)
		ver, _ := debianPHPTree(t, "cli", "fpm", "apache2")
		ini := func(sapi string) string { return filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName) }
		r := []store.AuditResult{{Name: "php_expose_82", Category: "php"}}
		installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
		if err := os.Mkdir(ini("fpm"), 0o700); err != nil {
			t.Fatal(err)
		}
		if out := applyPHPFixes(r, installs); out[0].Status != "failed" {
			t.Fatalf("first apply = %+v", out)
		}
		// The operator clears the obstacle and applies the same fix again.
		if err := os.Remove(ini("fpm")); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		if out := applyPHPFixes(r, installs); out[0].Status != "applied" || strings.Contains(out[0].Message, "Undo is unavailable") {
			t.Fatalf("retry = %+v", out)
		}
		// apache2 already held the first attempt's Off.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "php_expose_82", Category: "php", Kind: "php", PHP: []phpUndoState{
			{Path: ini("apache2"), Key: "expose_php", Applied: "Off"},
			{Path: ini("fpm"), Key: "expose_php", Applied: "Off"},
			{Path: ini("cli"), Key: "expose_php", Applied: "Off"},
		}})
	})
	t.Run("php retry that stops sooner", func(t *testing.T) {
		withHardeningUndoDir(t)
		withPHPReloadStubbed(t)
		ver, _ := debianPHPTree(t, "cli", "fpm", "apache2")
		ini := func(sapi string) string { return filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName) }
		r := []store.AuditResult{{Name: "php_expose_82", Category: "php"}}
		installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
		if err := os.Mkdir(ini("cli"), 0o700); err != nil {
			t.Fatal(err)
		}
		if out := applyPHPFixes(r, installs); out[0].Status != "failed" {
			t.Fatalf("first apply = %+v", out)
		}
		// Now fpm is in the way instead, so the retry writes only apache2.
		for _, path := range []string{ini("cli"), ini("fpm")} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(ini("fpm"), 0o700); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		if out := applyPHPFixes(r, installs); out[0].Status != "failed" {
			t.Fatalf("retry = %+v", out)
		}
		// The first attempt's fpm change stays undoable.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "php_expose_82", Category: "php", Kind: "php", PHP: []phpUndoState{
			{Path: ini("apache2"), Key: "expose_php", Applied: "Off"},
			{Path: ini("fpm"), Key: "expose_php", Applied: "Off"},
		}})
	})
	t.Run("sysctl runtime changed by hand", func(t *testing.T) {
		withHardeningUndoDir(t)
		withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
		withMockCmd(t, &mockCmd{run: kernelSysctl})
		r := []store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}
		if out := applySysctlFixes(r); out[0].Status != "applied" {
			t.Fatalf("first apply = %+v", out)
		}
		if _, err := kernelSysctl("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		if out := applySysctlFixes(r); out[0].Status != "applied" {
			t.Fatalf("re-apply = %+v", out)
		}
		// The runtime value set by hand is restored; the drop-in line is still
		// CSM's own, so undo removes it as before.
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_rp_filter", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "0", AppliedValue: "1",
		}})
	})
	t.Run("sysctl record before the drop-in is saved", func(t *testing.T) {
		withHardeningUndoDir(t)
		withTempSysctl(t, "net.ipv4.conf.all.rp_filter = 2\n", map[string]string{"net.ipv4.conf.all.rp_filter": "2", "kernel.randomize_va_space": "1"})
		withMockCmd(t, &mockCmd{run: kernelSysctl})
		if out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}); out[0].Status != "applied" {
			t.Fatalf("first apply = %+v", out)
		}
		if _, err := kernelSysctl("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"); err != nil {
			t.Fatal(err)
		}
		// The drop-in still holds the first apply's line; this apply has only
		// changed the runtime value when the next command runs.
		want := HardeningUndoRecord{Name: "os_sysctl_rp_filter", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "0", PrevLines: []string{"net.ipv4.conf.all.rp_filter = 2"}, AppliedValue: "1",
		}}
		since := time.Now()
		checked := false
		withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
			if strings.Contains(strings.Join(args, " "), "randomize_va_space") {
				wantUndoRecord(t, since, want)
				checked = true
			}
			return kernelSysctl(name, args...)
		}})
		out := applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}, {Name: "os_sysctl_aslr", Category: "os"}})
		if !checked || out[0].Status != "applied" || out[1].Status != "applied" {
			t.Fatalf("checked = %v, results = %+v", checked, out)
		}
		wantUndoRecord(t, since, want)
	})
	t.Run("sysctl drop-in changed by hand", func(t *testing.T) {
		withHardeningUndoDir(t)
		conf := withTempSysctl(t, "net.ipv4.conf.all.rp_filter = 2\n", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
		withMockCmd(t, &mockCmd{run: kernelSysctl})
		r := []store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}
		if out := applySysctlFixes(r); out[0].Status != "applied" {
			t.Fatalf("first apply = %+v", out)
		}
		if err := os.WriteFile(conf, []byte("net.ipv4.conf.all.rp_filter = 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		if out := applySysctlFixes(r); out[0].Status != "applied" {
			t.Fatalf("re-apply = %+v", out)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "os_sysctl_rp_filter", Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "2", PrevLines: []string{"net.ipv4.conf.all.rp_filter = 0"}, AppliedValue: "1",
		}})
	})
	t.Run("ssh block still holds the applied value", func(t *testing.T) {
		withHardeningUndoDir(t)
		path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
		withMockCmd(t, &mockCmd{run: ok})
		r := []store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}
		if out := applySSHFixes(r); out[0].Status != "applied" {
			t.Fatalf("first apply = %+v", out)
		}
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
		since := time.Now()
		if out := applySSHFixes(r); out[0].Status != "applied" {
			t.Fatalf("re-apply = %+v", out)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: "ssh_max_auth_tries", Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
			Keyword: "MaxAuthTries", AppliedValue: "4", DisabledLines: []string{"MaxAuthTries 6", "MaxAuthTries 8"},
		}})
	})
	t.Run("tweak unchanged", func(t *testing.T) {
		withHardeningUndoDir(t)
		var value *string // the tweak starts unset
		withMockCmd(t, &mockCmd{run: func(_ string, args ...string) ([]byte, error) {
			if slices.Contains(args, "get_tweaksetting") {
				if value == nil {
					return []byte(`{"data":{"tweaksetting":{"key":"maxemailsperhour"}},"metadata":{"result":1}}`), nil
				}
				return []byte(`{"data":{"tweaksetting":{"key":"maxemailsperhour","value":"` + *value + `"}},"metadata":{"result":1}}`), nil
			}
			set := strings.TrimPrefix(args[len(args)-1], "value=")
			value = &set
			return []byte(`{"metadata":{"result":1}}`), nil
		}})
		r := store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"}
		for range 2 {
			since := time.Now()
			if res := applyHardeningSingle(r); res.Status != "applied" {
				t.Fatalf("result = %+v", res)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: r.Name, Category: r.Category, Kind: "tweak", Tweak: &tweakUndoState{
				Key: "maxemailsperhour", Applied: cpTweakFixes[r.Name].value,
			}})
		}
	})
	t.Run("mode", func(t *testing.T) {
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
		uid, gid := fileOwner(t, path)
		applied, err := shadowFixMode(gid, user.LookupGroup)
		if err != nil {
			t.Fatal(err)
		}
		r := store.AuditResult{Name: "os_shadow_permissions", Category: "os"}
		// Unchanged since the first apply, then changed by hand.
		for _, step := range []struct {
			chmod os.FileMode
			want  uint32
		}{{0, 0o644}, {0, 0o644}, {0o604, 0o604}} {
			if step.chmod != 0 {
				if err := os.Chmod(path, step.chmod); err != nil {
					t.Fatal(err)
				}
			}
			since := time.Now()
			if res := applyHardeningSingle(r); res.Status != "applied" {
				t.Fatalf("result = %+v", res)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: r.Name, Category: r.Category, Kind: "mode", Mode: &modeUndoState{
				Path: path, Mode: step.want, UID: uid, GID: gid, AppliedMode: uint32(applied), AppliedUID: uid, AppliedGID: gid,
			}})
		}
	})
	t.Run("compilers", func(t *testing.T) {
		withHardeningUndoDir(t)
		dir := t.TempDir()
		gcc := filepath.Join(dir, "gcc")
		if err := os.WriteFile(gcc, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(gcc, 0o755); err != nil {
			t.Fatal(err)
		}
		withCompilerPaths(t, gcc, filepath.Join(dir, "missing-compilers-script"))
		target, err := filepath.EvalSymlinks(gcc)
		if err != nil {
			t.Fatal(err)
		}
		uid, gid := fileOwner(t, target)
		r := store.AuditResult{Name: "cp_compilers", Category: "cpanel"}
		for range 2 {
			since := time.Now()
			if res := applyHardeningSingle(r); res.Status != "applied" {
				t.Fatalf("result = %+v", res)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: r.Name, Category: r.Category, Kind: "compilers", Compilers: &compilersUndoState{
				Method: "chmod", Path: target, Mode: 0o755, UID: uid, GID: gid, AppliedMode: 0o750, AppliedUID: uid, AppliedGID: gid,
			}})
		}
	})
	t.Run("file", func(t *testing.T) {
		withHardeningUndoDir(t)
		path := withTempCPUpdateConf(t)
		if err := os.WriteFile(path, []byte("UPDATES=manual\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		r := store.AuditResult{Name: "cp_updates", Category: "cpanel"}
		for range 2 {
			since := time.Now()
			if res := applyHardeningSingle(r); res.Status != "applied" {
				t.Fatalf("result = %+v", res)
			}
			wantUndoRecord(t, since, HardeningUndoRecord{Name: r.Name, Category: r.Category, Kind: "file", File: &fileUndoState{
				Path: path, Previous: "UPDATES=manual\n", Applied: "UPDATES=daily\n",
			}})
		}
	})
}

// An earlier record that cannot be read could hold the only way back to the
// original state, so the fix applies without undo rather than recording
// CSM's own earlier change in its place.
func TestHardeningUndoUnreadableOlderRecord(t *testing.T) {
	dir := withHardeningUndoDir(t)
	path := withTempCPUpdateConf(t)
	if err := os.WriteFile(path, []byte("UPDATES=manual\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeHardeningUndo(HardeningUndoRecord{Name: "cp_updates", Kind: "file", File: &fileUndoState{Path: path}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cp_updates.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})
	if res.Status != "applied" || !strings.Contains(res.Message, "Undo is unavailable") {
		t.Fatalf("result = %+v", res)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "UPDATES=daily\n" {
		t.Fatalf("file = %q, %v", data, err)
	}
	// No new record, and the unreadable one is removed.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("records left: %v, %v", entries, err)
	}
}

func TestHardeningUndoNoRecordOnFailedApply(t *testing.T) {
	cases := []struct {
		name  string
		apply func(t *testing.T) HardeningFixResult
	}{
		{"ssh_max_auth_tries", func(t *testing.T) HardeningFixResult {
			withTempSSHDConfig(t, "MaxAuthTries 6\n")
			withMockCmd(t, &mockCmd{run: func(name string, _ ...string) ([]byte, error) {
				if name == "systemctl" {
					return nil, nil
				}
				return []byte("bad configuration option"), errors.New("exit status 255")
			}})
			return applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}})[0]
		}},
		{"os_sysctl_rp_filter", func(t *testing.T) HardeningFixResult {
			withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
			withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) {
				return []byte("sysctl: permission denied on key"), errors.New("exit status 255")
			}})
			return applySysctlFixes([]store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}})[0]
		}},
		{"cp_max_emails_hour", func(t *testing.T) HardeningFixResult {
			withMockCmd(t, &mockCmd{run: func(_ string, args ...string) ([]byte, error) {
				if slices.Contains(args, "get_tweaksetting") {
					return []byte(`{"data":{"tweaksetting":{"key":"maxemailsperhour","value":"0"}},"metadata":{"result":1}}`), nil
				}
				return []byte(`{"metadata":{"result":0,"reason":"denied"}}`), nil
			}})
			return applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"})
		}},
		{"php_expose_81", func(t *testing.T) HardeningFixResult {
			withPHPReloadStubbed(t)
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, hardeningPHPIniName), 0o700); err != nil {
				t.Fatal(err)
			}
			return applyPHPFixes([]store.AuditResult{{Name: "php_expose_81", Category: "php"}}, []phpInstall{{shortID: "81", scanDir: dir}})[0]
		}},
		{"os_shadow_permissions", func(t *testing.T) HardeningFixResult {
			old := hardeningShadowPath
			hardeningShadowPath = filepath.Join(t.TempDir(), "missing-shadow")
			t.Cleanup(func() { hardeningShadowPath = old })
			return applyHardeningSingle(store.AuditResult{Name: "os_shadow_permissions", Category: "os"})
		}},
		{"os_tmp_permissions", func(t *testing.T) HardeningFixResult {
			old := hardeningTmpDirs
			hardeningTmpDirs = map[string]string{"os_tmp_permissions": filepath.Join(t.TempDir(), "missing-tmp")}
			t.Cleanup(func() { hardeningTmpDirs = old })
			return applyHardeningSingle(store.AuditResult{Name: "os_tmp_permissions", Category: "os"})
		}},
		{"cp_compilers", func(t *testing.T) HardeningFixResult {
			dir := t.TempDir()
			withCompilerPaths(t, filepath.Join(dir, "missing-cc"), filepath.Join(dir, "missing-compilers-script"))
			withMockCmd(t, &mockCmd{})
			return applyHardeningSingle(store.AuditResult{Name: "cp_compilers", Category: "cpanel"})
		}},
		{"cp_updates", func(t *testing.T) HardeningFixResult {
			withTempCPUpdateConf(t)
			return applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})
		}},
	}
	records := testHardeningUndoRecords()
	for _, tc := range cases {
		for _, withOlder := range []bool{false, true} {
			t.Run(tc.name+"/older="+strconv.FormatBool(withOlder), func(t *testing.T) {
				withHardeningUndoDir(t)
				i := slices.IndexFunc(records, func(r HardeningUndoRecord) bool { return r.Name == tc.name })
				if i < 0 {
					t.Fatalf("no sample record for %s", tc.name)
				}
				older := records[i]
				if withOlder {
					if err := writeHardeningUndo(older); err != nil {
						t.Fatal(err)
					}
				}
				if res := tc.apply(t); res.Status != "failed" {
					t.Fatalf("result = %+v; want a failed apply", res)
				}
				names, err := HardeningUndoNames()
				if err != nil {
					t.Fatal(err)
				}
				if !withOlder {
					if len(names) != 0 {
						t.Fatalf("records after a failed apply: %v", names)
					}
					return
				}
				got, ok, err := readHardeningUndo(tc.name)
				if err != nil || !ok || !reflect.DeepEqual(got, older) {
					t.Fatalf("older record = %+v, %v, %v; want it unchanged", got, ok, err)
				}
				if !slices.Equal(names, []string{tc.name}) {
					t.Fatalf("records = %v", names)
				}
			})
		}
	}
}

// The change stands when its undo record cannot be kept; the result says
// so, and no older record is left to undo to the state before an earlier
// apply.
func TestHardeningUndoUnavailableKeepsChange(t *testing.T) {
	t.Run("record not written", func(t *testing.T) {
		dir := withHardeningUndoDir(t)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := withTempCPUpdateConf(t)
		if err := os.WriteFile(path, []byte("UPDATES=manual\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		res := applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})
		if res.Status != "applied" || !strings.Contains(res.Message, "Undo is unavailable") {
			t.Fatalf("result = %+v", res)
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "UPDATES=daily\n" {
			t.Fatalf("file = %q, %v", data, err)
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Fatalf("written to an unsafe store: %v, %v", entries, err)
		}
	})
	t.Run("previous value unreadable", func(t *testing.T) {
		withHardeningUndoDir(t)
		older := HardeningUndoRecord{Name: "cp_max_emails_hour", Category: "cpanel", Kind: "tweak", AppliedAt: time.Now().UTC(),
			Tweak: &tweakUndoState{Key: "maxemailsperhour", Previous: "0", HadValue: true, Applied: "200"}}
		if err := writeHardeningUndo(older); err != nil {
			t.Fatal(err)
		}
		withMockCmd(t, &mockCmd{run: func(_ string, args ...string) ([]byte, error) {
			if slices.Contains(args, "get_tweaksetting") {
				return nil, errors.New("exit status 1")
			}
			return []byte(`{"metadata":{"result":1}}`), nil
		}})
		res := applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"})
		if res.Status != "applied" || !strings.Contains(res.Message, "Undo is unavailable") {
			t.Fatalf("result = %+v", res)
		}
		wantNoUndoRecord(t, "cp_max_emails_hour")
	})
}

// A fix the apply code can run but the store does not know would apply with
// no way back.
func TestHardeningUndoKnowsEveryDispatchableFix(t *testing.T) {
	var names []string
	for _, table := range []map[string]keyValue{sshFixDirectives, sysctlFixes, cpTweakFixes} {
		for name := range table {
			names = append(names, name)
		}
	}
	for name := range hardeningTmpDirs {
		names = append(names, name)
	}
	for _, fix := range phpOffFixes {
		names = append(names, fix.key+"82", fix.key+"system")
	}
	// applyHardeningSingle and autoFixDescription also switch on literal names.
	file, err := parser.ParseFile(token.NewFileSet(), "hardening_apply.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || (fn.Name.Name != "applyHardeningSingle" && fn.Name.Name != "autoFixDescription") {
			continue
		}
		var literals []string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if clause, isCase := n.(*ast.CaseClause); isCase {
				for _, e := range clause.List {
					if lit, isLit := e.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
						name, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatal(err)
						}
						literals = append(literals, name)
					}
				}
			}
			return true
		})
		if len(literals) == 0 {
			t.Fatalf("found no fix names in %s", fn.Name.Name)
		}
		names = append(names, literals...)
	}
	for _, name := range names {
		if !knownHardeningFix(name) {
			t.Errorf("the undo store does not know the fix %q", name)
		}
	}
}
