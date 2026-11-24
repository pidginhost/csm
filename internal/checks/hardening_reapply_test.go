package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// Re-applying an unchanged managed keyword must track the disabled lines
// still present, in file order, without counting a re-enabled line twice.
func TestHardeningReapplySSHDisabledLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []string
		want []string
	}{
		{"inserted before", []string{"MaxAuthTries 8", sshdDisabledBy + "MaxAuthTries 6"}, []string{"MaxAuthTries 8", "MaxAuthTries 6"}},
		{"re-enabled", []string{"MaxAuthTries 6"}, []string{"MaxAuthTries 6"}},
		{"deleted", []string{"MaxAuthTries 8"}, []string{"MaxAuthTries 8"}},
		{"duplicate retained", []string{sshdDisabledBy + "MaxAuthTries 6", "MaxAuthTries 6"}, []string{"MaxAuthTries 6", "MaxAuthTries 6"}},
		{"edited comment", []string{sshdDisabledBy + "MaxAuthTries 7"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
			withMockCmd(t, &mockCmd{run: func(string, ...string) ([]byte, error) { return nil, nil }})
			items := []store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}
			if out := applySSHFixes(items); len(out) != 1 || out[0].Status != "applied" {
				t.Fatalf("first apply = %+v", out)
			}
			lines := append([]string{sshdBlockBegin, "MaxAuthTries 4", sshdBlockEnd}, tc.body...)
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				since := time.Now()
				if out := applySSHFixes(items); len(out) != 1 || out[0].Status != "applied" {
					t.Fatalf("re-apply = %+v", out)
				}
				wantUndoRecord(t, since, HardeningUndoRecord{Name: items[0].Name, Category: "ssh", Kind: "ssh", SSH: &sshUndoState{
					Keyword: "MaxAuthTries", AppliedValue: "4", DisabledLines: tc.want,
				}})
			}
		})
	}
}

// Ownership and permissions can be edited independently. Changing one must
// not turn CSM's previous write to another into the original state.
func TestHardeningReapplyModeFields(t *testing.T) {
	for _, kind := range []string{"mode", "compilers"} {
		for _, field := range []string{"mode", "owner", "group"} {
			t.Run(kind+"/"+field, func(t *testing.T) {
				withHardeningUndoDir(t)
				appliedMode, appliedUID, appliedGID := uint32(0o1777), uint32(0), uint32(0)
				if kind == "compilers" {
					appliedMode, appliedUID, appliedGID = 0o750, 7, 8
				}
				mode, uid, gid := appliedMode, appliedUID, appliedGID
				wantMode, wantUID, wantGID := uint32(0o755), uint32(7), uint32(8)
				switch field {
				case "mode":
					mode, wantMode = 0o700, 0o700
				case "owner":
					uid, wantUID = 9, 9
				case "group":
					gid, wantGID = 9, 9
				}
				older := HardeningUndoRecord{Kind: kind}
				current := HardeningUndoRecord{Kind: kind}
				want := HardeningUndoRecord{Kind: kind}
				if kind == "mode" {
					older.Mode = &modeUndoState{Path: "/tmp", Mode: 0o755, UID: 7, GID: 8, AppliedMode: appliedMode}
					current.Mode = &modeUndoState{Path: "/tmp", Mode: mode, UID: uid, GID: gid, AppliedMode: appliedMode}
					want.Mode = &modeUndoState{Path: "/tmp", Mode: wantMode, UID: wantUID, GID: wantGID, AppliedMode: appliedMode}
					want.Name, want.Category = "os_tmp_permissions", "os"
				} else {
					older.Compilers = &compilersUndoState{Method: "chmod", Path: "/usr/bin/cc", Mode: 0o755, UID: 7, GID: 8, AppliedMode: appliedMode, AppliedUID: appliedUID, AppliedGID: appliedGID}
					current.Compilers = &compilersUndoState{Method: "chmod", Path: "/usr/bin/cc", Mode: mode, UID: uid, GID: gid, AppliedMode: appliedMode, AppliedUID: uid, AppliedGID: gid}
					want.Compilers = &compilersUndoState{Method: "chmod", Path: "/usr/bin/cc", Mode: wantMode, UID: wantUID, GID: wantGID, AppliedMode: appliedMode, AppliedUID: uid, AppliedGID: gid}
					want.Name, want.Category = "cp_compilers", "cpanel"
				}
				older.Name = want.Name
				if err := writeHardeningUndo(older); err != nil {
					t.Fatal(err)
				}
				since := time.Now()
				if note := recordHardeningUndo(store.AuditResult{Name: want.Name, Category: want.Category}, current, readUndoPrior(want.Name), nil); note != "" {
					t.Fatal(note)
				}
				wantUndoRecord(t, since, want)
			})
		}
	}
}

// A runtime-only attempt must not claim ownership of drop-in lines it never
// wrote when a later apply finally saves the setting.
func TestHardeningReapplySysctlRuntimeOnly(t *testing.T) {
	withHardeningUndoDir(t)
	conf := withTempSysctl(t, "", map[string]string{"net.ipv4.conf.all.rp_filter": "2"})
	withMockCmd(t, &mockCmd{run: kernelSysctl})
	if err := os.Mkdir(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	items := []store.AuditResult{{Name: "os_sysctl_rp_filter", Category: "os"}}
	since := time.Now()
	if out := applySysctlFixes(items); len(out) != 1 || out[0].Status != "failed" {
		t.Fatalf("first apply = %+v", out)
	}
	wantUndoRecord(t, since, HardeningUndoRecord{Name: items[0].Name, Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
		Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "2", AppliedValue: "1", RuntimeOnly: true,
	}})
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	const line = "net.ipv4.conf.all.rp_filter = 0"
	if err := os.WriteFile(conf, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		since := time.Now()
		if out := applySysctlFixes(items); len(out) != 1 || out[0].Status != "applied" {
			t.Fatalf("re-apply = %+v", out)
		}
		wantUndoRecord(t, since, HardeningUndoRecord{Name: items[0].Name, Category: "os", Kind: "sysctl", Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "2", AppliedValue: "1", PrevLines: []string{line},
		}})
	}
}

// Every incremental PHP record must fold the initial prior record once,
// retaining unwritten SAPIs and the operator's edits as each is captured.
func TestHardeningReapplyPHPIntermediateRecords(t *testing.T) {
	withHardeningUndoDir(t)
	withPHPReloadStubbed(t)
	ver, dirs := debianPHPTree(t, "cli", "fpm", "apache2")
	for _, dir := range dirs {
		if err := os.WriteFile(filepath.Join(dir, hardeningPHPIniName), []byte("expose_php = On\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	items := []store.AuditResult{{Name: "php_expose_82", Category: "php"}}
	installs := []phpInstall{{shortID: "82", scanDir: filepath.Join(ver, "cli", "conf.d")}}
	if out := applyPHPFixes(items, installs); len(out) != 1 || out[0].Status != "applied" {
		t.Fatalf("first apply = %+v", out)
	}
	if err := os.WriteFile(filepath.Join(ver, "fpm", "conf.d", hardeningPHPIniName), []byte("expose_php = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := HardeningUndoRecord{Name: items[0].Name, Category: "php", Kind: "php"}
	for _, sapi := range []string{"apache2", "fpm", "cli"} {
		want.PHP = append(want.PHP, phpUndoState{Path: filepath.Join(ver, sapi, "conf.d", hardeningPHPIniName), Key: "expose_php", PrevLine: "expose_php = On", HadKey: true, Applied: "Off"})
	}
	since := time.Now()
	writes := 0
	oldSync := hardeningUndoSync
	t.Cleanup(func() { hardeningUndoSync = oldSync })
	hardeningUndoSync = func(f *os.File) error {
		if f.Name() == hardeningUndoDir {
			writes++
			if writes >= 2 {
				want.PHP[1].PrevLine = "expose_php = 1"
			}
			wantUndoRecord(t, since, want)
		}
		return oldSync(f)
	}
	if out := applyPHPFixes(items, installs); len(out) != 1 || out[0].Status != "applied" || strings.Contains(out[0].Message, "Undo is unavailable") {
		t.Fatalf("re-apply = %+v", out)
	}
	if writes != 3 {
		t.Fatalf("records published = %d, want 3", writes)
	}
	wantUndoRecord(t, since, want)
}
