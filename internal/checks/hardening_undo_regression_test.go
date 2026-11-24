package checks

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

func TestHardeningUndoSSHPartialRestoreKeepsRecord(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempSSHDConfig(t, "MaxAuthTries 6\n")
	calls := recordCommands(t)
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
	editFile(t, path, sshdDisabledBy+"MaxAuthTries 6", "MaxAuthTries 6\nMaxAuthTries 8")
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_use_dns", Category: "ssh"}}))
	// Reset only the recorded line and block value. The later apply also
	// disabled a line that still needs restoring.
	editFile(t, path, "MaxAuthTries 4\n", "")
	editFile(t, path, sshdDisabledBy+"MaxAuthTries 6", "MaxAuthTries 6")
	before := fileText(t, path)
	rec := storedUndoRecord(t, "ssh_max_auth_tries")
	*calls = nil
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "refused", "changed since")
	if fileText(t, path) != before || len(*calls) != 0 {
		t.Fatal("refused undo changed SSH state")
	}
	if got := storedUndoRecord(t, rec.Name); !reflect.DeepEqual(got, rec) {
		t.Fatal("record changed")
	}
}

func TestHardeningUndoSSHReorderedGlobalsKeepsRecord(t *testing.T) {
	withHardeningUndoDir(t)
	path := withTempSSHDConfig(t, "MaxAuthTries 6\nMaxAuthTries 8\n")
	calls := recordCommands(t)
	applyOK(t, applySSHFixes([]store.AuditResult{{Name: "ssh_max_auth_tries", Category: "ssh"}}))
	// Both lines are enabled, but the first value sshd reads is different.
	const changed = "MaxAuthTries 8\nMaxAuthTries 6\n"
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := storedUndoRecord(t, "ssh_max_auth_tries")
	*calls = nil
	wantUndoResult(t, UndoHardening(rec.Name), rec.Name, "refused", "changed since")
	if fileText(t, path) != changed || len(*calls) != 0 {
		t.Fatal("refused undo changed SSH state")
	}
	if got := storedUndoRecord(t, rec.Name); !reflect.DeepEqual(got, rec) {
		t.Fatal("record changed")
	}
}

func TestHardeningUndoUpdatesDuplicateRecovery(t *testing.T) {
	for _, tc := range []struct{ name, before, now, want, status string }{
		{"first line already daily", "UPDATES=daily\nUPDATES=never\n", "", "UPDATES=daily\nUPDATES=never\n", "undone"},
		{"no change on apply", "UPDATES=daily\n", "", "UPDATES=daily\n", "undone"},
		{"last duplicate comment missing", "UPDATES=manual\nUPDATES=never\nUPDATES=manual\nRPMUP=daily\n", "UPDATES=daily\n# UPDATES=never\nRPMUP=manual\n", "UPDATES=manual\nUPDATES=never\nUPDATES=manual\nRPMUP=manual\n", "undone"},
		{"middle duplicate comment missing", "UPDATES=manual\nUPDATES=never\nUPDATES=manual\n", "UPDATES=daily\n# UPDATES=manual\n", "UPDATES=manual\nUPDATES=never\nUPDATES=manual\n", "undone"},
		{"identical comments retained", "UPDATES=manual\n# UPDATES=never\nUPDATES=never\nUPDATES=never\n", "", "UPDATES=manual\n# UPDATES=never\nUPDATES=never\nUPDATES=never\n", "undone"},
		{"ambiguous identical comment removed", "UPDATES=manual\nUPDATES=never\n# UPDATES=never\n", "UPDATES=daily\n# UPDATES=never\n", "UPDATES=daily\n# UPDATES=never\n", "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHardeningUndoDir(t)
			path := withTempCPUpdateConf(t)
			if err := os.WriteFile(path, []byte(tc.before), 0o640); err != nil {
				t.Fatal(err)
			}
			applyOK(t, []HardeningFixResult{applyHardeningSingle(store.AuditResult{Name: "cp_updates", Category: "cpanel"})})
			rec := storedUndoRecord(t, "cp_updates")
			if tc.now != "" {
				if err := os.WriteFile(path, []byte(tc.now), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			wantUndoResult(t, UndoHardening(rec.Name), rec.Name, tc.status, "")
			if got := fileText(t, path); got != tc.want {
				t.Fatalf("file = %q, want %q", got, tc.want)
			}
			if tc.status == "undone" {
				wantNoUndoRecord(t, rec.Name)
			} else if got := storedUndoRecord(t, rec.Name); !reflect.DeepEqual(got, rec) {
				t.Fatal("record changed")
			}
		})
	}
}

func TestHardeningReapplyKeepsWHMUndoWarning(t *testing.T) {
	withHardeningUndoDir(t)
	withFakeWHMTweak(t, "maxemailsperhour", nil)
	for range 2 {
		res := applyHardeningSingle(store.AuditResult{Name: "cp_max_emails_hour", Category: "cpanel"})
		applyOK(t, []HardeningFixResult{res})
		if !strings.Contains(res.Message, "Undo will need WHM Tweak Settings") {
			t.Fatalf("apply = %+v", res)
		}
	}
}
