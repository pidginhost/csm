package txn

import (
	"maps"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

// Apply renders for the stack preflight found; the request names none.
// Rendering for the wrong stack would leave a Postfix target with no
// managed text, written as an empty file.
func TestApplyRendersForTheCollectedStack(t *testing.T) {
	f := newFake(t)
	f.stack = antispam.StackPostfix
	want, err := antispam.RenderPostfix(enforce())
	if err != nil {
		t.Fatal(err)
	}
	// The first configtest checks the staged files; until the Exim steps
	// learn the Postfix stack, a rollback follows and checks again.
	staged := "<not staged>"
	f.onCall = func(line string) {
		if line == "rspamadm configtest" && staged == "<not staged>" {
			staged = f.file(antispam.MilterHeadersPath)
		}
	}
	f.host().Apply(enforce())
	if staged != want[antispam.MilterHeadersPath] {
		t.Fatalf("milter_headers.conf at configtest = %q, want %q", staged, want[antispam.MilterHeadersPath])
	}
}

// On Postfix, enforce takes over a foreign actions.conf with a backup, like
// any file CSM owns; a dry run leaves it to the host and backs up nothing.
func TestApplyPostfixActionsTakeover(t *testing.T) {
	for _, dry := range []bool{false, true} {
		f := newFake(t)
		f.stack = antispam.StackPostfix
		writeTest(t, f.root+actionsPath, foreignActions, 0o644)
		s := enforce()
		s.DryRun = dry
		postfix := s
		postfix.Stack = antispam.StackPostfix
		managed, err := antispam.ManagedContent(postfix)
		if err != nil {
			t.Fatal(err)
		}
		staged, backups, checked := "", map[string]string(nil), false
		f.onCall = func(line string) {
			if line == "rspamadm configtest" && !checked {
				checked = true
				staged, backups = f.file(actionsPath), f.replaced()
			}
		}
		f.host().Apply(s)
		want, wantBackups := managed[actionsPath], map[string]string{actionsPath: foreignActions}
		if dry {
			want, wantBackups = foreignActions, map[string]string{}
		}
		if !checked || staged != want || !maps.Equal(backups, wantBackups) {
			t.Errorf("dry run %t: configtest ran %t with actions.conf %q and backups %q; want %q and %q",
				dry, checked, staged, backups, want, wantBackups)
		}
	}
}
