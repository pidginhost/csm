package txn

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

// The worker collects its own facts after the daemon's assessment. A
// changed proxy must be refused before writes, backups, probes or reloads.
func TestApplyPostfixRechecksQuietRejects(t *testing.T) {
	for _, installed := range []bool{false, true} {
		for _, option := range []string{`"discard_on_reject":true`, `"quarantine_on_reject":true`, `"discard_on_reject":[true,false]`, `"discard_on_reject":null`, `"quarantine_on_reject":[]`} {
			t.Run(fmt.Sprintf("installed=%t/%s", installed, option), func(t *testing.T) {
				f := postfixFake(t)
				if installed {
					wantOK(t, f.host().Apply(enforce()))
				}
				before := f.state()
				f.reset()
				f.milters, f.pings = nil, 0
				f.workers = `{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true,` + option + `}}`
				r := f.host().Apply(enforce())
				if r.OK || r.FailedStep != StepPreconditions || r.Rollback != antispam.RollbackNone || !strings.Contains(r.Error, antispam.CodeMilterRejects) {
					t.Fatalf("got %+v; want a quiet-reject precondition failure", r)
				}
				if !maps.Equal(before, f.state()) || len(f.calls) != 0 || len(f.milters) != 0 || f.pings != 0 || len(f.replaced()) != 0 {
					t.Fatal("refused apply changed files, created backups or contacted services")
				}
			})
		}
	}
}

func TestApplyQuietRejectsAllowsDryRunAndExim(t *testing.T) {
	for _, stack := range []antispam.MailStack{antispam.StackPostfix, antispam.StackExim} {
		t.Run(string(stack), func(t *testing.T) {
			f := newFake(t)
			f.stack = stack
			f.workers = `{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true,"discard_on_reject":true,"quarantine_on_reject":true}}`
			s := enforce()
			s.DryRun = stack == antispam.StackPostfix
			wantOK(t, f.host().Apply(s))
			if stack == antispam.StackPostfix {
				wantPostfixFiles(t, f, s)
				noExim(t, f)
			}
		})
	}
}
