package txn

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestApplyRechecksOperatorScores(t *testing.T) {
	for _, stack := range []antispam.MailStack{antispam.StackExim, antispam.StackPostfix} {
		t.Run(string(stack), func(t *testing.T) {
			f := newFake(t)
			f.stack = stack
			h := f.host()
			preflight := h.preflight
			h.preflight = func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
				facts, problems := preflight(ctx, s)
				facts.GroupFiles = map[string]antispam.GroupFile{
					"policies": {Content: "symbols { DMARC_POLICY_REJECT { weight = 5; } }"},
				}
				return facts, problems
			}
			// The operator added a definition after the daemon resolved this
			// request. The worker has fresh facts under its mutation lock.
			result := h.Apply(enforce())
			if result.OK || result.FailedStep != StepPreconditions || result.Rollback != antispam.RollbackNone {
				t.Fatalf("stale request was not refused before mutation: %+v", result)
			}
			if len(f.calls) != 0 || f.file(antispam.ScoresPath) != "<absent>" || f.file(antispam.RecordPath) != "<absent>" {
				t.Fatal("stale request ran commands or changed files")
			}
			resolved := enforce()
			resolved.HostScores = []string{"DMARC_POLICY_REJECT"}
			wantOK(t, h.Apply(resolved))
			got := f.file(antispam.ScoresPath)
			if strings.Contains(got, "DMARC_POLICY_REJECT") || !strings.Contains(got, "HIDDEN_TEXT") || !strings.Contains(got, "URL_VERY_LONG") {
				t.Fatalf("worker overwrote an operator weight: %q", got)
			}
		})
	}
}
