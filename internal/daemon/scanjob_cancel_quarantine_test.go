package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Cancelling a `--quarantine` job keeps the partial findings, but it must not
// keep acting on them: the operator withdrew consent for further changes, and
// the findings produced while the scan was being torn down are the least
// verified of the batch.
func TestScanJobCancelledJobDoesNotQuarantine(t *testing.T) {
	st, _ := openTestScanJobStores(t)
	m, err := NewScanJobManager(st, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	calls := 0
	m.quarantineFile = func(f alert.Finding) (checks.RemediationResult, bool) {
		calls++
		return checks.RemediationResult{Success: true, Action: "moved"}, true
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := scanJobRequest{
		id:         "job-1",
		quarantine: true,
		cancelCtx:  ctx,
		cancelFn:   cancel,
		remediated: map[string]scanJobRemediation{},
	}
	in := alert.Finding{Severity: alert.Critical, Check: "webshell", FilePath: "/home/acct/public_html/shell.php"}

	out := m.annotateQuarantine(req, in)
	if calls != 0 {
		t.Fatalf("quarantine ran %d time(s) on a cancelled job", calls)
	}
	if out.RemediationStatus != "" || out.RemediationDetail != "" {
		t.Fatalf("finding annotated after cancel: %+v", out)
	}
}
