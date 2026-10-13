package reconcile

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/checks"
)

var testNow = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func TestFindingChecksAreRegistered(t *testing.T) {
	for _, name := range []string{CheckPrecondition, CheckApplyFailed, CheckRspamdDown, CheckRspamdRecovered, CheckScanError} {
		if _, ok := checks.LookupCheck(name); !ok {
			t.Errorf("%s is not registered", name)
		}
	}
}

func TestProblemFinding(t *testing.T) {
	for _, tc := range []struct {
		sev    antispam.Severity
		effect string
	}{
		{antispam.Temporary, "checks again"},
		{antispam.Definite, "removes"},
		{antispam.Warning, ""},
	} {
		f := problemFinding(antispam.Problem{Code: antispam.CodeSocket, Severity: tc.sev, Detail: "rspamd socket /run/x does not exist"}, testNow)
		if f.Check != CheckPrecondition || f.Severity != alert.Warning || !f.Timestamp.Equal(testNow) ||
			!strings.Contains(f.Message, antispam.CodeSocket) || !strings.HasPrefix(f.Details, "rspamd socket /run/x does not exist") ||
			!strings.Contains(f.Details, tc.effect) {
			t.Errorf("severity %d: %+v", tc.sev, f)
		}
	}
}

// Problem details can name directories a tenant created; a finding must
// not carry their control characters into alerts.
func TestProblemFindingEscapesControlCharacters(t *testing.T) {
	f := problemFinding(antispam.Problem{Code: antispam.CodeSocket, Severity: antispam.Definite,
		Detail: "/home/user/evil\nCSM: all clear\x1b[0m is writable by group or others"}, testNow)
	if strings.ContainsAny(f.Details, "\n\x1b") || !strings.Contains(f.Details, `evil\nCSM`) {
		t.Fatalf("details %q", f.Details)
	}
}

func TestResultFinding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		result   antispam.Result
		err      error
		want     bool
		severity alert.Severity
		text     string
	}{
		{"applied", antispam.Result{Operation: antispam.OpApply, OK: true, Generation: strings.Repeat("a", 64)}, nil, false, 0, ""},
		{"busy", antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}, nil, false, 0, ""},
		{"verified rollback", antispam.Result{Operation: antispam.OpApply, FailedStep: "exim_probe", Rollback: antispam.RollbackVerified, Error: "exim SMTP greeting probe failed"},
			nil, true, alert.Warning, "restored"},
		{"failed rollback", antispam.Result{Operation: antispam.OpRemove, FailedStep: "rspamd_reload", Rollback: antispam.RollbackFailed, Error: "restoring /etc/exim.conf.local: conflict"},
			nil, true, alert.Critical, "could not confirm"},
		{"refused", antispam.Result{Operation: antispam.OpApply, FailedStep: "preconditions", Rollback: antispam.RollbackNone, Error: "preconditions not met: rspamd_socket"},
			nil, true, alert.Warning, "changed nothing"},
		{"no result", antispam.Result{}, errors.New("antispam worker returned no result: secret stderr"), true, alert.Warning, "no result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := resultFinding(antispam.OpApply, tc.result, tc.err, testNow)
			if ok != tc.want {
				t.Fatalf("finding %t, want %t: %+v", ok, tc.want, f)
			}
			if !ok {
				return
			}
			if f.Check != CheckApplyFailed || f.Severity != tc.severity || !strings.Contains(f.Message+" "+f.Details, tc.text) {
				t.Errorf("finding %+v", f)
			}
			if strings.Contains(f.Details, "secret") {
				t.Errorf("worker output reached the finding: %q", f.Details)
			}
		})
	}
}
