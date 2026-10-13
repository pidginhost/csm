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
		info, ok := checks.LookupCheck(name)
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if info.Category != checks.CategoryEmail || info.Correlation != checks.CorrelationIgnored || info.CorrelationReason != "self-health" {
			t.Errorf("%s is not classified as email self-health: %+v", name, info)
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
		if tc.sev == antispam.Warning && f.Details != "rspamd socket /run/x does not exist" {
			t.Errorf("warning-only problem promises an integration change: %q", f.Details)
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

func TestFindingDetailsEscapeTenantPaths(t *testing.T) {
	for _, tc := range []struct {
		name, path, escaped string
	}{
		{"line controls", "/home/user/a\nb\rc\td", `/home/user/a\nb\rc\td`},
		{"terminal controls", "/home/user/a\x1b[0m\x00\x7f", `/home/user/a\x1b[0m\x00\x7f`},
		{"non-ASCII", "/home/user/\u202e\u00e9", `/home/user/\u202e\u00e9`},
		{"invalid UTF-8", "/home/user/a\xff", `/home/user/a\xff`},
		{"literal escapes", "/home/user/a\\n\"b", `/home/user/a\\n\"b`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problem := problemFinding(antispam.Problem{Code: antispam.CodeSocket, Severity: antispam.Warning, Detail: tc.path}, testNow)
			if problem.Details != tc.escaped {
				t.Errorf("problem details = %q, want %q", problem.Details, tc.escaped)
			}
			result, ok := resultFinding(antispam.OpRemove, antispam.Result{
				Operation: antispam.OpRemove, FailedStep: "exim_files", Rollback: antispam.RollbackFailed,
				Error: "restoring " + tc.path + ": conflict",
			}, nil, testNow)
			if !ok || result.Severity != alert.Critical || !strings.HasPrefix(result.Details, "restoring "+tc.escaped+": conflict.") {
				t.Errorf("worker failure lost the escaped path or rollback severity: %+v, %t", result, ok)
			}
			for _, f := range []alert.Finding{problem, result} {
				for _, c := range f.Message + f.Details {
					if c < ' ' || c > '~' {
						t.Fatalf("finding contains a control or non-ASCII character: %+v", f)
					}
				}
			}
		})
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
			op := tc.result.Operation
			if op == "" {
				op = antispam.OpApply
			}
			f, ok := resultFinding(op, tc.result, tc.err, testNow)
			if ok != tc.want {
				t.Fatalf("finding %t, want %t: %+v", ok, tc.want, f)
			}
			if !ok {
				if f.Check != "" || f.Message != "" || f.Details != "" || !f.Timestamp.IsZero() {
					t.Errorf("successful or busy result returned a finding: %+v", f)
				}
				return
			}
			if f.Check != CheckApplyFailed || f.Severity != tc.severity || !f.Timestamp.Equal(testNow) || !strings.Contains(f.Message+" "+f.Details, tc.text) {
				t.Errorf("finding %+v", f)
			}
			wantMessage := "Antispam " + op + " failed at " + tc.result.FailedStep
			if tc.err != nil {
				wantMessage = "Antispam " + op + " returned no result"
			}
			if f.Message != wantMessage {
				t.Errorf("message = %q, want %q", f.Message, wantMessage)
			}
			if strings.Contains(f.Message+f.Details, "secret") {
				t.Errorf("worker output reached the finding: %+v", f)
			}
		})
	}
}
