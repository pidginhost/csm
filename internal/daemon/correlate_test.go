package daemon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

func TestExpandWithCorrelationKeepsBatchWithOldTimestamps(t *testing.T) {
	now := time.Now()
	batch := []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, TenantID: "one", Timestamp: now.Add(-3 * time.Hour)},
		{Check: "webshell", Severity: alert.Critical, TenantID: "two", Timestamp: now.Add(-2 * time.Hour)},
		{Check: "db_rogue_admin", Severity: alert.Critical, TenantID: "three", Timestamp: now},
		{Check: "webshell", Severity: alert.Critical, Timestamp: now.Add(-2 * time.Hour)},
	}
	checks.ResetAttributionHealthForTest()
	t.Cleanup(checks.ResetAttributionHealthForTest)
	got := expandWithCorrelation(batch, now)
	if len(got) != 6 || got[4].Check != "coordinated_attack" || got[5].Check != "cross_account_malware" {
		t.Fatalf("batch lost timestamped evidence: %+v", got)
	}
	if h := checks.AttributionHealth(); h.Cumulative["webshell"] != 1 {
		t.Fatalf("batch lost attribution diagnostics: %+v", h)
	}
	if again := expandWithCorrelation(got, now.Add(time.Hour)); !reflect.DeepEqual(again, got) {
		t.Fatal("dispatch changed an already-correlated batch")
	}
}

func TestExpandWithCorrelationSharesUnattributedReporter(t *testing.T) {
	// A subprocess starts with a fresh process-wide seen set without
	// resetting a reporter that other daemon tests may have used.
	if os.Getenv("CSM_TEST_CORRELATION_REPORTER") == "1" {
		csmlog.Init()
		batch := []alert.Finding{
			{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)"},
			{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: bob)"},
		}
		expandWithCorrelation(batch, time.Now())
		st, err := state.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := st.Close(); err != nil {
				t.Error(err)
			}
		}()
		batch = append(batch, alert.Finding{Severity: alert.Warning, Check: "webshell", Message: "unattributed shell"})
		checks.StoreLatestScanFindings(st, []string{"db_rogue_admin", "webshell"}, batch)
		expandWithCorrelation(batch, time.Now())
		checks.ReportUnattributedCorrelation(map[string]int{"db_rogue_admin": 9, "webshell": 7})
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestExpandWithCorrelationSharesUnattributedReporter$")
	cmd.Env = append(os.Environ(), "CSM_TEST_CORRELATION_REPORTER=1", "CSM_LOG_FORMAT=json", "CSM_LOG_LEVEL=warn")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reporter subprocess: %v\n%s", err, out)
	}
	type warning struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
		Check string `json:"check"`
		Rows  int    `json:"rows"`
	}
	var got []warning
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var w warning
		if err := json.Unmarshal([]byte(line), &w); err != nil {
			t.Fatal(err)
		}
		got = append(got, w)
	}
	const message = "cross-account correlation could not attribute findings to an account"
	want := []warning{{"WARN", message, "db_rogue_admin", 2}, {"WARN", message, "webshell", 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shared reporter warnings = %+v, want %+v", got, want)
	}
}

func TestExpandWithCorrelationInitializesPlatform(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	batch := []alert.Finding{{Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "alice"}}
	got := expandWithCorrelation(batch, time.Now())
	if !reflect.DeepEqual(got, batch) {
		t.Fatalf("single-account batch changed: %+v", got)
	}
	if platform.SetOverrides(platform.Overrides{}) {
		t.Fatal("dispatcher left platform discovery to the correlator")
	}
}

func TestExpandWithCorrelationEmptySkipsPlatformDiscovery(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	if got := expandWithCorrelation(nil, time.Now()); got != nil {
		t.Fatalf("empty batch changed: %+v", got)
	}
	if !platform.SetOverrides(platform.Overrides{}) {
		t.Fatal("empty batch initialized platform detection")
	}
}

func TestExpandWithCorrelation_EmitsCoordinatedAttack(t *testing.T) {
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Details: "found in /home/alice/public_html/shell.php", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Details: "found in /home/bob/public_html/x.php", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Details: "found in /home/carol/public_html/y.php", Timestamp: now},
	}

	out := expandWithCorrelation(findings, now)

	if len(out) < len(findings)+1 {
		t.Fatalf("output len = %d, want at least %d (input + synthetic)", len(out), len(findings)+1)
	}
	got := ""
	for _, f := range out {
		if f.Check == "coordinated_attack" {
			got = f.Message
			if f.Timestamp.IsZero() {
				t.Errorf("synthetic finding must have a timestamp, message=%q", f.Message)
			}
			break
		}
	}
	if got == "" {
		t.Fatal("expected coordinated_attack synthetic finding, none emitted")
	}
}

func TestExpandWithCorrelation_StampsMissingTimestamp(t *testing.T) {
	stamp := time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC)
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Details: "/home/alice/p.php"},
		{Severity: alert.Critical, Check: "webshell", Details: "/home/bob/q.php"},
		{Severity: alert.Critical, Check: "webshell", Details: "/home/carol/r.php"},
	}

	out := expandWithCorrelation(findings, stamp)
	stamped := 0
	for _, f := range out {
		if f.Check == "coordinated_attack" {
			if !f.Timestamp.Equal(stamp) {
				t.Errorf("synthetic timestamp = %v, want %v", f.Timestamp, stamp)
			}
			stamped++
		}
	}
	if stamped == 0 {
		t.Fatal("expected at least one stamped synthetic finding")
	}
}

func TestExpandWithCorrelation_DoesNotDuplicateExistingSyntheticFindings(t *testing.T) {
	stamp := time.Date(2026, 5, 26, 15, 0, 0, 0, time.UTC)
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/p.php"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/bob/public_html/q.php"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/carol/public_html/r.php"},
	}
	preCorrelated := append(append([]alert.Finding(nil), findings...), checks.CorrelateFindings(findings).Derived...)

	out := expandWithCorrelation(preCorrelated, stamp)

	if len(out) != len(preCorrelated) {
		t.Fatalf("pre-correlated batch grew from %d to %d", len(preCorrelated), len(out))
	}
	gotCounts := map[string]int{}
	for _, f := range out {
		if !checks.IsDerivedCorrelationCheck(f.Check) {
			continue
		}
		gotCounts[f.Check]++
		if f.Timestamp.IsZero() {
			t.Errorf("synthetic finding %q was not timestamped", f.Check)
		}
	}
	for _, check := range []string{"coordinated_attack", "cross_account_malware"} {
		if gotCounts[check] != 1 {
			t.Errorf("synthetic finding count for %q = %d, want 1", check, gotCounts[check])
		}
	}
}

func TestExpandWithCorrelation_BelowThresholdEmitsNothingExtra(t *testing.T) {
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Details: "/home/alice/p.php", Timestamp: now},
	}
	out := expandWithCorrelation(findings, now)
	if len(out) != len(findings) {
		t.Errorf("single-account batch should not synthesize anything, got %d vs %d", len(out), len(findings))
	}
}

func TestExpandWithCorrelation_ExactCountsAndIdempotence(t *testing.T) {
	stamp := time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC)
	batch := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "alice", Message: "rogue admin on alice"},
		{Severity: alert.Critical, Check: "webshell", TenantID: "bob", Message: "shell on bob"},
		{Severity: alert.Critical, Check: "webshell", TenantID: "carol", Message: "shell on carol"},
	}
	out := expandWithCorrelation(append([]alert.Finding(nil), batch...), stamp)
	if len(out) != len(batch)+2 {
		t.Fatalf("expanded to %d rows, want %d", len(out), len(batch)+2)
	}
	derived := map[string]alert.Finding{}
	for _, f := range out[len(batch):] {
		if !checks.IsDerivedCorrelationCheck(f.Check) {
			t.Fatalf("appended non-derived row %+v", f)
		}
		if !f.Timestamp.Equal(stamp) {
			t.Fatalf("derived row not stamped: %+v", f)
		}
		derived[f.Check] = f
	}
	if len(derived) != 2 {
		t.Fatalf("derived %v", derived)
	}
	keys := map[string]bool{}
	for _, f := range derived {
		keys[f.Key()] = true
	}
	again := expandWithCorrelation(append([]alert.Finding(nil), out...), stamp.Add(time.Hour))
	if len(again) != len(out) {
		t.Fatalf("re-expansion grew the batch from %d to %d", len(out), len(again))
	}
	for _, f := range again[len(batch):] {
		if !keys[f.Key()] || !f.Timestamp.Equal(stamp) {
			t.Fatalf("re-expansion changed a derived row: %+v", f)
		}
	}
}

func TestExpandWithCorrelation_UnattributedRowsAreNotAppended(t *testing.T) {
	now := time.Now()
	batch := []alert.Finding{
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: alice)"},
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: bob)"},
		{Severity: alert.Critical, Check: "db_rogue_admin", Message: "rogue admin (account: carol)"},
	}
	out := expandWithCorrelation(append([]alert.Finding(nil), batch...), now)
	if len(out) != len(batch) {
		t.Fatalf("unattributed rows aggregated: %+v", out[len(batch):])
	}
}
