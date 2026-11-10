package checks

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

func TestPrestaShopEmployeeDetails(t *testing.T) {
	for _, tc := range []struct {
		name, profile, event string
		storeless, known     bool
		severity             alert.Severity
	}{
		{name: "visibility", profile: "1", storeless: true, severity: alert.Warning},
		{name: "new employee", profile: "4", severity: alert.High},
		{name: "new SuperAdmin", profile: "1", event: "new SuperAdmin", severity: alert.Critical},
		{name: "promotion", profile: "1", event: "promoted to SuperAdmin", known: true, severity: alert.Critical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPSEmployeeHarness(t)
			switch {
			case tc.storeless:
				h.store = nil
			case tc.known:
				h.scan("9\t4\temployee@example.test")
			default:
				h.scan()
			}
			row := "9\t" + tc.profile + "\temployee@example.test"
			got := h.scan(row)
			if len(got) != 1 || len(psFindings(got, "prestashop_admin_injection")) != 1 || got[0].Severity != tc.severity {
				t.Fatalf("findings = %+v, want one %v", got, tc.severity)
			}
			lines := strings.Split(got[0].Details, "\n")
			for _, want := range []string{
				"Account: alice", "Employee id: 9", "Profile id: " + tc.profile,
				"Email: employee@example.test", "Row: " + row,
				"Database: shop_db", "Table prefix: ps_", "Database host: localhost",
			} {
				if !slices.Contains(lines, want) {
					t.Errorf("finding details lack %q: %q", want, got[0].Details)
				}
			}
			identity := []string{"cms-admin=prestashop", "id=9"}
			if tc.event != "" {
				identity = append(identity, "event="+tc.event)
				if !slices.Contains(lines, "Event: "+tc.event) || !strings.Contains(got[0].Message, tc.event) {
					t.Errorf("finding does not identify its event: %+v", got[0])
				}
			} else if strings.Contains(got[0].Details, "Event:") {
				t.Errorf("ordinary employee finding has a SuperAdmin event: %+v", got[0])
			}
			wantKey := dbContentDedupKey("alice", psScanCreds("ps_").asWPDBCreds(), "ps_", identity...)
			if got[0].DedupKey != wantKey {
				t.Errorf("dedup key = %q, want %q", got[0].DedupKey, wantKey)
			}
		})
	}
}

func TestPrestaShopPartialEmployeesPreserveState(t *testing.T) {
	for _, cause := range []string{"overflow", "query failure", "cancellation", "malformed id"} {
		t.Run(cause, func(t *testing.T) {
			s := newCrontabTestStore(t)
			creds := psScanCreds("ps_")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, coverage := withIncompleteCheckCollector(ctx)
			creds.ctx = ctx
			baselineRows := append(slices.Clone(psBaselineRows), psEmployeeRows(cmsScanRowLimit + 1)[3:]...)
			rows := baselineRows
			var queryErr error
			cancelQuery := false
			mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
				if cancelQuery {
					cancel()
				}
				return rows, queryErr
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			if got := scanPrestaShopEmployees(s, "alice", creds); len(got) != 0 {
				t.Fatalf("baseline = %+v", got)
			}
			w := creds.asWPDBCreds()
			setKey := "_pssuperadmin:v1:" + dbContentDedupKey("alice", w, "ps_", "cms-admin=prestashop", "superadmins")
			baselineKey := "_cmsadmin_baseline:v2:" + dbContentDedupKey("alice", w, "ps_", "cms-admin=prestashop")
			rows = []string{"1\t4\towner@example.test", "2\t1\tstaff@example.test", "3\t1\tnew@example.test"}
			recoveredRows := slices.Clone(rows)
			switch cause {
			case "overflow":
				rows = append(rows, baselineRows[2:]...)
			case "query failure":
				queryErr = errors.New("database unavailable")
			case "cancellation":
				cancelQuery = true
			case "malformed id":
				rows = append(rows, "broken\t1\temployee@example.test")
			}
			got := scanPrestaShopEmployees(s, "alice", creds)
			if cause == "overflow" || cause == "malformed id" {
				if len(got) != 2 || got[0].Severity != alert.Critical || got[1].Severity != alert.Critical ||
					!strings.Contains(got[0].Details, "Event: promoted to SuperAdmin") ||
					!strings.Contains(got[1].Details, "Event: new SuperAdmin") {
					t.Fatalf("partial findings = %+v, want one promotion and one new SuperAdmin", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("failed query produced findings: %+v", got)
			}
			if !coverage.contains(prestashopOwner) {
				t.Error("partial result did not mark the check incomplete")
			}
			if value, ok := s.GetRaw(setKey); !ok || value != "1" {
				t.Errorf("partial result changed the SuperAdmin set: %q, %v", value, ok)
			}
			if value, ok := s.GetRaw(baselineKey); !ok || value != "1" {
				t.Errorf("partial result changed the baseline: %q, %v", value, ok)
			}
			for _, id := range []string{"1", "2"} {
				if value, ok := s.GetRaw(cmsAdminSeenKey("alice", w, "prestashop", id)); !ok || value != "seen" {
					t.Errorf("partial result changed seen id %s: %q, %v", id, value, ok)
				}
			}
			if _, seen := s.GetRaw(cmsAdminSeenKey("alice", w, "prestashop", "3")); seen {
				t.Error("partial result consumed the new SuperAdmin id")
			}
			rows, queryErr, cancelQuery = recoveredRows, nil, false
			creds.ctx = context.Background()
			recovered := scanPrestaShopEmployees(s, "alice", creds)
			if len(recovered) != 2 || recovered[0].Severity != alert.Critical || recovered[1].Severity != alert.Critical {
				t.Fatalf("complete recovery = %+v, want both Critical events", recovered)
			}
			if value, ok := s.GetRaw(setKey); !ok || value != "2,3" {
				t.Errorf("complete result did not record SuperAdmins: %q, %v", value, ok)
			}
			if again := scanPrestaShopEmployees(s, "alice", creds); len(again) != 0 {
				t.Fatalf("recorded events repeated: %+v", again)
			}
		})
	}
}

func TestPrestaShopEmployeeDetailsWithEmptyEmail(t *testing.T) {
	mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
		return []string{"9\t1\t"}, nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	got := scanPrestaShopEmployees(nil, "alice", psScanCreds("ps_"))
	if len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("findings = %+v, want one Warning", got)
	}
	lines := strings.Split(got[0].Details, "\n")
	for _, want := range []string{"Employee id: 9", "Profile id: 1", "Email: "} {
		if !slices.Contains(lines, want) {
			t.Errorf("finding details lack %q: %q", want, got[0].Details)
		}
	}
}
