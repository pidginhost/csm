package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

// A suppressed database finding keeps its session notice, which blocks
// nothing, and makes no database writes.
func TestDBSuppressionPreservesSessionNoticesWithoutDatabaseWrites(t *testing.T) {
	for _, check := range []string{"db_options_injection", "db_siteurl_hijack"} {
		for _, remediate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/remediate=%t", check, remediate), func(t *testing.T) {
				withDatabaseCoverageInstalls(t, map[string]string{
					"/home/alice/public_html/wp-config.php": databaseCoverageConfig("site"),
				}, nil)
				var writes []string
				mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
					switch {
					case strings.Contains(query, "SELECT option_value"):
						return []string{`<script src="http://192.0.2.1/payload.js"></script>`}, nil
					case strings.Contains(query, "SELECT meta_value FROM wp_usermeta"):
						return []string{`a:1:{s:2:"ip";s:10:"192.0.2.10";}`}, nil
					case strings.Contains(query, "SELECT user_id, meta_value"):
						return []string{"1\t" + `a:1:{s:2:"ip";s:10:"192.0.2.10";}`}, nil
					case !strings.HasPrefix(query, "SELECT "):
						writes = append(writes, query)
					}
					return nil, nil
				})
				t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
				cfg := pendingTestConfig(t)
				cfg.AutoResponse.CleanDatabase = true
				b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}}
				applyBlockTestSetup(t, b)
				f := alert.Finding{Check: check, Severity: alert.High, Message: "database compromise", Details: "Database: site\nOption: injected_option"}
				actions := AutoRespondDBMalwareWithPolicy(cfg, []alert.Finding{f}, func(alert.Finding) bool { return remediate })
				if len(b.ids) != 0 {
					t.Fatalf("session addresses were blocked: %v", b.ids)
				}
				if (len(writes) > 0) != remediate {
					t.Fatalf("database writes=%d with remediation=%t", len(writes), remediate)
				}
				if len(actions) == 0 || actions[0].Check != "auto_response" || actions[0].Cause == nil || actions[0].Cause.FindingID != alert.FindingID(f) || !strings.Contains(actions[0].Details, "192.0.2.10") {
					t.Fatalf("actions = %+v, want the session notice first", actions)
				}
				if !remediate && len(actions) != 1 {
					t.Fatalf("suppressed database response returned more than its notice: %+v", actions)
				}
			})
		}
	}
}

func TestDBSuppressionPreventsObjectRemoval(t *testing.T) {
	var drops int
	previous := dbDropObjectFn
	dbDropObjectFn = func(_, _, _, _ string, _ bool) DBCleanResult {
		drops++
		return DBCleanResult{Success: true}
	}
	t.Cleanup(func() { dbDropObjectFn = previous })
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.CleanDatabase = true
	findings := []alert.Finding{maliciousObjectFinding()}
	if actions := AutoRespondDBMalwareWithPolicy(cfg, findings, func(alert.Finding) bool { return false }); len(actions) != 0 || drops != 0 {
		t.Fatalf("suppressed object was remediated: actions=%v drops=%d", actions, drops)
	}
	if actions := AutoRespondDBMalwareWithPolicy(cfg, findings, func(alert.Finding) bool { return true }); len(actions) != 1 || drops != 1 {
		t.Fatalf("unsuppressed object was not remediated: actions=%v drops=%d", actions, drops)
	}
}
