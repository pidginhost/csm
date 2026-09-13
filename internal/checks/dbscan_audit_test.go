package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

func TestDatabaseAuditKeepsDistinctEndpoints(t *testing.T) {
	withDatabaseCoverageInstalls(t, map[string]string{
		"/home/alice/first/wp-config.php":  databaseCoverageConfig("shared") + "define('DB_HOST', 'first.example');\n",
		"/home/alice/second/wp-config.php": databaseCoverageConfig("shared") + "define('DB_HOST', 'second.example');\n",
	}, nil)
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		if strings.Contains(query, "FROM wp_terms") {
			return []string{"1\tcategory\t1\thttps://example.com"}, nil
		}
		return databaseCoverageHealthyRows(query), nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	findings := CheckDatabaseContent(context.Background(), nil, nil)
	if len(findings) != 2 || findings[0].Key() == findings[1].Key() {
		t.Fatalf("separate database endpoints did not produce distinct findings: %+v", findings)
	}
	if findings[0].Details != findings[1].Details {
		t.Fatal("fixture no longer exercises endpoint identity outside display details")
	}
	alert.FillTimestamps(findings, time.Unix(123, 0))

	alert.CloseAuditSinks()
	t.Cleanup(alert.CloseAuditSinks)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.AuditLog.File.Enabled = true
	cfg.Alerts.AuditLog.File.Path = path
	for range 2 {
		if err := alert.DispatchWithSources(cfg, nil, findings); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("database endpoint observations collapsed or replayed: records=%d, want two", len(lines))
	}
	for _, line := range lines {
		var event alert.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Check != "db_spam_taxonomy" || event.Details != findings[0].Details {
			t.Fatalf("unexpected database audit evidence: %+v", event)
		}
	}
}
