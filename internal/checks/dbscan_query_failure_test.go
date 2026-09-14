package checks

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// A posts query can fail while the taxonomy tables remain readable. Losing
// those independent findings would turn one schema defect into a blind scan.
func TestDatabaseStatementFailureKeepsIndependentChecks(t *testing.T) {
	for _, tc := range []struct {
		code  uint16
		class string
	}{
		{1054, "schema"},
		{1146, "schema"},
		{1064, "syntax"},
		{1142, "permission"},
		{1143, "permission"},
		{1139, "expression"},
		{1267, "expression"},
		{1271, "expression"},
		{3699, "timeout"},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			withDatabaseCoverageInstalls(t, map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("fixture"),
			}, nil)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				if strings.Contains(query, "post_content_filtered") {
					return nil, &mysql.MySQLError{Number: tc.code, Message: "server-private-diagnostic"}
				}
				if strings.Contains(query, "FROM wp_terms t") {
					return []string{"1\tcategory\t1\thttps://example.com"}, nil
				}
				return databaseCoverageHealthyRows(query), nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			findings := CheckDatabaseContent(ctx, nil, nil)
			found := false
			for _, f := range findings {
				found = found || f.Check == "db_spam_taxonomy"
			}
			if !found {
				t.Fatal("a statement error suppressed the independent taxonomy detection")
			}
			if !incomplete.contains("db_content") {
				t.Fatal("continued scanning erased the failed query's coverage gap")
			}
			summary := databaseCoverageSummary(t, findings)
			for _, want := range []string{"query_failed=1", "stage=posts", "class=" + tc.class, fmt.Sprintf("code=%d", tc.code)} {
				if !strings.Contains(summary.Details, want) {
					t.Errorf("coverage summary omits %q: %s", want, summary.Details)
				}
			}
			if strings.Contains(summary.Details, "server-private-diagnostic") || strings.Contains(summary.Details, "SELECT ") {
				t.Fatal("coverage summary exposed raw server diagnostics or SQL")
			}
		})
	}
}

func TestDatabaseConnectionFailureStopsRetriesAndNamesCause(t *testing.T) {
	for _, tc := range []struct {
		name, class string
		err         error
	}{
		{"authentication", "authentication", &mysql.MySQLError{Number: 1045, Message: "server-private-diagnostic"}},
		{"missing database", "database_missing", &mysql.MySQLError{Number: 1049, Message: "server-private-diagnostic"}},
		{"connection", "connection", driver.ErrBadConn},
		{"disconnected", "connection", io.EOF},
		{"refused connection", "connection", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
		{"connection limit", "resource", &mysql.MySQLError{Number: 1040, Message: "server-private-diagnostic"}},
		{"unknown failure", "unknown", errors.New("server-private-diagnostic")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDatabaseCoverageInstalls(t, map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("fixture"),
			}, nil)
			calls := 0
			mysqlclient.SetPerAccountQueryForTest(func(context.Context, mysqlclient.Creds, string, ...any) ([]string, error) {
				calls++
				return nil, tc.err
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			ctx, _ := withIncompleteCheckCollector(context.Background())
			summary := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
			if calls != 1 {
				t.Fatalf("unavailable database queried %d times, want one attempt", calls)
			}
			for _, want := range []string{"stage=options", "class=" + tc.class} {
				if !strings.Contains(summary.Details, want) {
					t.Errorf("coverage summary omits %q: %s", want, summary.Details)
				}
			}
			if strings.Contains(summary.Details, "server-private-diagnostic") {
				t.Fatal("coverage summary exposed raw server diagnostics")
			}
		})
	}
}

func TestHiddenLinkTimeoutKeepsAdminChecks(t *testing.T) {
	withDatabaseCoverageInstalls(t, map[string]string{
		"/home/alice/public_html/wp-config.php": databaseCoverageConfig("fixture"),
	}, nil)
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		if strings.Contains(query, "'site' AS kind") {
			return nil, &mysql.MySQLError{Number: 3699, Message: "server-private-diagnostic"}
		}
		if strings.Contains(query, "SELECT u.ID, u.user_login") {
			return []string{"9\tunexpected\tadmin@example.com\tNULL\tNULL"}, nil
		}
		return databaseCoverageHealthyRows(query), nil
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckDatabaseContent(ctx, nil, nil)
	found := false
	for _, f := range findings {
		found = found || f.Check == "db_rogue_admin"
	}
	if !found {
		t.Fatal("hidden-link timeout suppressed the later admin detection")
	}
	if !incomplete.contains("db_content") {
		t.Fatal("hidden-link timeout lost its coverage gap")
	}
	summary := databaseCoverageSummary(t, findings)
	for _, want := range []string{"query_failed=1", "stage=hidden_links class=timeout code=3699"} {
		if !strings.Contains(summary.Details, want) {
			t.Errorf("coverage summary omits %q: %s", want, summary.Details)
		}
	}
}

// Host-wide diagnostics must remain bounded even when every install returns
// a different server error, without dropping the total failed-query count.
func TestDatabaseQueryDiagnosticsBoundedAcrossInstalls(t *testing.T) {
	bodies := make(map[string]string)
	for i := range 100 {
		bodies[fmt.Sprintf("/home/account%d/public_html/wp-config.php", i)] = databaseCoverageConfig(fmt.Sprintf("fixture%d", i))
	}
	withDatabaseCoverageInstalls(t, bodies, nil)
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, creds mysqlclient.Creds, _ string, _ ...any) ([]string, error) {
		i, err := strconv.Atoi(strings.TrimPrefix(creds.DBName, "fixture"))
		if err != nil {
			t.Fatal(err)
		}
		return nil, &mysql.MySQLError{Number: uint16(2000 + i), Message: "server-private-diagnostic"}
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
	ctx, _ := withIncompleteCheckCollector(context.Background())
	summary := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
	if len(summary.Details) > 4096 {
		t.Fatalf("diagnostic grew with every distinct error: %d bytes", len(summary.Details))
	}
	total := 0
	for _, match := range regexp.MustCompile(`queries=(\d+)`).FindAllStringSubmatch(summary.Details, -1) {
		n, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total != 100 {
		t.Fatalf("reported query failures = %d, want 100", total)
	}
}
