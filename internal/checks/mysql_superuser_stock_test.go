package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

// The primary audit must retain the account until its authentication is
// verified. A familiar username and host alone do not identify a stock user.
func TestCheckMySQLUsersVerifiesStockMariaDBAccount(t *testing.T) {
	for _, tc := range []struct {
		name      string
		verified  []string
		err       error
		wantLocal bool
	}{
		{name: "stock socket account", verified: []string{"1"}},
		{name: "custom authentication", wantLocal: true},
		{name: "MySQL without global_priv", err: errors.New("table does not exist"), wantLocal: true},
		{name: "verification failed", err: context.DeadlineExceeded, wantLocal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := []string{"mysql\tlocalhost", "mysql\t127.0.0.1", "mysql\t::1", "mysql\t%", "mysql\tlocalhost.example", "rogue\tlocalhost"}
			var verified bool
			mysqlclient.SetRootQueryForTest(func(_ context.Context, _ string, query string, _ ...any) ([]string, error) {
				if strings.Contains(query, "FROM mysql.user") {
					if strings.Contains(query, "user='mysql'") {
						t.Error("primary query hides mysql before authentication can be verified")
						return rows[1:], nil
					}
					return append([]string(nil), rows...), nil
				}
				if !strings.Contains(query, "FROM mysql.global_priv") {
					t.Fatalf("unexpected query: %s", query)
				}
				verified = true
				return tc.verified, tc.err
			})
			t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			findings := CheckMySQLUsers(context.Background(), nil, st)
			if !verified {
				t.Error("stock account authentication was never checked")
			}
			if len(findings) != 1 || findings[0].Check != "mysql_superuser" || findings[0].Severity != alert.High {
				t.Fatalf("unexpected findings: %+v", findings)
			}
			details := findings[0].Details
			if got := strings.Contains(details+"\n", "mysql\tlocalhost\n"); got != tc.wantLocal {
				t.Errorf("local mysql account reported = %v, want %v", got, tc.wantLocal)
			}
			for _, row := range rows[1:] {
				if !strings.Contains(details+"\n", row+"\n") {
					t.Errorf("non-stock privileged account %q was hidden", row)
				}
			}
		})
	}
}
