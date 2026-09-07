package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

// MariaDB 10.4+ ships a stock mysql@localhost account holding SUPER, used for
// unix_socket authentication of the local root shell. It is present on every
// MariaDB host, so flagging it makes the check fire a permanent HIGH finding
// that no operator can resolve without dropping a system account.
//
// The exclusion is deliberately scoped to the user and host together: an
// attacker who creates mysql@'%' must still be reported, so excluding on the
// username alone would open a hiding place.
func TestCheckMySQLUsersExcludesStockMariaDBAccount(t *testing.T) {
	var gotQuery string
	mysqlclient.SetRootQueryForTest(func(_ context.Context, _ string, query string, _ ...any) ([]string, error) {
		gotQuery = query
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	CheckMySQLUsers(context.Background(), nil, st)

	if gotQuery == "" {
		t.Fatal("CheckMySQLUsers issued no query")
	}
	normalized := strings.Join(strings.Fields(gotQuery), " ")

	if !strings.Contains(normalized, "user='mysql'") || !strings.Contains(normalized, "host='localhost'") {
		t.Errorf("query does not exclude the stock mysql@localhost account: %s", normalized)
	}
	// Excluding the bare username would let mysql@'%' hide.
	if strings.Contains(normalized, "'root','mysql',") || strings.Contains(normalized, ",'mysql',") {
		t.Errorf("query excludes the mysql username outright; scope it to host localhost: %s", normalized)
	}
}
