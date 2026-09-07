//go:build mysqlintegration

package checks

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Run against a disposable MariaDB server with CSM_TEST_MYSQL_SOCKET set.
// A connection-local table isolates the fixtures from real grant tables.
func TestStockMariaDBAccountQuery(t *testing.T) {
	socket := os.Getenv("CSM_TEST_MYSQL_SOCKET")
	if socket == "" {
		t.Fatal("CSM_TEST_MYSQL_SOCKET is required")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Net, cfg.Addr = "root", "unix", socket
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "CREATE TEMPORARY TABLE mysql.global_priv (Host varchar(255), User varchar(128), Priv longtext)"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, user, host, plugin, auth, alternatives string
		want                                         bool
	}{
		{"stock", "mysql", "localhost", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket"}]`, true},
		{"password enabled", "mysql", "localhost", "mysql_native_password", "changed", `[{}, {"plugin": "unix_socket"}]`, false},
		{"empty password", "mysql", "localhost", "mysql_native_password", "", `[{}, {"plugin": "unix_socket"}]`, false},
		{"other plugin", "mysql", "localhost", "pam", "invalid", `[{}, {"plugin": "unix_socket"}]`, false},
		{"extra auth", "mysql", "localhost", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket"}, {"plugin": "pam"}]`, false},
		{"socket identity mapping", "mysql", "localhost", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket", "authentication_string": "other"}]`, false},
		{"IPv4", "mysql", "127.0.0.1", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket"}]`, false},
		{"IPv6", "mysql", "::1", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket"}]`, false},
		{"wildcard", "mysql", "%", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket"}]`, false},
		{"different user", "other", "localhost", "mysql_native_password", "invalid", `[{}, {"plugin": "unix_socket"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := conn.ExecContext(ctx, "DELETE FROM mysql.global_priv"); err != nil {
				t.Fatal(err)
			}
			priv, err := json.Marshal(map[string]any{"plugin": tc.plugin, "authentication_string": tc.auth, "auth_or": json.RawMessage(tc.alternatives)})
			if err != nil {
				t.Fatal(err)
			}
			if _, insertErr := conn.ExecContext(ctx, "INSERT INTO mysql.global_priv VALUES (?, ?, ?)", tc.host, tc.user, string(priv)); insertErr != nil {
				t.Fatal(insertErr)
			}
			var match int
			err = conn.QueryRowContext(ctx, stockMariaDBAccountQuery).Scan(&match)
			if tc.want {
				if err != nil || match != 1 {
					t.Fatalf("stock account: match=%d err=%v", match, err)
				}
			} else if err != sql.ErrNoRows {
				t.Fatalf("non-stock account: match=%d err=%v; want no rows", match, err)
			}
		})
	}
}
