package mysqlclient

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func resetRootForTest(t *testing.T) {
	t.Helper()
	rootMu.Lock()
	if rootDB != nil {
		_ = rootDB.Close()
	}
	rootDB = nil
	rootPath = "/root/.my.cnf"
	rootMu.Unlock()
	t.Cleanup(func() {
		rootMu.Lock()
		if rootDB != nil {
			_ = rootDB.Close()
		}
		rootDB = nil
		rootPath = "/root/.my.cnf"
		rootMu.Unlock()
	})
}

func parsedDSN(t *testing.T, creds Creds) *mysql.Config {
	t.Helper()
	cfg, err := mysql.ParseDSN(creds.dsn())
	if err != nil {
		t.Fatalf("ParseDSN(%q): %v", creds.dsn(), err)
	}
	return cfg
}

func TestCredsDSNParsesWordPressPortHost(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:3307":  "127.0.0.1:3307",
		"localhost:3307":  "localhost:3307",
		"db.example:3308": "db.example:3308",
	}
	for host, wantAddr := range tests {
		cfg := parsedDSN(t, Creds{
			User:     "u",
			Password: "p",
			Host:     host,
			DBName:   "wp",
		})
		if cfg.Net != "tcp" {
			t.Fatalf("host %q network = %q, want tcp", host, cfg.Net)
		}
		if cfg.Addr != wantAddr {
			t.Fatalf("host %q addr = %q, want %s", host, cfg.Addr, wantAddr)
		}
	}
}

func TestCredsDSNParsesUnixSocketHost(t *testing.T) {
	for _, host := range []string{"/tmp/mysql.sock", "localhost:/tmp/mysql.sock", "localhost:3306:/tmp/mysql.sock"} {
		cfg := parsedDSN(t, Creds{
			User:     "u",
			Password: "p",
			Host:     host,
			DBName:   "wp",
		})
		if cfg.Net != "unix" {
			t.Fatalf("host %q network = %q, want unix", host, cfg.Net)
		}
		if cfg.Addr != "/tmp/mysql.sock" {
			t.Fatalf("host %q addr = %q, want /tmp/mysql.sock", host, cfg.Addr)
		}
	}
}

func TestLoadRootCredsHonorsSocket(t *testing.T) {
	resetRootForTest(t)
	path := filepath.Join(t.TempDir(), ".my.cnf")
	writeRootCnf(t, path, "[client]\nuser=root\npassword='secret'\nsocket=/tmp/custom-mysql.sock\n")
	SetRootCnfPath(path)

	creds, err := loadRootCreds()
	if err != nil {
		t.Fatalf("loadRootCreds: %v", err)
	}
	cfg := parsedDSN(t, creds)
	if cfg.Net != "unix" {
		t.Fatalf("network = %q, want unix", cfg.Net)
	}
	if cfg.Addr != "/tmp/custom-mysql.sock" {
		t.Fatalf("addr = %q, want /tmp/custom-mysql.sock", cfg.Addr)
	}
}

func TestLoadRootCredsFallsBackToRootWhenConfigMissing(t *testing.T) {
	resetRootForTest(t)
	SetRootCnfPath(filepath.Join(t.TempDir(), "missing.cnf"))

	creds, err := loadRootCreds()
	if err != nil {
		t.Fatalf("loadRootCreds: %v", err)
	}
	if creds.User != "root" {
		t.Fatalf("user = %q, want root", creds.User)
	}
	if creds.Password != "" {
		t.Fatalf("password = %q, want empty", creds.Password)
	}
}

func TestLoadRootCredsKeepsRootDefaultWhenUserOmitted(t *testing.T) {
	resetRootForTest(t)
	path := filepath.Join(t.TempDir(), ".my.cnf")
	writeRootCnf(t, path, "[client]\npassword='secret'\nsocket=/tmp/custom-mysql.sock\n")
	SetRootCnfPath(path)

	creds, err := loadRootCreds()
	if err != nil {
		t.Fatalf("loadRootCreds: %v", err)
	}
	if creds.User != "root" {
		t.Fatalf("user = %q, want root", creds.User)
	}
	if creds.Password != "secret" {
		t.Fatalf("password = %q, want secret", creds.Password)
	}
}

func TestRunQueryEscapesLikeMySQLBatchMode(t *testing.T) {
	db := openBatchDB(t, [][]driver.Value{{
		"line\nbreak\tback\\slash\rcarriage\x00nul",
		nil,
	}})
	defer func() { _ = db.Close() }()

	rows, err := runQuery(context.Background(), db, "SELECT value")
	if err != nil {
		t.Fatalf("runQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want one row", rows)
	}
	want := "line\\nbreak\\tback\\\\slash\\rcarriage\\0nul\tNULL"
	if rows[0] != want {
		t.Fatalf("row = %q, want %q", rows[0], want)
	}
}

func TestRootSingletonDoesNotDeadlockLoadingCreds(t *testing.T) {
	resetRootForTest(t)
	path := filepath.Join(t.TempDir(), ".my.cnf")
	writeRootCnf(t, path, "[client]\nuser=root\npassword=secret\n")
	SetRootCnfPath(path)

	done := make(chan error, 1)
	go func() {
		_, err := RootDB()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rootSingleton: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("rootSingleton deadlocked while loading root credentials")
	}
}

func writeRootCnf(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	batchDriverOnce sync.Once
	batchDriverMu   sync.Mutex
	batchDriverRows [][]driver.Value
)

func openBatchDB(t *testing.T, rows [][]driver.Value) *sql.DB {
	t.Helper()
	batchDriverOnce.Do(func() {
		sql.Register("csm_mysqlclient_batch_test", batchDriver{})
	})
	batchDriverMu.Lock()
	batchDriverRows = cloneDriverRows(rows)
	batchDriverMu.Unlock()

	db, err := sql.Open("csm_mysqlclient_batch_test", "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	return db
}

func cloneDriverRows(rows [][]driver.Value) [][]driver.Value {
	out := make([][]driver.Value, len(rows))
	for i := range rows {
		out[i] = append([]driver.Value(nil), rows[i]...)
	}
	return out
}

type batchDriver struct{}

func (batchDriver) Open(string) (driver.Conn, error) {
	return batchConn{}, nil
}

type batchConn struct{}

func (batchConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}

func (batchConn) Close() error {
	return nil
}

func (batchConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}

func (batchConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	batchDriverMu.Lock()
	rows := cloneDriverRows(batchDriverRows)
	batchDriverMu.Unlock()
	cols := make([]string, 0)
	if len(rows) > 0 {
		cols = make([]string, len(rows[0]))
		for i := range cols {
			cols[i] = "c"
		}
	}
	return &batchRows{cols: cols, rows: rows}, nil
}

type batchRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *batchRows) Columns() []string {
	return r.cols
}

func (r *batchRows) Close() error {
	return nil
}

func (r *batchRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}
