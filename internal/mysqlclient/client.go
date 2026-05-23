// Package mysqlclient wraps the database/sql + go-sql-driver/mysql
// pair for the read-only queries CSM issues against host-local
// MySQL/MariaDB. It replaces the per-call `mysql -e <query>`
// shell-outs across CMS DB scans, performance metrics, and forensic
// dumps so the daemon no longer forks and tears down a child process
// (plus its libc/libmariadbclient relocations) every query.
//
// Two cred modes are supported:
//
//   - Root: implicit, mirrors the historical `mysql` CLI behaviour
//     that reads /root/.my.cnf [client] section. RootDB parses that
//     file and returns a *sql.DB pointed at unix-socket auth.
//
//   - Per-account: the caller passes explicit user / password / host
//     / dbname / port / socket via DSN. PerAccountQuery opens,
//     runs, closes.
//
// Output shape mirrors the previous `mysql -N -B -e` shell-out: rows
// are returned as []string where each entry is the tab-joined column
// values of one result row, with leading/trailing whitespace already
// trimmed. Existing scanner code paths consume this format unchanged.
package mysqlclient

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

// queryTimeout caps a single SELECT to a defensive 30 s -- well under
// the legacy 2 min CLI cmdTimeout but enough for any realistic CMS
// scan / SHOW STATUS / SHOW PROCESSLIST result.
const queryTimeout = 30 * time.Second

// Creds carries per-account database credentials. Mirrors wpDBCreds in
// internal/checks so callers can pass the same shape without an extra
// adapter type.
type Creds struct {
	User     string
	Password string
	Host     string
	Port     int
	Socket   string
	DBName   string
}

// dsn returns a go-sql-driver/mysql connection string. Empty Host
// falls back to the Unix socket path the mysql CLI uses on cPanel
// hosts; this matches the historical default when -h was omitted.
func (c Creds) dsn() string {
	cfg := mysql.NewConfig()
	cfg.User = c.User
	cfg.Passwd = c.Password
	cfg.DBName = c.DBName
	// Read timeouts mirror queryTimeout's budget.
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = queryTimeout
	cfg.WriteTimeout = 5 * time.Second
	cfg.Loc = time.Local

	cfg.Net, cfg.Addr = c.networkAddr()
	return cfg.FormatDSN()
}

func (c Creds) networkAddr() (string, string) {
	host := strings.TrimSpace(c.Host)
	socket := strings.TrimSpace(c.Socket)
	if socket != "" && (host == "" || host == "localhost") {
		return "unix", socket
	}
	if strings.HasPrefix(host, "/") {
		return "unix", host
	}
	if _, socket, ok := splitHostSocket(host); ok {
		return "unix", socket
	}
	if host == "" || host == "localhost" {
		return "unix", defaultUnixSocket()
	}

	host, port := splitHostPort(host, c.Port)
	return "tcp", net.JoinHostPort(host, strconv.Itoa(port))
}

func splitHostSocket(host string) (string, string, bool) {
	idx := strings.LastIndex(host, ":/")
	if idx < 0 || idx == len(host)-1 {
		return "", "", false
	}
	return host[:idx], host[idx+1:], true
}

func splitHostPort(host string, fallbackPort int) (string, int) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if port, perr := strconv.Atoi(p); perr == nil {
			return trimIPv6Brackets(h), port
		}
	}
	if strings.Count(host, ":") == 1 {
		h, p, _ := strings.Cut(host, ":")
		if port, err := strconv.Atoi(p); err == nil {
			return h, port
		}
	}
	if fallbackPort == 0 {
		fallbackPort = 3306
	}
	return trimIPv6Brackets(host), fallbackPort
}

func trimIPv6Brackets(host string) string {
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

// defaultUnixSocket returns the first known mysql socket path that
// exists on disk, falling back to the cPanel canonical location.
func defaultUnixSocket() string {
	candidates := []string{
		"/var/lib/mysql/mysql.sock",
		"/tmp/mysql.sock",
		"/var/run/mysqld/mysqld.sock",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/var/lib/mysql/mysql.sock"
}

// PerAccountQuery opens a short-lived connection with the supplied
// credentials, runs the query, and returns each row as a tab-joined
// string. Empty result set returns (nil, nil). Errors include open,
// query, and scan failures.
//
// Tests can intercept via SetPerAccountQueryForTest.
func PerAccountQuery(ctx context.Context, creds Creds, query string, args ...any) ([]string, error) {
	if fn := getPerAccountQueryMock(); fn != nil {
		return fn(ctx, creds, query, args...)
	}
	db, err := sql.Open("mysql", creds.dsn())
	if err != nil {
		return nil, fmt.Errorf("mysqlclient: open: %w", err)
	}
	defer func() { _ = db.Close() }()
	// Single short-lived call: cap idle pool to avoid leaking
	// connections on per-account scans across many tenants.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	db.SetConnMaxLifetime(queryTimeout)

	return runQuery(ctx, db, query, args...)
}

// PerAccountQueryFunc is the signature SetPerAccountQueryForTest accepts.
type PerAccountQueryFunc func(ctx context.Context, creds Creds, query string, args ...any) ([]string, error)

var (
	perAccountMockMu sync.RWMutex
	perAccountMock   PerAccountQueryFunc
)

// SetPerAccountQueryForTest installs an interceptor for
// PerAccountQuery. Pass nil to clear and restore the real database/sql
// path. Production code paths must NOT call this.
func SetPerAccountQueryForTest(fn PerAccountQueryFunc) {
	perAccountMockMu.Lock()
	defer perAccountMockMu.Unlock()
	perAccountMock = fn
}

func getPerAccountQueryMock() PerAccountQueryFunc {
	perAccountMockMu.RLock()
	defer perAccountMockMu.RUnlock()
	return perAccountMock
}

// runQuery is the shared execution path for any *sql.DB. Internal so
// the package can grow a RootDB-backed singleton later without
// duplicating the row-iteration code.
func runQuery(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	rows, err := db.QueryContext(cctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mysqlclient: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("mysqlclient: columns: %w", err)
	}
	out := make([]string, 0)
	raw := make([]sql.NullString, len(cols))
	scanArgs := make([]any, len(cols))
	for i := range raw {
		scanArgs[i] = &raw[i]
	}
	for rows.Next() {
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("mysqlclient: scan: %w", err)
		}
		parts := make([]string, len(cols))
		for i, v := range raw {
			if v.Valid {
				parts[i] = v.String
			} else {
				// `mysql -N -B` prints NULL for SQL NULL; preserve
				// that so legacy parsers that key off the literal
				// see the same bytes.
				parts[i] = "NULL"
			}
		}
		out = append(out, strings.Join(parts, "\t"))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysqlclient: iterate: %w", err)
	}
	return out, nil
}

// --- Root creds via /root/.my.cnf ---------------------------------------

var (
	rootMu   sync.Mutex
	rootDB   *sql.DB
	rootPath = "/root/.my.cnf"
)

// SetRootCnfPath overrides the [client] config path before the first
// RootDB() call. Tests set this to a tempdir-rooted .my.cnf.
func SetRootCnfPath(p string) {
	rootMu.Lock()
	defer rootMu.Unlock()
	rootPath = p
	// Drop any cached DB so the next RootDB() rebuilds from the new path.
	if rootDB != nil {
		_ = rootDB.Close()
		rootDB = nil
	}
}

// RootQuery runs a query as root using the credentials in
// /root/.my.cnf (or the path set via SetRootCnfPath). It mirrors the
// historical `mysql -N -B -e <query>` invocation that picked up
// /root/.my.cnf implicitly. The connection is pooled across calls.
func RootQuery(ctx context.Context, query string, args ...any) ([]string, error) {
	db, err := RootDB()
	if err != nil {
		return nil, err
	}
	return runQuery(ctx, db, query, args...)
}

// RootDB returns the pooled root MySQL handle backed by /root/.my.cnf
// (or the path set via SetRootCnfPath). sql.Open does not contact the
// server until the first query.
func RootDB() (*sql.DB, error) {
	return rootSingleton()
}

// RootQuerySchema runs a query against an explicit schema using root
// creds. Mirrors `mysql <schema> -e <query>`.
func RootQuerySchema(ctx context.Context, schema, query string, args ...any) ([]string, error) {
	creds, err := loadRootCreds()
	if err != nil {
		return nil, err
	}
	creds.DBName = schema
	return PerAccountQuery(ctx, creds, query, args...)
}

func rootSingleton() (*sql.DB, error) {
	rootMu.Lock()
	if rootDB != nil {
		defer rootMu.Unlock()
		return rootDB, nil
	}
	rootMu.Unlock()

	creds, err := loadRootCreds()
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", creds.dsn())
	if err != nil {
		return nil, fmt.Errorf("mysqlclient: root open: %w", err)
	}
	// Conservative pool: root scans run at most a few queries per
	// minute, sharing one idle connection is plenty.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	rootMu.Lock()
	defer rootMu.Unlock()
	if rootDB != nil {
		_ = db.Close()
		return rootDB, nil
	}
	rootDB = db
	return rootDB, nil
}

// loadRootCreds parses /root/.my.cnf's [client] section (or the
// path set via SetRootCnfPath). The format is the same INI subset
// mysql_config_editor / the official client honour: section header
// in `[client]`, key=value pairs (values may be unquoted, single
// quoted, or double quoted; matching quote is stripped).
//
// Returns an error if the file is missing or the [client] section
// has no user. Empty password is allowed (socket-auth setups).
func loadRootCreds() (Creds, error) {
	rootMu.Lock()
	path := rootPath
	rootMu.Unlock()

	// #nosec G304 -- path is operator-configured at init time, not
	// attacker-controlled.
	f, err := os.Open(path)
	if err != nil {
		return Creds{}, fmt.Errorf("mysqlclient: open %s: %w", path, err)
	}
	defer f.Close()

	creds := Creds{}
	inClient := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inClient = strings.EqualFold(line, "[client]") || strings.EqualFold(line, "[mysql]")
			continue
		}
		if !inClient {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = unquote(strings.TrimSpace(val))
		switch strings.ToLower(key) {
		case "user":
			creds.User = val
		case "password", "pass":
			creds.Password = val
		case "host":
			creds.Host = val
		case "port":
			if p, perr := strconv.Atoi(val); perr == nil {
				creds.Port = p
			}
		case "socket":
			creds.Socket = val
		}
	}
	if err := scanner.Err(); err != nil {
		return Creds{}, fmt.Errorf("mysqlclient: read %s: %w", path, err)
	}
	if creds.User == "" {
		return Creds{}, errors.New("mysqlclient: [client] section missing 'user' key")
	}
	return creds, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
