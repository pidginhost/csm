package checks

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"github.com/go-sql-driver/mysql"
)

const maxDatabaseQueryDiagnostics = 16

// dbQueryState separates incomplete coverage from an unusable connection.
// Both prevent a clean baseline, but a statement-local failure must not stop
// independent detectors from reading other tables in the same installation.
type dbQueryState struct {
	failed   bool
	halted   bool
	failures map[string]int
}

func (c wpDBCreds) withQueryStage(stage string) wpDBCreds {
	c.queryStage = stage
	return c
}

func (s *dbQueryState) record(stage string, err error) {
	if s == nil {
		return
	}
	class, code, halt := databaseQueryErrorClass(err)
	s.failed = true
	s.halted = s.halted || halt
	if stage == "" {
		stage = "query"
	}
	if s.failures == nil {
		s.failures = make(map[string]int)
	}
	// Only a code-defined stage, class and numeric error code leave the query
	// boundary. Server messages and SQL can contain account data or values.
	key := fmt.Sprintf("stage=%s class=%s code=%d", stage, class, code)
	s.failures[key]++
}

func databaseQueryErrorClass(err error) (class string, code uint16, halt bool) {
	var sqlErr *mysql.MySQLError
	if errors.As(err, &sqlErr) {
		code = sqlErr.Number
		switch code {
		case 1054, 1146:
			return "schema", code, false
		case 1064:
			return "syntax", code, false
		case 1142, 1143:
			return "permission", code, false
		case 1139, 1267, 1271:
			return "expression", code, false
		case 3699:
			// ICU stops this expression when its work budget is exhausted;
			// the connection and independent statements remain usable.
			return "timeout", code, false
		case 1044, 1045:
			return "authentication", code, true
		case 1049:
			return "database_missing", code, true
		case 1040, 1203, 1226:
			return "resource", code, true
		}
	}
	// Unknown failures keep the existing stop behavior. Continuing is safe
	// only when the server identified a failure confined to this statement.
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", code, true
	}
	if errors.Is(err, context.Canceled) {
		return "canceled", code, true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout", code, true
		}
		return "connection", code, true
	}
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, mysql.ErrInvalidConn) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "connection", code, true
	}
	return "unknown", code, true
}

func (c *dbScanCoverage) recordQueryFailures(state *dbQueryState) {
	if state == nil || len(state.failures) == 0 {
		return
	}
	if c.queryFailures == nil {
		c.queryFailures = make(map[string]int)
	}
	keys := make([]string, 0, len(state.failures))
	for key := range state.failures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := state.failures[key]
		if c.queryFailures[key] == 0 && len(c.queryFailures) >= maxDatabaseQueryDiagnostics {
			c.queryFailureOverflow += count
			continue
		}
		c.queryFailures[key] += count
	}
}

func (c *dbScanCoverage) queryFailureSummary() string {
	keys := make([]string, 0, len(c.queryFailures))
	for key := range c.queryFailures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&b, "Query failures: %s queries=%d\n", key, c.queryFailures[key])
	}
	if c.queryFailureOverflow > 0 {
		fmt.Fprintf(&b, "Other query failures: queries=%d\n", c.queryFailureOverflow)
	}
	return b.String()
}
