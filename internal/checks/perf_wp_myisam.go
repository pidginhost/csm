package checks

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/state"
)

// wpMyISAMQuery lists every MyISAM table on the server in one catalogue read.
// It carries no tenant-supplied names; installs are matched in Go.
const wpMyISAMQuery = "SELECT TABLE_SCHEMA, TABLE_NAME, COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0) " +
	"FROM information_schema.TABLES WHERE ENGINE = 'MyISAM' AND TABLE_TYPE = 'BASE TABLE'"

const wpMyISAMListedTables = 10

type wpMyISAMTable struct {
	name  string
	bytes int64
}

// wpMyISAMScope is one set of WordPress tables: a database and table prefix,
// with every install configured to use it.
type wpMyISAMScope struct {
	schema   string
	prefix   string
	installs []wpInstall
	tables   []wpMyISAMTable
}

// CheckWPMyISAM reports WordPress installs whose tables still use MyISAM.
// MyISAM locks the whole table for every write, so a burst of uncached
// requests queues behind those locks until it holds every database connection
// the account may open; InnoDB locks rows instead.
// The runner enforces a 60-minute throttle via checkThrottleMin.
func CheckWPMyISAM(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}

	scopes := make(map[string]*wpMyISAMScope)
	prefixesBySchema := make(map[string][]string)
	for _, in := range wpInstalls(ctx, "perf_wp_myisam") {
		if ctx.Err() != nil {
			return nil
		}
		creds, complete := parseWPConfigChecked(in.ConfigPath)
		if !complete {
			markCheckIncomplete(ctx, "perf_wp_myisam")
			continue
		}
		prefix, ok := resolveTablePrefix(creds)
		if !ok || creds.dbName == "" || !wpDBHostIsLocal(creds.dbHost) {
			continue
		}
		// Every readable install claims its prefix, reported or not, so a
		// table is never attributed to a sibling with a shorter prefix.
		key := creds.dbName + "\x00" + prefix
		scope, seen := scopes[key]
		if !seen {
			scope = &wpMyISAMScope{schema: creds.dbName, prefix: prefix}
			scopes[key] = scope
			prefixesBySchema[creds.dbName] = append(prefixesBySchema[creds.dbName], prefix)
		}
		scope.installs = append(scope.installs, in)
	}
	if len(scopes) == 0 {
		return nil
	}

	rows, err := mysqlclient.RootQuery(ctx, wpMyISAMQuery)
	if err != nil {
		markCheckIncomplete(ctx, "perf_wp_myisam")
		return nil
	}
	for _, line := range rows {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			continue
		}
		schema := mysqlclient.BatchUnescape(fields[0])
		table := mysqlclient.BatchUnescape(fields[1])
		owner := ""
		for _, prefix := range prefixesBySchema[schema] {
			if strings.HasPrefix(table, prefix) && len(prefix) > len(owner) {
				owner = prefix
			}
		}
		if owner == "" {
			continue
		}
		size, _ := strconv.ParseInt(fields[2], 10, 64)
		scope := scopes[schema+"\x00"+owner]
		scope.tables = append(scope.tables, wpMyISAMTable{name: table, bytes: size})
	}

	var findings []alert.Finding
	for _, scope := range scopes {
		if len(scope.tables) == 0 {
			continue
		}
		if in, ok := wpMyISAMReportedInstall(scope.installs); ok {
			findings = append(findings, newWPMyISAMFinding(scope, in))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Details < findings[j].Details })
	return findings
}

// wpMyISAMReportedInstall picks the install a finding names. A dormant root
// and a suspended account serve no traffic, so their tables cannot queue
// requests; the same tables used by a live root are still reported.
func wpMyISAMReportedInstall(installs []wpInstall) (wpInstall, bool) {
	var live []wpInstall
	for _, in := range installs {
		if in.Served == notServed || accountSuspended(in.Account) {
			continue
		}
		live = append(live, in)
	}
	if len(live) == 0 {
		return wpInstall{}, false
	}
	sort.Slice(live, func(i, j int) bool { return live[i].ConfigPath < live[j].ConfigPath })
	return live[0], true
}

func newWPMyISAMFinding(scope *wpMyISAMScope, in wpInstall) alert.Finding {
	tables := scope.tables
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].bytes != tables[j].bytes {
			return tables[i].bytes > tables[j].bytes
		}
		return tables[i].name < tables[j].name
	})
	var total int64
	names := make([]string, 0, wpMyISAMListedTables)
	for i, t := range tables {
		total += t.bytes
		if i < wpMyISAMListedTables {
			names = append(names, t.name)
		}
	}
	list := strings.Join(names, ", ")
	if more := len(tables) - len(names); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	owner := in.Account
	if owner == "" {
		owner = in.DocRoot
	}
	return alert.Finding{
		Severity: alert.Warning,
		Check:    "perf_wp_myisam",
		Message:  fmt.Sprintf("WordPress tables use MyISAM for %s", owner),
		Details: fmt.Sprintf(
			"Database: %s, prefix: %s, MyISAM tables: %d (%s): %s. File: %s - "+
				"convert them to InnoDB after a backup; MyISAM locks the whole table on every write",
			scope.schema, scope.prefix, len(tables), humanBytes(total), list, in.ConfigPath,
		),
		// Sizes change on every scan; the identity is the set of tables.
		DedupKey:  fmt.Sprintf("db=%q prefix=%q", scope.schema, scope.prefix),
		Timestamp: time.Now(),
	}
}

// wpDBHostIsLocal reports whether a wp-config.php DB_HOST names this server.
// WordPress accepts host, host:port and host:/socket. The catalogue read only
// sees the local server, where a schema with the same name as a remote
// database is a different database, often a copy left behind by a migration.
func wpDBHostIsLocal(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	switch {
	case strings.HasPrefix(h, "["):
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return false
		}
		h = h[1:end]
	case strings.Count(h, ":") == 1:
		h = h[:strings.IndexByte(h, ':')]
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
