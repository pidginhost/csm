package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/forensic"
)

// runForensicSnapshot wires the production I/O dependencies into the
// reusable internal/forensic.Snapshot type.
//
// Usage: csm forensic-snapshot <account> --out <archive.tar.gz>
//
// The output path is required -- there is no default. Snapshot writes
// the archive plus a `<out>.sha256` sidecar.
func runForensicSnapshot() {
	args := os.Args[2:]
	account := ""
	out := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--out", "-o":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "csm forensic-snapshot: --out requires a value")
				os.Exit(2)
			}
			out = args[i+1]
			i++
		case "--help", "-h":
			printForensicUsage()
			return
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "csm forensic-snapshot: unknown flag %q\n", a)
				os.Exit(2)
			}
			if account != "" {
				fmt.Fprintln(os.Stderr, "csm forensic-snapshot: only one account name accepted")
				os.Exit(2)
			}
			account = a
		}
	}
	if account == "" || out == "" {
		printForensicUsage()
		os.Exit(2)
	}
	if !forensic.AccountNameValid(account) {
		fmt.Fprintf(os.Stderr, "csm forensic-snapshot: invalid account name: %q\n", account)
		os.Exit(1)
	}
	if err := forensic.ValidateOutPath(account, out); err != nil {
		fmt.Fprintf(os.Stderr, "csm forensic-snapshot: %v\n", err)
		os.Exit(1)
	}

	targets, audit := discoverForensicTargetsWithAudit(account)
	snap := forensic.Snapshot{
		Account:        account,
		OutPath:        out,
		Timestamp:      time.Now().UTC(),
		DiscoveryAudit: audit,
		Sources: forensic.Sources{
			DiscoverTargets: func(string) []forensic.SchemaTarget { return targets },
			DumpSchema:      mysqldumpSchema,
			ListAdmins:      listForensicAdmins,
			ListSessions:    listForensicSessions,
			ListRecentFiles: listRecentMtimes,
		},
	}

	archivePath, sha, err := snap.Write()
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm forensic-snapshot: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Snapshot: %s\nSHA256:   %s\n", archivePath, sha)
}

func printForensicUsage() {
	fmt.Fprint(os.Stderr, `Usage: csm forensic-snapshot <account> --out <archive.tar.gz>

Bundles incident-response evidence for one cPanel account into a single
tar+gzip archive: MySQL trigger/event/routine definitions per schema,
the administrator user roster, active session metadata, and the
last-7-days file mtime list under the account's document roots.

The archive does NOT include credentials -- password rotation belongs
to a separate runbook step.

Flags:
  --out, -o   Required. Destination path for the archive.

`)
}

// discoverForensicTargets walks /home/<account> for wp-config.php files and
// extracts the DB_NAME and $table_prefix pair from each file. Used in
// production wiring; tests inject a fixed slice.
func discoverForensicTargetsWithAudit(account string) ([]forensic.SchemaTarget, forensic.DiscoveryAudit) {
	return discoverForensicTargetsInRootWithAudit("/home/" + account)
}

func discoverForensicTargetsInRootWithAudit(accountRoot string) ([]forensic.SchemaTarget, forensic.DiscoveryAudit) {
	var matches []string
	audit := forensic.DiscoveryAudit{
		AccountRoot:          accountRoot,
		PrivatePathsExcluded: true,
		PrivateTopPaths:      forensicPrivateTopPaths(),
	}
	// #nosec G703 -- production callers build accountRoot as /home/<validated cPanel account>; tests pass t.TempDir.
	_ = filepath.WalkDir(accountRoot, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // skip unreadable account paths without aborting the snapshot.
		}
		if entry.IsDir() {
			if p != accountRoot && forensicSkipPrivatePath(accountRoot, p) {
				if forensicPathDepth(accountRoot, p) == 0 {
					audit.SkippedPaths = append(audit.SkippedPaths, forensic.SkippedPath{
						Path:   p,
						Reason: "private-account-path",
					})
				}
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "wp-config.php" {
			return nil
		}
		matches = append(matches, p)
		return nil
	})
	sort.Slice(matches, func(i, j int) bool {
		di := forensicPathDepth(accountRoot, matches[i])
		dj := forensicPathDepth(accountRoot, matches[j])
		if di != dj {
			return di < dj
		}
		return matches[i] < matches[j]
	})

	var out []forensic.SchemaTarget
	seen := map[string]bool{}
	for _, p := range matches {
		schema, prefix := parseWPConfigForensic(p)
		if schema == "" {
			audit.SkippedPaths = append(audit.SkippedPaths, forensic.SkippedPath{
				Path:   p,
				Reason: "missing-db-name",
			})
			continue
		}
		if !forensicSchemaValid(schema) {
			audit.SkippedPaths = append(audit.SkippedPaths, forensic.SkippedPath{
				Path:   p,
				Reason: "invalid-schema",
			})
			continue
		}
		if prefix == "" {
			prefix = "wp_"
		}
		if !forensicTablePrefixValid(prefix) {
			audit.SkippedPaths = append(audit.SkippedPaths, forensic.SkippedPath{
				Path:   p,
				Reason: "invalid-table-prefix",
			})
			continue
		}
		if seen[schema] {
			audit.SkippedPaths = append(audit.SkippedPaths, forensic.SkippedPath{
				Path:   p,
				Reason: "duplicate-schema",
			})
			continue
		}
		seen[schema] = true
		out = append(out, forensic.SchemaTarget{Schema: schema, TablePrefix: prefix, ConfigPath: p})
	}
	return out, audit
}

func forensicPathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return strings.Count(filepath.ToSlash(path), "/")
	}
	return strings.Count(filepath.ToSlash(rel), "/")
}

var (
	wpDBNameRe      = regexp.MustCompile(`define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]`)
	wpTablePrefixRe = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]+)['"]`)
)

func parseWPConfigForensic(path string) (string, string) {
	data, err := os.ReadFile(path) // #nosec G304 -- path discovered under /home/<validated cPanel account>.
	if err != nil {
		return "", ""
	}
	var schema, prefix string
	if m := wpDBNameRe.FindStringSubmatch(string(data)); m != nil {
		schema = m[1]
	}
	if m := wpTablePrefixRe.FindStringSubmatch(string(data)); m != nil {
		prefix = m[1]
	}
	return schema, prefix
}

// mysqldumpSchema runs `mysqldump --no-data --routines --triggers
// --events <schema>` using /root/.my.cnf for credentials. The
// command is invoked with a 60s timeout so a hung mysqld can't stall
// the whole snapshot.
func mysqldumpSchema(schema string) ([]byte, error) {
	if !forensicSchemaValid(schema) {
		return nil, fmt.Errorf("invalid schema name %q", schema)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// #nosec G204 -- schema validated against forensicIdentRe above.
	cmd := exec.CommandContext(ctx, "mysqldump", "--no-data", "--routines", "--triggers", "--events", schema)
	return cmd.Output()
}

func listForensicAdmins(schema, tablePrefix string) ([]byte, error) {
	if !forensicSchemaValid(schema) || !forensicTablePrefixValid(tablePrefix) {
		return nil, errors.New("invalid identifier")
	}
	query := fmt.Sprintf(
		"SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name "+
			"FROM `%susers` u JOIN `%susermeta` um ON u.ID = um.user_id "+
			"WHERE um.meta_key = '%scapabilities' AND um.meta_value LIKE '%%administrator%%' "+
			"ORDER BY u.user_registered",
		tablePrefix, tablePrefix, tablePrefix,
	)
	return runForensicMySQL(schema, query)
}

func listForensicSessions(schema, tablePrefix string) ([]byte, error) {
	if !forensicSchemaValid(schema) || !forensicTablePrefixValid(tablePrefix) {
		return nil, errors.New("invalid identifier")
	}
	query := fmt.Sprintf(
		"SELECT user_id, meta_value FROM `%susermeta` WHERE meta_key = 'session_tokens'",
		tablePrefix,
	)
	return runForensicMySQL(schema, query)
}

func runForensicMySQL(schema, query string) ([]byte, error) {
	if !forensicSchemaValid(schema) {
		return nil, errors.New("invalid schema")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- schema validated; query built with validated identifiers above.
	cmd := exec.CommandContext(ctx, "mysql", "-N", "-B", schema, "-e", query)
	return cmd.Output()
}

// listRecentMtimes walks accountRoot for files modified since `since`
// and returns a TSV of (path, mtime). Bounded to a per-call timeout
// because a large account can have millions of files. The function
// skips private account storage that does not belong in a customer
// hand-off archive.
func listRecentMtimes(accountRoot string, since time.Time) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var b strings.Builder
	cutoff := since.UTC()
	err := filepath.Walk(accountRoot, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			// Permission or transient FS errors: skip the entry, don't abort.
			return nil //nolint:nilerr // intentional skip on walk errors
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			if forensicSkipPrivatePath(accountRoot, p) {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip account-private storage. The operator can pull those
		// paths manually if needed; bundling them into a customer
		// hand-off archive is privacy overreach.
		if forensicSkipPrivatePath(accountRoot, p) {
			return nil
		}
		mt := info.ModTime().UTC()
		if mt.Before(cutoff) {
			return nil
		}
		fmt.Fprintf(&b, "%s\t%s\n", p, mt.Format(time.RFC3339))
		return nil
	})
	return []byte(b.String()), err
}

func forensicSkipPrivatePath(accountRoot, path string) bool {
	rel, err := filepath.Rel(accountRoot, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == "." {
		return false
	}
	first, _, _ := strings.Cut(rel, "/")
	for _, private := range forensicPrivateTopNames {
		if first == private {
			return true
		}
	}
	return strings.HasPrefix(first, ".")
}

var forensicPrivateTopNames = []string{
	".cagefs",
	".cpanel",
	".spamassassin",
	".trash",
	"access-logs",
	"etc",
	"homedir",
	"logs",
	"lscache",
	"mail",
	"ssl",
	"tmp",
}

func forensicPrivateTopPaths() []string {
	paths := append([]string(nil), forensicPrivateTopNames...)
	return append(paths, "top-level dotfiles")
}

var forensicSchemaRe = regexp.MustCompile(`^[A-Za-z0-9_@]+$`)
var forensicTablePrefixRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func forensicSchemaValid(s string) bool {
	return forensicSchemaRe.MatchString(s)
}

func forensicTablePrefixValid(s string) bool {
	return forensicTablePrefixRe.MatchString(s)
}
