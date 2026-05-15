// Package forensic produces evidence archives for incident response.
//
// A snapshot bundles the structured outputs an operator needs to hand a
// customer after a database-layer compromise: full trigger / event /
// routine definitions, the admin user roster, active session metadata,
// and the recent-mtime list under the account's document roots. Wrapped
// in a tar+gzip with a manifest and a SHA256 sidecar.
//
// The snapshot intentionally excludes credentials. Password rotation is
// a separate runbook step; bundling new credentials with the evidence
// archive would conflate two opposing flows (hand-to-customer for
// audit vs hand-to-ops for rotation) and risk credential leakage if
// the archive is later shared casually.
package forensic

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SchemaTarget identifies one MySQL schema to include in the snapshot
// along with the WordPress table prefix needed to enumerate the user
// roster correctly. Discovered from wp-config.php in the account's
// document roots by the production hook.
type SchemaTarget struct {
	Schema      string
	TablePrefix string
	ConfigPath  string
}

// DiscoveryAudit records why a snapshot captured the targets it did.
// It is written into the manifest so operators can validate the
// evidence boundary without inspecting the host again.
type DiscoveryAudit struct {
	AccountRoot          string
	PrivatePathsExcluded bool
	PrivateTopPaths      []string
	SkippedPaths         []SkippedPath
}

// SkippedPath records one discovery path that was not safe or useful
// to capture.
type SkippedPath struct {
	Path   string
	Reason string
}

// Sources lets the caller swap each I/O dependency for a test double.
// Production wiring lives in cmd/csm; tests pass deterministic
// closures.
type Sources struct {
	DiscoverTargets func(account string) []SchemaTarget
	DumpSchema      func(schema string) ([]byte, error)
	ListAdmins      func(schema, tablePrefix string) ([]byte, error)
	ListSessions    func(schema, tablePrefix string) ([]byte, error)
	ListRecentFiles func(accountRoot string, since time.Time) ([]byte, error)
}

// Snapshot is the operator-facing configuration. Account and OutPath
// are required; Sources is required when running outside the default
// production wiring (see cmd/csm for the defaults).
type Snapshot struct {
	Account        string
	OutPath        string
	Timestamp      time.Time
	DiscoveryAudit DiscoveryAudit
	Sources        Sources
}

var accountNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
var schemaNamePattern = regexp.MustCompile(`^[A-Za-z0-9_@]+$`)
var tablePrefixPattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// AccountNameValid keeps the account string conservative enough to use
// in archive entry names, manifest keys, and shell-free SQL queries.
func AccountNameValid(name string) bool {
	return accountNamePattern.MatchString(name)
}

func schemaNameValid(name string) bool {
	return schemaNamePattern.MatchString(name)
}

func tablePrefixValid(name string) bool {
	return tablePrefixPattern.MatchString(name)
}

// Write builds the archive at s.OutPath and a `<out>.sha256` sidecar,
// returning the archive path and the SHA256 hex digest. Errors abort
// before any partial state is written.
func (s Snapshot) Write() (string, string, error) {
	if !AccountNameValid(s.Account) {
		return "", "", fmt.Errorf("invalid account name: %q", s.Account)
	}
	if s.OutPath == "" {
		return "", "", errors.New("forensic snapshot: OutPath required")
	}
	if err := ValidateOutPath(s.Account, s.OutPath); err != nil {
		return "", "", err
	}
	if s.Sources.DiscoverTargets == nil {
		return "", "", errors.New("forensic snapshot: Sources.DiscoverTargets required")
	}

	ts := s.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	targets := s.Sources.DiscoverTargets(s.Account)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Schema < targets[j].Schema })

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	var manifestB strings.Builder
	fmt.Fprintf(&manifestB, "account=%s\n", s.Account)
	fmt.Fprintf(&manifestB, "timestamp=%s\n", ts.UTC().Format(time.RFC3339))
	fmt.Fprintf(&manifestB, "schema_count=%d\n", len(targets))
	writeDiscoveryAudit(&manifestB, s.DiscoveryAudit)

	var validTargets, invalidTargets int
	var dumpOK, dumpErr int
	var adminsOK, adminsErr int
	var sessionsOK, sessionsErr int
	recentStatus := "disabled"
	for i, tgt := range targets {
		if !schemaNameValid(tgt.Schema) || !tablePrefixValid(tgt.TablePrefix) {
			invalidTargets++
			fmt.Fprintf(&manifestB, "invalid_target=%d schema=%q table_prefix=%q\n", i, tgt.Schema, tgt.TablePrefix)
			name := "schema/invalid-target-" + strconv.Itoa(i) + ".err"
			data := []byte(fmt.Sprintf("invalid schema target: schema=%q table_prefix=%q\n", tgt.Schema, tgt.TablePrefix))
			if err := writeArchiveEntry(tw, name, data, ts); err != nil {
				return "", "", err
			}
			continue
		}
		validTargets++
		fmt.Fprintf(&manifestB, "schema=%s table_prefix=%s", tgt.Schema, tgt.TablePrefix)
		if tgt.ConfigPath != "" {
			fmt.Fprintf(&manifestB, " config_path=%q", tgt.ConfigPath)
		}
		fmt.Fprint(&manifestB, "\n")

		// Schema dump.
		if s.Sources.DumpSchema != nil {
			data, err := s.Sources.DumpSchema(tgt.Schema)
			name := "schema/" + tgt.Schema + "-routines.sql"
			if err != nil {
				dumpErr++
				name += ".err"
				data = []byte(err.Error() + "\n")
			} else {
				dumpOK++
			}
			if werr := writeArchiveEntry(tw, name, data, ts); werr != nil {
				return "", "", werr
			}
		}

		// Admin roster.
		if s.Sources.ListAdmins != nil {
			data, err := s.Sources.ListAdmins(tgt.Schema, tgt.TablePrefix)
			name := "schema/" + tgt.Schema + "-admins.tsv"
			if err != nil {
				adminsErr++
				name += ".err"
				data = []byte(err.Error() + "\n")
			} else {
				adminsOK++
			}
			if werr := writeArchiveEntry(tw, name, data, ts); werr != nil {
				return "", "", werr
			}
		}

		// Sessions.
		if s.Sources.ListSessions != nil {
			data, err := s.Sources.ListSessions(tgt.Schema, tgt.TablePrefix)
			name := "schema/" + tgt.Schema + "-sessions.tsv"
			if err != nil {
				sessionsErr++
				name += ".err"
				data = []byte(err.Error() + "\n")
			} else {
				sessionsOK++
			}
			if werr := writeArchiveEntry(tw, name, data, ts); werr != nil {
				return "", "", werr
			}
		}
	}

	// Recent files.
	if s.Sources.ListRecentFiles != nil {
		data, err := s.Sources.ListRecentFiles("/home/"+s.Account, ts.Add(-7*24*time.Hour))
		name := "files/recent-mtimes.tsv"
		if err != nil {
			recentStatus = "error"
			name += ".err"
			data = []byte(err.Error() + "\n")
		} else {
			recentStatus = "ok"
		}
		if werr := writeArchiveEntry(tw, name, data, ts); werr != nil {
			return "", "", werr
		}
	}
	fmt.Fprintf(&manifestB, "valid_target_count=%d\n", validTargets)
	fmt.Fprintf(&manifestB, "invalid_target_count=%d\n", invalidTargets)
	fmt.Fprintf(&manifestB, "dump_success_count=%d\n", dumpOK)
	fmt.Fprintf(&manifestB, "dump_error_count=%d\n", dumpErr)
	fmt.Fprintf(&manifestB, "admins_success_count=%d\n", adminsOK)
	fmt.Fprintf(&manifestB, "admins_error_count=%d\n", adminsErr)
	fmt.Fprintf(&manifestB, "sessions_success_count=%d\n", sessionsOK)
	fmt.Fprintf(&manifestB, "sessions_error_count=%d\n", sessionsErr)
	fmt.Fprintf(&manifestB, "recent_mtimes_status=%s\n", recentStatus)

	// Manifest last so the schema list reflects what was actually
	// processed.
	if err := writeArchiveEntry(tw, "manifest.txt", []byte(manifestB.String()), ts); err != nil {
		return "", "", err
	}

	if err := tw.Close(); err != nil {
		return "", "", fmt.Errorf("closing tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return "", "", fmt.Errorf("closing gzip: %w", err)
	}

	if err := os.WriteFile(s.OutPath, buf.Bytes(), 0o600); err != nil {
		return "", "", fmt.Errorf("writing archive: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	hexSum := hex.EncodeToString(sum[:])
	sidecar := s.OutPath + ".sha256"
	sidecarBody := fmt.Sprintf("%s  %s\n", hexSum, filepath.Base(s.OutPath))
	if err := os.WriteFile(sidecar, []byte(sidecarBody), 0o600); err != nil {
		return "", "", fmt.Errorf("writing sidecar: %w", err)
	}
	return s.OutPath, hexSum, nil
}

func writeDiscoveryAudit(b *strings.Builder, audit DiscoveryAudit) {
	if audit.AccountRoot != "" {
		fmt.Fprintf(b, "discovery_root=%q\n", audit.AccountRoot)
	}
	if audit.PrivatePathsExcluded {
		fmt.Fprintln(b, "private_paths_excluded=true")
	}
	if len(audit.PrivateTopPaths) > 0 {
		paths := append([]string(nil), audit.PrivateTopPaths...)
		sort.Strings(paths)
		fmt.Fprintf(b, "private_top_excluded=%q\n", strings.Join(paths, ","))
	}
	for i, skipped := range audit.SkippedPaths {
		fmt.Fprintf(b, "skipped_path=%d path=%q reason=%q\n", i, skipped.Path, skipped.Reason)
	}
}

// ValidateOutPath rejects destinations that would land inside the
// target account's home directory. Writing forensic evidence somewhere
// the suspect user can read defeats the point.
func ValidateOutPath(account, outPath string) error {
	if !AccountNameValid(account) {
		return fmt.Errorf("invalid account name: %q", account)
	}
	abs, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolving out path: %w", err)
	}
	home := filepath.Clean("/home/" + account)
	homes := []string{home}
	if realHome, err := filepath.EvalSymlinks(home); err == nil {
		homes = append(homes, realHome)
	}
	paths := []string{abs}
	if realAbs, err := filepath.EvalSymlinks(abs); err == nil {
		paths = append(paths, realAbs)
	}
	if realParent, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		paths = append(paths, filepath.Join(realParent, filepath.Base(abs)))
	}
	for _, h := range homes {
		for _, p := range paths {
			if pathWithin(h, p) {
				return fmt.Errorf("out path must not be inside /home/%s/", account)
			}
		}
	}
	return nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// writeArchiveEntry adds a single file to the tar stream with a fixed
// mtime so identical inputs produce byte-identical archives. The mode
// is 0600 because forensic content is operator-only.
func writeArchiveEntry(tw *tar.Writer, name string, data []byte, ts time.Time) error {
	if unsafeArchiveEntryName(name) {
		return fmt.Errorf("unsafe archive entry name: %q", name)
	}
	hdr := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0o600,
		ModTime: ts.UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("tar body %s: %w", name, err)
	}
	return nil
}

func unsafeArchiveEntryName(name string) bool {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, `\`) {
		return true
	}
	clean := filepath.Clean(name)
	return clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator))
}
