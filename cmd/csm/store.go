package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// StoreCompactOptions controls runStoreCompact behavior. Preview means
// "run the snapshot and report sizes, but do not replace the live DB."
type StoreCompactOptions struct {
	Preview bool
}

// StoreCompactResult summarises one compact run.
type StoreCompactResult struct {
	SrcSize  int64
	DstSize  int64
	Reclaim  int64
	Preview  bool
	DstPath  string // absolute path of the compacted file (or temp path in preview mode)
	Replaced bool   // true if the live DB was actually replaced
}

// runStoreCompact opens the bbolt store at statePath, snapshots it into a
// temp file next to the live DB, and (when opts.Preview is false) renames
// the temp file over the live DB. The operation is designed to run with
// the daemon stopped: bbolt's file-lock will reject the Open call with a
// timeout if another process already holds it, while the daemon state lock
// serializes against startup compaction and another daemon start.
//
// The function is deliberately single-purpose and does not touch any
// global state; it can be called from tests without needing to spin up
// the full CLI.
func runStoreCompact(statePath string, opts StoreCompactOptions) (*StoreCompactResult, error) {
	if statePath == "" {
		return nil, errors.New("state path is empty")
	}

	// Ensure the dir exists. Open would create it, but we want a clean
	// error before touching bolt if the path is unusable.
	if err := os.MkdirAll(statePath, 0700); err != nil {
		return nil, fmt.Errorf("state dir %q: %w", statePath, err)
	}
	stateLock, err := state.AcquireLock(statePath)
	if err != nil {
		return nil, fmt.Errorf("state lock: %w", err)
	}
	defer stateLock.Release()

	db, err := store.Open(statePath)
	if err != nil {
		// bbolt uses fcntl file-locks; a daemon already holding the DB
		// manifests here as a timeout on the lock-wait. Translate it so
		// operators know what to do.
		if strings.Contains(err.Error(), "timeout") {
			return nil, fmt.Errorf("state DB is locked (daemon likely running); stop with `systemctl stop csm` and retry: %w", err)
		}
		return nil, fmt.Errorf("opening state DB: %w", err)
	}

	return compactOpenStore(db, opts)
}

func compactOpenStore(db *store.DB, opts StoreCompactOptions) (*StoreCompactResult, error) {
	if db == nil {
		return nil, errors.New("state DB is nil")
	}
	livePath := db.Path()
	tmpPath := livePath + ".compact.tmp"
	// Stale temp file from an aborted previous run: remove before CompactInto
	// so bolt.Open on dst sees a fresh file.
	_ = os.Remove(tmpPath)

	srcSize, dstSize, err := db.CompactInto(tmpPath, 0)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("compacting: %w", err)
	}
	result := &StoreCompactResult{
		SrcSize: srcSize,
		DstSize: dstSize,
		Reclaim: srcSize - dstSize,
		Preview: opts.Preview,
		DstPath: tmpPath,
	}

	if opts.Preview {
		// Leave the temp snapshot in place for the operator to inspect;
		// runStoreCompactCLI will print its path.
		if err := db.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("closing source DB: %w", err)
		}
		return result, nil
	}

	// Atomic swap: rename temp over live while the source DB lock is still
	// held. Callers that promote the snapshot also hold the daemon state lock,
	// so there is no close-before-rename window for another CSM process.
	if err := os.Rename(tmpPath, livePath); err != nil {
		_ = os.Remove(tmpPath)
		_ = db.Close()
		return nil, fmt.Errorf("renaming compacted file into place: %w", err)
	}
	result.Replaced = true
	result.DstPath = livePath
	if err := db.Close(); err != nil {
		return nil, fmt.Errorf("closing source DB after replace: %w", err)
	}
	return result, nil
}

// shouldCompactState reports whether the bbolt state db is worth compacting at
// startup: large enough that the slack matters AND fragmented enough that a
// compaction would reclaim a meaningful fraction. minSizeMB and fillRatio come
// from Retention config; non-positive values disable the check. freeBytes
// above sizeBytes is clamped (used=0) rather than producing a negative fill.
func shouldCompactState(sizeBytes, freeBytes int64, minSizeMB int, fillRatio float64) bool {
	if minSizeMB <= 0 || fillRatio <= 0 || sizeBytes <= 0 {
		return false
	}
	if sizeBytes < int64(minSizeMB)*1024*1024 {
		return false
	}
	used := sizeBytes - freeBytes
	if used < 0 {
		used = 0
	}
	fill := float64(used) / float64(sizeBytes)
	return fill < fillRatio
}

func openStateDBForCompaction(statePath string) (*store.DB, bool, error) {
	if statePath == "" {
		return nil, false, errors.New("state path is empty")
	}
	dbPath := filepath.Join(statePath, "csm.db")
	if info, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	} else if info.IsDir() {
		return nil, false, fmt.Errorf("state DB path %q is a directory", dbPath)
	}
	db, err := store.Open(statePath)
	if err != nil {
		return nil, true, err
	}
	return db, true, nil
}

// maybeCompactStateAtStartup compacts the bbolt state db before the daemon
// opens it, when the file is both large and mostly free pages. Compaction is
// non-destructive (it only reclaims freelist slack, never deletes data), so it
// runs independently of the opt-in retention sweeps -- operators disable it by
// setting retention.compact_min_size_mb to 0. runDaemon calls this after the
// daemon process lock is held and before any daemon bbolt handle is open, and
// compactOpenStore keeps the source bbolt lock through the rename.
// Returns the compaction result when one ran, or nil when skipped.
func maybeCompactStateAtStartup(cfg *config.Config) (*StoreCompactResult, error) {
	if cfg == nil {
		return nil, nil
	}
	db, exists, err := openStateDBForCompaction(cfg.StatePath)
	if err != nil || !exists {
		return nil, err
	}
	size, err := db.Size()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	free, err := db.FreeBytes()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if !shouldCompactState(size, free, cfg.Retention.CompactMinSizeMB, cfg.Retention.CompactFillRatio) {
		if err := db.Close(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	fmt.Fprintf(os.Stderr, "state: auto-compacting bbolt db (size=%d bytes, free=%d bytes) before startup\n", size, free)
	return compactOpenStore(db, StoreCompactOptions{})
}

// runStoreCompactCLI is the thin argv→options wrapper invoked from
// main.go. Exits non-zero on error.
func runStoreCompactCLI() {
	opts := StoreCompactOptions{}
	// Very small flag surface: `--preview` toggles preview mode. All
	// other args are reserved for future use.
	for _, arg := range os.Args[3:] {
		switch arg {
		case "--preview":
			opts.Preview = true
		case "--help", "-h":
			printStoreCompactUsage()
			return
		default:
			fmt.Fprintf(os.Stderr, "csm store compact: unknown flag %q\n", arg)
			printStoreCompactUsage()
			os.Exit(2)
		}
	}

	cfg := loadConfigLite()
	res, err := runStoreCompact(cfg.StatePath, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm store compact: %v\n", err)
		os.Exit(1)
	}

	reclaimPct := 0.0
	if res.SrcSize > 0 {
		reclaimPct = 100.0 * float64(res.Reclaim) / float64(res.SrcSize)
	}
	if res.Preview {
		fmt.Printf("compact preview:\n")
		fmt.Printf("  src: %d bytes\n", res.SrcSize)
		fmt.Printf("  dst: %d bytes (%.1f%% smaller)\n", res.DstSize, reclaimPct)
		fmt.Printf("  preview file: %s\n", res.DstPath)
		fmt.Printf("  rerun without --preview to replace the live DB\n")
		return
	}
	fmt.Printf("compact done: %d -> %d bytes (%.1f%% reclaimed)\n", res.SrcSize, res.DstSize, reclaimPct)
}

func printStoreCompactUsage() {
	fmt.Fprintln(os.Stderr, `csm store compact - reclaim unused space in the bbolt state database

Usage:
  csm store compact [--preview]

Flags:
  --preview   Snapshot into a temp file and report sizes without
              replacing the live DB. The temp file is left on disk
              so the operator can spot-check it before re-running.

Requires the daemon to be stopped (systemctl stop csm) because bbolt
holds an exclusive file lock while the daemon runs.`)
}

// runStoreCLI dispatches `csm store <subcommand>`.
func runStoreCLI() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "csm store: missing subcommand (try `csm store compact|export|import|reset-bot-verify`)")
		os.Exit(2)
	}
	switch os.Args[2] {
	case "compact":
		runStoreCompactCLI()
	case "export":
		runStoreExportCLI()
	case "import":
		runStoreImportCLI()
	case "reset-bot-verify":
		runStoreResetBotVerifyCLI()
	case "--help", "-h", "help":
		printStoreUsage()
	default:
		fmt.Fprintf(os.Stderr, "csm store: unknown subcommand %q\n", os.Args[2])
		os.Exit(2)
	}
}

// runStoreResetBotVerify opens the bbolt store at statePath and drops
// every cached PTR+forward-A result. Returns the number of entries
// removed. The daemon must be stopped because bbolt holds an exclusive
// file lock while it runs; the function translates the lock-timeout
// error so operators know what to do.
func runStoreResetBotVerify(statePath string) (int, error) {
	if statePath == "" {
		return 0, errors.New("state path is empty")
	}
	if err := os.MkdirAll(statePath, 0700); err != nil {
		return 0, fmt.Errorf("state dir %q: %w", statePath, err)
	}
	db, err := store.Open(statePath)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return 0, fmt.Errorf("state DB is locked (daemon likely running); stop with `systemctl stop csm` and retry: %w", err)
		}
		return 0, fmt.Errorf("opening state DB: %w", err)
	}
	defer func() { _ = db.Close() }()
	return db.ResetBotVerify()
}

func runStoreResetBotVerifyCLI() {
	for _, arg := range os.Args[3:] {
		switch arg {
		case "--help", "-h":
			printStoreResetBotVerifyUsage()
			return
		default:
			fmt.Fprintf(os.Stderr, "csm store reset-bot-verify: unknown flag %q\n", arg)
			printStoreResetBotVerifyUsage()
			os.Exit(2)
		}
	}
	cfg := loadConfigLite()
	n, err := runStoreResetBotVerify(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm store reset-bot-verify: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("reset-bot-verify done: cleared %d cached PTR results\n", n)
}

func printStoreResetBotVerifyUsage() {
	fmt.Fprintln(os.Stderr, `csm store reset-bot-verify - drop the cached PTR+forward-A results

Usage:
  csm store reset-bot-verify

Removes every entry in the botverify bucket so the next scan re-runs
reverse DNS verification for each crawler IP it sees. Useful after a
verifier-logic upgrade that would invalidate prior negative cache
entries (for example, adding a new bot domain suffix). Requires the
daemon to be stopped (systemctl stop csm) because bbolt holds an
exclusive file lock while the daemon runs.`)
}

func printStoreUsage() {
	fmt.Fprintln(os.Stderr, `csm store - manage the bbolt state database

Subcommands:
  compact            Reclaim unused space (daemon must be stopped)
  export <path>      Write a backup archive (daemon must be running)
  import <path>      Restore from a backup archive (daemon must be stopped)
  reset-bot-verify   Drop cached PTR+forward-A results (daemon must be stopped)

Run "csm store <subcommand> --help" for details.`)
}

// runStoreExportCLI sends CmdStoreExport to the running daemon. The
// daemon owns the source of truth for state and rules paths; the CLI
// only supplies the destination archive path.
func runStoreExportCLI() {
	args := os.Args[3:]
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printStoreExportUsage()
		if len(args) == 0 {
			os.Exit(2)
		}
		return
	}
	dstPath := args[0]
	for _, a := range args[1:] {
		switch a {
		case "--help", "-h":
			printStoreExportUsage()
			return
		default:
			fmt.Fprintf(os.Stderr, "csm store export: unknown flag %q\n", a)
			printStoreExportUsage()
			os.Exit(2)
		}
	}

	if !strings.HasPrefix(dstPath, "/") {
		// The daemon writes the file; relative paths land in the daemon's
		// CWD which is rarely what the operator meant. Force absolute.
		fmt.Fprintln(os.Stderr, "csm store export: path must be absolute (daemon writes the file)")
		os.Exit(2)
	}

	raw, err := sendControlWithTimeout(control.CmdStoreExport, control.StoreExportArgs{DstPath: dstPath}, 30*time.Minute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm store export: %v\n", err)
		os.Exit(1)
	}
	var res control.StoreExportResult
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Fprintf(os.Stderr, "csm store export: decoding response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("export: %s (%d bytes)\n", res.Path, res.Bytes)
	fmt.Printf("  archive sha256: %s\n", res.ArchiveSHA256)
	fmt.Printf("  bbolt   sha256: %s\n", res.BboltSHA256)
	fmt.Printf("  companion file: %s.sha256\n", res.Path)
}

func printStoreExportUsage() {
	fmt.Fprintln(os.Stderr, `csm store export - back up the bbolt store, state files, and signature cache

Usage:
  csm store export <absolute-path>

Writes a tar+zstd archive at the given path plus a sibling .sha256 file
containing the archive hash. Requires a running daemon.`)
}

// runStoreImportCLI is direct-to-disk: import requires a stopped daemon
// because split-brain (live writes mixing with restored state) is worse
// than the downtime of a `systemctl stop csm`.
func runStoreImportCLI() {
	args := os.Args[3:]
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printStoreImportUsage()
		if len(args) == 0 {
			os.Exit(2)
		}
		return
	}
	srcPath := args[0]
	only := "all"
	forcePlatform := false
	for _, a := range args[1:] {
		switch {
		case a == "--help" || a == "-h":
			printStoreImportUsage()
			return
		case a == "--force-platform-mismatch":
			forcePlatform = true
		case strings.HasPrefix(a, "--only="):
			only = strings.TrimPrefix(a, "--only=")
		default:
			fmt.Fprintf(os.Stderr, "csm store import: unknown flag %q\n", a)
			printStoreImportUsage()
			os.Exit(2)
		}
	}

	// Refuse with a live daemon. Connecting to the socket is the
	// authoritative check: if it accepts our connection, the daemon is
	// up regardless of pid files.
	if isDaemonLive() {
		fmt.Fprintln(os.Stderr, "csm store import: daemon is running; stop it first (systemctl stop csm)")
		os.Exit(1)
	}

	cfg := loadConfigLite()
	pi := platform.Detect()
	currentPlatform := map[string]string{
		"os":         string(pi.OS),
		"os_version": pi.OSVersion,
		"panel":      string(pi.Panel),
		"webserver":  string(pi.WebServer),
	}

	res, err := store.Import(store.ImportOptions{
		SrcPath:               srcPath,
		StatePath:             cfg.StatePath,
		RulesPath:             cfg.Signatures.RulesDir,
		Only:                  only,
		ForcePlatformMismatch: forcePlatform,
		CurrentPlatform:       currentPlatform,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm store import: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("import: archive from %s (csm %s on %s)\n",
		res.Manifest.SourceHostname, res.Manifest.CSMVersion, res.Manifest.SourcePlatform["os"])
	fmt.Printf("  buckets restored: %d\n", len(res.BucketsRestored))
	fmt.Printf("  state files restored: %d\n", res.StateFiles)
	fmt.Printf("  rules files restored: %d\n", res.RulesFiles)
	fmt.Printf("  start the daemon to resume: systemctl start csm\n")
}

func printStoreImportUsage() {
	fmt.Fprintln(os.Stderr, `csm store import - restore from a backup archive

Usage:
  csm store import <path> [--only=all|baseline|firewall] [--force-platform-mismatch]

Requires the daemon to be stopped (systemctl stop csm). The default
"--only=all" restores bbolt, state files, and the signature cache.

  --only=baseline   Restore only the state JSON files (baseline file
                    hashes). Skips bbolt and signature cache.
  --only=firewall   Restore only the firewall buckets (fw:*) into the
                    target bbolt; leaves history, attacks, reputation,
                    and other buckets intact.

  --force-platform-mismatch  Allow restore when the archive's source OS,
                             panel, or web server differs from the host.
                             A baseline captured on Apache is rarely
                             meaningful on Nginx -- use with caution.`)
}

// isDaemonLive returns true if the control socket accepts a connection
// right now. Used by import to refuse split-brain restores.
func isDaemonLive() bool {
	conn, err := net.DialTimeout("unix", controlSocketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
