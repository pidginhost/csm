package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

// defaultActionLogDir mirrors the LogsDirectory the packaged unit creates.
const defaultActionLogDir = "/var/log/csm"

type actionFilter struct {
	since time.Time
	op    string
	limit int
	json  bool
}

// runActions prints what CSM did to this host. It reads the log directly
// rather than going through the daemon, so it still answers after a crash.
func runActions() {
	filter := actionFilter{limit: 50}
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			filter.json = true
		case "--since":
			i++
			if i >= len(args) {
				actionsFatal("--since needs a value (RFC 3339 timestamp or duration like 24h / 7d)\n")
			}
			since, err := parseSince(args[i])
			if err != nil {
				actionsFatal("%v\n", err)
			}
			filter.since = since
		case "--op":
			i++
			if i >= len(args) {
				actionsFatal("--op needs an operation ID (see csm privileges)\n")
			}
			filter.op = args[i]
		case "--limit":
			i++
			n, err := strconv.Atoi(argOrEmpty(args, i))
			if err != nil || n <= 0 {
				actionsFatal("--limit needs a positive number\n")
			}
			filter.limit = n
		default:
			actionsFatal("Unknown flag for csm actions: %s\n", args[i])
		}
	}

	records, err := readActionLog(actionLogFile(), filter)
	if err != nil {
		actionsFatal("Cannot read the action log: %v\n", err)
	}
	if err := writeActions(os.Stdout, records, filter.json); err != nil {
		actionsFatal("Cannot write actions: %v\n", err)
	}
}

func argOrEmpty(args []string, i int) string {
	if i >= len(args) {
		return ""
	}
	return args[i]
}

// actionLogFile puts the reader on the same file the daemon writes, following
// the audit-log directory when the operator moved it.
func actionLogFile() string {
	dir := defaultActionLogDir
	if cfg, err := tryLoadConfigLite(); err == nil && cfg != nil {
		if configured := cfg.Alerts.AuditLog.File.Path; configured != "" {
			dir = filepath.Dir(configured)
		}
	}
	return actionlog.DefaultPath(dir)
}

// readActionLog reads the current file and the one rotated before it, oldest
// first, so a --since window that spans a rotation is still complete.
func readActionLog(path string, filter actionFilter) ([]actionlog.Record, error) {
	var records []actionlog.Record
	for _, candidate := range []string{path + ".1", path} {
		batch, err := readActionFile(candidate, filter)
		if err != nil {
			return nil, err
		}
		records = append(records, batch...)
	}
	if filter.limit > 0 && len(records) > filter.limit {
		records = records[len(records)-filter.limit:]
	}
	return records, nil
}

func readActionFile(path string, filter actionFilter) ([]actionlog.Record, error) {
	// #nosec G304 -- path is derived from the operator-configured log directory.
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fh.Close() }()

	var out []actionlog.Record
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec actionlog.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			// A truncated final line after a crash must not hide the rest.
			continue
		}
		if !filter.since.IsZero() && rec.Timestamp.Before(filter.since) {
			continue
		}
		if filter.op != "" && rec.Op != filter.op {
			continue
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func writeActions(w io.Writer, records []actionlog.Record, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		for _, rec := range records {
			if err := enc.Encode(rec); err != nil {
				return err
			}
		}
		return nil
	}
	if len(records) == 0 {
		_, err := fmt.Fprintln(w, "No actions recorded.")
		return err
	}
	for _, rec := range records {
		if _, err := fmt.Fprintln(w, rec.Describe()); err != nil {
			return err
		}
	}
	return nil
}

func actionsFatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

// installCLIActionLog points a CLI process at the same action log the daemon
// writes, so `csm clean` and the firewall commands leave the same evidence an
// automatic action does.
func installCLIActionLog() {
	actionlog.SetSink(actionlog.NewFileSink(actionLogFile, nil), hostnameLite())
	actionlog.SetDefaultActor(actionlog.CLI)
}
