package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/control"
)

// runExportCLI implements `csm export` -- the SIEM backfill command.
// Reads every history-bucket finding newer than --since via the
// control socket, transforms each into the same AuditEvent shape the
// live audit_log sinks emit, and writes JSONL to stdout. Operators
// pipe to a file (`csm export --since 24h > backfill.jsonl`) or
// straight into a log shipper.
func runExportCLI() {
	args := os.Args[2:]
	since := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			printExportUsage()
			return
		case a == "--since":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "csm export: --since requires a value")
				os.Exit(2)
			}
			since = args[i+1]
			i++
		case strings.HasPrefix(a, "--since="):
			since = strings.TrimPrefix(a, "--since=")
		default:
			fmt.Fprintf(os.Stderr, "csm export: unknown flag %q\n", a)
			printExportUsage()
			os.Exit(2)
		}
	}

	if since == "" {
		fmt.Fprintln(os.Stderr, "csm export: --since is required")
		printExportUsage()
		os.Exit(2)
	}

	cutoff, err := parseSince(since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm export: %v\n", err)
		os.Exit(2)
	}

	cfg := loadConfigLite()
	hostname := cfg.Hostname
	if hostname == "" {
		if h, hErr := os.Hostname(); hErr == nil {
			hostname = h
		}
	}

	raw, err := sendControlWithTimeout(
		control.CmdHistorySince,
		control.HistorySinceArgs{Since: cutoff.Format(time.RFC3339)},
		5*time.Minute,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm export: %v\n", err)
		os.Exit(1)
	}
	var resp control.HistorySinceResult
	if err := json.Unmarshal(raw, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "csm export: decoding response: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	for _, f := range resp.Findings {
		ev := alert.NewAuditEvent(hostname, f)
		if err := enc.Encode(ev); err != nil {
			fmt.Fprintf(os.Stderr, "csm export: encoding event: %v\n", err)
			os.Exit(1)
		}
	}
}

// parseSince accepts either RFC 3339 ("2026-04-01T00:00:00Z") or a
// duration string with the standard time.ParseDuration grammar
// ("24h", "7d" via days handled below). Days are not in
// time.ParseDuration, so handle "Nd" specially.
func parseSince(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 {
			return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().UTC().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("--since must be RFC 3339 timestamp or duration like '24h' / '7d', got %q", s)
}

func printExportUsage() {
	fmt.Fprintln(os.Stderr, `csm export - dump audit-log events from the bbolt history bucket

Usage:
  csm export --since <when>

The <when> argument is either an RFC 3339 timestamp or a duration
relative to "now":

  --since 2026-04-01T00:00:00Z
  --since 24h
  --since 7d

Output is one JSON event per line on stdout, in the same v=1 schema
the live audit_log sinks emit. Pipe to a file or log shipper:

  csm export --since 24h > recent.jsonl
  csm export --since 7d  | nc -u syslog-host 514

Requires a running daemon.`)
}
