package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// scanFlags holds the parsed result of the flags for `csm scan`.
type scanFlags struct {
	// Legacy in-process flags.
	account   string
	sendAlert bool

	// Full-scan mode.
	full           bool
	wait           bool
	jsonOutput     bool
	respectIgnores bool
	quarantine     bool

	// Query sub-commands (no account required).
	statusID    string // --status [id]: empty means list all
	reportID    string // --report <id>
	cancelID    string // --cancel <id>
	statusGiven bool   // true when --status was given (even without id)
}

// parseScanFlags parses the positional and flag arguments that follow
// `csm scan` (i.e. os.Args[2:]). It returns a populated scanFlags or
// an error describing the first constraint violation.
//
// Supported forms:
//
//	csm scan <user> [--full] [--wait] [--json] [--respect-ignores] [--quarantine] [--alert]
//	csm scan --status [id]
//	csm scan --report <id>
//	csm scan --cancel <id>
func parseScanFlags(args []string) (scanFlags, error) {
	var f scanFlags
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--full":
			f.full = true
		case "--wait":
			f.wait = true
		case "--json":
			f.jsonOutput = true
		case "--respect-ignores":
			f.respectIgnores = true
		case "--quarantine":
			f.quarantine = true
		case "--alert":
			f.sendAlert = true
		case "--all":
			return scanFlags{}, errors.New("--all (server-wide full scan) is Phase 2 and not yet supported")
		case "--status":
			f.statusGiven = true
			// Optional argument: the next token if it does not start with '--'.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				f.statusID = args[i]
			}
		case "--report":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return scanFlags{}, errors.New("--report requires a job id")
			}
			i++
			f.reportID = args[i]
		case "--cancel":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return scanFlags{}, errors.New("--cancel requires a job id")
			}
			i++
			f.cancelID = args[i]
		default:
			if strings.HasPrefix(args[i], "--") {
				return scanFlags{}, fmt.Errorf("unknown flag: %s", args[i])
			}
			if f.account != "" {
				return scanFlags{}, fmt.Errorf("unexpected argument: %s", args[i])
			}
			f.account = args[i]
		}
		i++
	}

	if f.quarantine && !f.full {
		return scanFlags{}, errors.New("--quarantine requires --full")
	}

	if f.wait && !f.full {
		return scanFlags{}, errors.New("--wait requires --full")
	}

	isQuery := f.statusGiven || f.reportID != "" || f.cancelID != ""

	if isQuery && f.account != "" {
		return scanFlags{}, errors.New("account username is not allowed with --status/--report/--cancel")
	}

	if !isQuery && f.account == "" {
		return scanFlags{}, errors.New("account username required")
	}

	return f, nil
}

// runScanAccount is the entry point for `csm scan`.
func runScanAccount() {
	args := os.Args[2:]
	if len(args) == 0 {
		printScanUsage()
		os.Exit(1)
	}

	f, err := parseScanFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm scan: %v\n", err)
		os.Exit(1)
	}

	switch {
	case f.statusGiven:
		runScanStatus(f)
	case f.reportID != "":
		runScanReport(f)
	case f.cancelID != "":
		runScanCancel(f)
	case f.full:
		runScanFull(f)
	default:
		runScanLegacy(f)
	}
}

func printScanUsage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  csm scan <user> [--alert]\n")
	fmt.Fprintf(os.Stderr, "  csm scan <user> --full [--wait] [--json] [--respect-ignores] [--quarantine]\n")
	fmt.Fprintf(os.Stderr, "  csm scan --status [id]\n")
	fmt.Fprintf(os.Stderr, "  csm scan --report <id>\n")
	fmt.Fprintf(os.Stderr, "  csm scan --cancel <id>\n")
}

// runScanFull handles `csm scan <user> --full [--wait]`.
// Always routes through the daemon; there is no in-process fallback.
func runScanFull(f scanFlags) {
	runScanFullWith(f, sendControl)
}

// sendFn is the type of the send function injected for testing.
type sendFn func(cmd string, args any) (json.RawMessage, error)

// runScanFullWith is the testable core of runScanFull.
// It accepts an injected sender so tests can drive it against a fake daemon.
func runScanFullWith(f scanFlags, send sendFn) {
	req := control.ScanEnqueueRequest{
		Scope:          "account",
		Target:         f.account,
		RespectIgnores: f.respectIgnores,
		Quarantine:     f.quarantine,
	}

	raw, err := send(control.CmdScanEnqueue, req)
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "csm: daemon not running (start with: systemctl start csm)")
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "csm: %v\n", err)
		os.Exit(1)
	}

	var enqResp control.ScanEnqueueResponse
	if err := json.Unmarshal(raw, &enqResp); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decode enqueue response: %v\n", err)
		os.Exit(1)
	}

	if !f.wait {
		if f.jsonOutput {
			printJSON(raw)
			return
		}
		fmt.Printf("job: %s  state: %s\n", enqResp.JobID, enqResp.State)
		fmt.Printf("poll: csm scan --status %s\n", enqResp.JobID)
		return
	}

	// --wait: poll until terminal, then print the report.
	// Check immediately first (fast scans complete before the first interval),
	// then sleep between subsequent polls.
	jobID := enqResp.JobID
	const pollInterval = 2 * time.Second
	for {
		statusRaw, err := send(control.CmdScanStatus, control.ScanStatusRequest{JobID: jobID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "csm: poll status: %v\n", err)
			os.Exit(1)
		}
		var statusResp control.ScanStatusResponse
		if err := json.Unmarshal(statusRaw, &statusResp); err != nil {
			fmt.Fprintf(os.Stderr, "csm: decode status response: %v\n", err)
			os.Exit(1)
		}
		if statusResp.Job == nil {
			fmt.Fprintf(os.Stderr, "csm: status response missing job\n")
			os.Exit(1)
		}
		switch statusResp.Job.State {
		case "done", "canceled", "error":
			printScanReportWith(jobID, f.jsonOutput, send)
			return
		}
		// queued or running -- sleep then poll again
		time.Sleep(pollInterval)
	}
}

// runScanStatus handles `csm scan --status [id]`.
func runScanStatus(f scanFlags) {
	req := control.ScanStatusRequest{JobID: f.statusID}
	raw := requireDaemon(control.CmdScanStatus, req)

	if f.jsonOutput {
		printJSON(raw)
		return
	}

	var resp control.ScanStatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decode status response: %v\n", err)
		os.Exit(1)
	}

	if resp.Job != nil {
		printJobRecord(*resp.Job)
		return
	}
	if len(resp.Jobs) == 0 {
		fmt.Println("no scan jobs found")
		return
	}
	for _, j := range resp.Jobs {
		printJobRecord(j)
	}
}

// runScanReport handles `csm scan --report <id>`.
func runScanReport(f scanFlags) {
	printScanReport(f.reportID, f.jsonOutput)
}

// runScanCancel handles `csm scan --cancel <id>`.
func runScanCancel(f scanFlags) {
	req := control.ScanCancelRequest{JobID: f.cancelID}
	raw := requireDaemon(control.CmdScanCancel, req)

	if f.jsonOutput {
		printJSON(raw)
		return
	}

	var resp control.ScanCancelResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decode cancel response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("job: %s  state: %s\n", resp.JobID, resp.State)
}

// printScanReport fetches and prints the full report for jobID.
func printScanReport(jobID string, asJSON bool) {
	printScanReportWith(jobID, asJSON, sendControl)
}

// printScanReportWith is the testable core of printScanReport.
func printScanReportWith(jobID string, asJSON bool, send sendFn) {
	req := control.ScanReportRequest{JobID: jobID}
	raw, err := send(control.CmdScanReport, req)
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "csm: daemon not running (start with: systemctl start csm)")
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "csm: %v\n", err)
		os.Exit(1)
	}

	if asJSON {
		printJSON(raw)
		return
	}

	var resp control.ScanReportResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decode report response: %v\n", err)
		os.Exit(1)
	}

	printJobRecord(resp.Job)
	if resp.Total == 0 {
		fmt.Println("no findings")
		return
	}
	fmt.Printf("%d finding(s):\n\n", resp.Total)
	for _, finding := range resp.Findings {
		fmt.Println(finding.String())
		fmt.Println()
	}
}

// runScanLegacy is the original in-process `csm scan <user> [--alert]` path.
func runScanLegacy(f scanFlags) {
	cfg := loadConfigLite()
	signatures.Init(cfg.Signatures.RulesDir)

	st, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening state: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	fmt.Fprintf(os.Stderr, "Scanning account: %s\n", f.account)
	start := time.Now()

	findings := checks.RunAccountScan(cfg, st, f.account)

	elapsed := time.Since(start).Round(time.Millisecond)
	fmt.Fprintf(os.Stderr, "Scan completed in %s: %d finding(s)\n\n", elapsed, len(findings))

	if len(findings) == 0 {
		fmt.Println("No findings. Account is clean.")
		return
	}

	for _, finding := range findings {
		fmt.Println(finding.String())
		fmt.Println()
	}

	if f.sendAlert {
		var alertFindings []alert.Finding
		for _, finding := range findings {
			if strings.HasPrefix(finding.Check, "perf_") && finding.Severity == alert.Warning {
				continue
			}
			alertFindings = append(alertFindings, finding)
		}
		if err := alert.Dispatch(cfg, alertFindings); err != nil {
			fmt.Fprintf(os.Stderr, "Alert dispatch error: %v\n", err)
		}
	}
}

// printJobRecord prints a single scan job record in human-readable form.
func printJobRecord(j store.ScanJobRecord) {
	fmt.Printf("id: %s  scope: %s  target: %s  state: %s\n",
		j.ID, j.Scope, j.Target, j.State)
	if !j.Created.IsZero() {
		fmt.Printf("  created: %s\n", j.Created.Format(time.RFC3339))
	}
	if !j.Started.IsZero() {
		fmt.Printf("  started: %s\n", j.Started.Format(time.RFC3339))
	}
	if !j.Finished.IsZero() {
		fmt.Printf("  finished: %s\n", j.Finished.Format(time.RFC3339))
	}
	if j.FindingCount > 0 || j.FilesScanned > 0 {
		fmt.Printf("  findings: %d  files: %d\n", j.FindingCount, j.FilesScanned)
	}
	if j.Error != "" {
		fmt.Printf("  error: %s\n", j.Error)
	}
}
