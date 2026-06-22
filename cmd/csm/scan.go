package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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
	all            bool
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
//	csm scan <user> [--alert]
//	csm scan <user> --full [--wait] [--json] [--respect-ignores] [--quarantine]
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
			f.all = true
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

	queryCount := 0
	if f.statusGiven {
		queryCount++
	}
	if f.reportID != "" {
		queryCount++
	}
	if f.cancelID != "" {
		queryCount++
	}
	if queryCount > 1 {
		return scanFlags{}, errors.New("use only one of --status, --report, or --cancel")
	}

	isQuery := queryCount == 1
	if isQuery && f.account != "" {
		return scanFlags{}, errors.New("account username is not allowed with --status/--report/--cancel")
	}
	if isQuery {
		if f.all || f.full || f.wait || f.quarantine || f.respectIgnores || f.sendAlert {
			return scanFlags{}, errors.New("scan query flags cannot be combined with scan execution flags")
		}
		return f, nil
	}

	// --all validation.
	if f.all {
		if !f.full {
			return scanFlags{}, errors.New("--all requires --full")
		}
		if f.account != "" {
			return scanFlags{}, errors.New("cannot combine --all with an account username")
		}
		// Server-wide quarantine would remediate across every account from a
		// single report-only audit pass; too dangerous to trigger blind. An
		// operator quarantines per-account after reviewing the --all report.
		if f.quarantine {
			return scanFlags{}, errors.New("--quarantine is not supported with --all; quarantine per account after review")
		}
		return f, nil
	}

	if f.account == "" {
		return scanFlags{}, errors.New("account username required")
	}
	if !control.ValidScanAccountTarget(f.account) {
		return scanFlags{}, fmt.Errorf("invalid account username: %q", f.account)
	}
	if f.quarantine && !f.full {
		return scanFlags{}, errors.New("--quarantine requires --full")
	}
	if f.wait && !f.full {
		return scanFlags{}, errors.New("--wait requires --full")
	}
	if f.respectIgnores && !f.full {
		return scanFlags{}, errors.New("--respect-ignores requires --full")
	}
	if f.jsonOutput && !f.full {
		return scanFlags{}, errors.New("--json requires --full or a scan query")
	}
	if f.sendAlert && f.full {
		return scanFlags{}, errors.New("--alert cannot be used with --full")
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
	fmt.Fprintf(os.Stderr, "  csm scan --all --full [--wait] [--json] [--respect-ignores]\n")
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
// The production poll interval (2 s) is injected so tests can use a
// sub-millisecond interval without sleeping.
func runScanFullWith(f scanFlags, send sendFn) {
	runScanFullWithInterval(f, send, 2*time.Second)
}

// runScanFullWithInterval is the inner core used by runScanFullWith and tests.
// interval is the sleep between status polls when --wait is set.
func runScanFullWithInterval(f scanFlags, send sendFn, interval time.Duration) {
	req := control.ScanEnqueueRequest{
		RespectIgnores: f.respectIgnores,
		Quarantine:     f.quarantine,
	}
	if f.all {
		req.Scope = "all"
		req.Target = ""
	} else {
		req.Scope = "account"
		req.Target = f.account
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
		time.Sleep(interval)
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
// requireDaemon handles the "not running" / transport error and may os.Exit;
// that exit path is preserved here in the production wrapper, not in the core.
func runScanCancel(f scanFlags) {
	runScanCancelWith(f, sendControl)
}

// runScanCancelWith is the testable core of runScanCancel.
// It accepts an injected sender so tests can drive it without hitting
// requireDaemon / sendControl.
func runScanCancelWith(f scanFlags, send sendFn) {
	req := control.ScanCancelRequest{JobID: f.cancelID}
	raw, err := send(control.CmdScanCancel, req)
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "csm: daemon not running (start with: systemctl start csm)")
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "csm: %v\n", err)
		os.Exit(1)
	}

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
// It writes to os.Stdout; see printScanReportTo for the io.Writer variant.
func printScanReportWith(jobID string, asJSON bool, send sendFn) {
	printScanReportTo(jobID, asJSON, os.Stdout, send)
}

// printScanReportTo is the inner core: it writes the human-readable (or JSON)
// report for jobID to w. Production callers pass os.Stdout; tests pass a
// bytes.Buffer so they can assert on the output without capturing os.Stdout.
func printScanReportTo(jobID string, asJSON bool, w io.Writer, send sendFn) {
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
		// Pass through raw JSON to w — no coverage header, no decoration.
		printJSONTo(w, raw)
		return
	}

	var resp control.ScanReportResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "csm: decode report response: %v\n", err)
		os.Exit(1)
	}

	printJobRecordTo(w, resp.Job)

	// Coverage header for full-scan jobs (Options map present).
	if resp.Job.Options != nil {
		printCoverageHeader(w, resp.Job, resp.Findings)
	}

	if resp.Total == 0 {
		fmt.Fprintln(w, "no findings")
		return
	}
	fmt.Fprintf(w, "%d finding(s):\n\n", resp.Total)

	if resp.Job.Scope == "all" {
		printFindingsGroupedByAccountTo(w, resp.Findings)
	} else {
		for _, finding := range resp.Findings {
			printFindingTo(w, finding)
		}
	}
}

// printCoverageHeader writes the full-scan coverage block to w.
// It derives counts from the findings slice already fetched; no additional
// RPCs are made. Only lines whose datum is available/non-zero are printed.
func printCoverageHeader(w io.Writer, job store.ScanJobRecord, findings []alert.Finding) {
	// Build scope summary.
	scope := job.Scope
	if scope == "all" {
		if job.AccountsTotal > 0 {
			fmt.Fprintf(w, "coverage: all accounts (%d/%d done)\n", job.AccountsDone, job.AccountsTotal)
		} else {
			fmt.Fprintln(w, "coverage: all accounts")
		}
	} else {
		target := job.Target
		if target == "" {
			target = "(unknown)"
		}
		fmt.Fprintf(w, "coverage: %s\n", target)
	}

	// mode: quarantine or report-only.
	mode := "report-only"
	if optBool(job.Options, "quarantine") {
		mode = "quarantine"
	}
	fmt.Fprintf(w, "  mode: %s\n", mode)

	// ignores: bypassed or respected. Only emit when the option was actually
	// recorded, so an absent key does not render a misleading "bypassed".
	if _, ok := job.Options["respect_ignores"]; ok {
		if optBool(job.Options, "respect_ignores") {
			fmt.Fprintln(w, "  ignores: respected")
		} else {
			fmt.Fprintln(w, "  ignores: bypassed")
		}
	}

	// max file size: only when > 0.
	if mb := optMB(job.Options, "max_file_bytes"); mb > 0 {
		fmt.Fprintf(w, "  max file size: %d MB\n", mb)
	}

	// files scanned: only when > 0.
	if job.FilesScanned > 0 {
		fmt.Fprintf(w, "  files scanned: %d\n", job.FilesScanned)
	}

	// Derived counts from the findings page already in hand.
	oversize := countCheck(findings, "full_scan_file_too_large")
	if oversize > 0 {
		fmt.Fprintf(w, "  oversize files skipped: %d\n", oversize)
	}
	truncated := countCheck(findings, "account_scan_truncated")
	if truncated > 0 {
		fmt.Fprintf(w, "  truncated path sets: %d\n", truncated)
	}

	fmt.Fprintln(w)
}

// optBool reads a bool from a map[string]any, tolerating missing keys and
// float64 values (JSON generic unmarshal encodes JSON numbers as float64).
func optBool(opts map[string]any, key string) bool {
	v, ok := opts[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case float64:
		return b != 0
	}
	return false
}

// optMB reads an integer megabyte value from a map[string]any key that holds
// a byte count. Returns 0 if absent, zero, or not a number.
func optMB(opts map[string]any, key string) int64 {
	const oneMB = 1 << 20
	v, ok := opts[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		if n <= 0 {
			return 0
		}
		return int64(n) / oneMB
	case int:
		if n <= 0 {
			return 0
		}
		return int64(n) / oneMB
	case int64:
		if n <= 0 {
			return 0
		}
		return n / oneMB
	}
	return 0
}

// countCheck returns the number of findings whose Check field equals check.
func countCheck(findings []alert.Finding, check string) int {
	n := 0
	for _, f := range findings {
		if f.Check == check {
			n++
		}
	}
	return n
}

// printFindingTo writes one finding (plus remediation line if set) to w.
func printFindingTo(w io.Writer, finding alert.Finding) {
	fmt.Fprintln(w, finding.String())
	if finding.RemediationStatus != "" {
		if finding.RemediationDetail != "" {
			fmt.Fprintf(w, "  remediation: %s — %s\n", finding.RemediationStatus, finding.RemediationDetail)
		} else {
			fmt.Fprintf(w, "  remediation: %s\n", finding.RemediationStatus)
		}
	}
	fmt.Fprintln(w)
}

// printFindingsGroupedByAccountTo groups findings by TenantID and writes a
// header line per account followed by that account's findings to w.
func printFindingsGroupedByAccountTo(w io.Writer, findings []alert.Finding) {
	// Collect the unique accounts, then sort alphabetically below for
	// deterministic, predictable output on large server-wide reports.
	seen := make(map[string]bool)
	var order []string
	byAccount := make(map[string][]alert.Finding)
	for _, f := range findings {
		acct := f.TenantID
		if acct == "" {
			acct = "(unknown)"
		}
		if !seen[acct] {
			seen[acct] = true
			order = append(order, acct)
		}
		byAccount[acct] = append(byAccount[acct], f)
	}
	sort.Strings(order)
	for _, acct := range order {
		fmt.Fprintf(w, "=== account: %s ===\n\n", acct)
		for _, finding := range byAccount[acct] {
			printFindingTo(w, finding)
		}
	}
}

// printJSONTo writes raw as pretty-printed JSON to w.
// It mirrors the behaviour of printJSON (in incidents.go) but accepts a
// caller-supplied writer so callers can direct output to any io.Writer.
func printJSONTo(w io.Writer, raw json.RawMessage) {
	var pretty interface{}
	if err := json.Unmarshal(raw, &pretty); err != nil {
		fmt.Fprintln(w, string(raw))
		return
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		fmt.Fprintln(w, string(raw))
		return
	}
	fmt.Fprintln(w, string(out))
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
	printJobRecordTo(os.Stdout, j)
}

// printJobRecordTo writes a single scan job record in human-readable form to w.
func printJobRecordTo(w io.Writer, j store.ScanJobRecord) {
	fmt.Fprintf(w, "id: %s  scope: %s  target: %s  state: %s\n",
		j.ID, j.Scope, j.Target, j.State)
	if !j.Created.IsZero() {
		fmt.Fprintf(w, "  created: %s\n", j.Created.Format(time.RFC3339))
	}
	if !j.Started.IsZero() {
		fmt.Fprintf(w, "  started: %s\n", j.Started.Format(time.RFC3339))
	}
	if !j.Finished.IsZero() {
		fmt.Fprintf(w, "  finished: %s\n", j.Finished.Format(time.RFC3339))
	}
	if j.Scope == "all" && j.AccountsTotal > 0 {
		fmt.Fprintf(w, "  accounts: %d/%d", j.AccountsDone, j.AccountsTotal)
		if j.CurrentAccount != "" {
			fmt.Fprintf(w, "  current: %s", j.CurrentAccount)
		}
		fmt.Fprintln(w)
	}
	if j.FindingCount > 0 || j.FilesScanned > 0 {
		fmt.Fprintf(w, "  findings: %d  files: %d\n", j.FindingCount, j.FilesScanned)
	}
	if j.Error != "" {
		fmt.Fprintf(w, "  error: %s\n", j.Error)
	}
}
