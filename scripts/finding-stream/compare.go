package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// compare sets the legacy path's automatic blocks against what the
// admission preview did with the same findings. It reads the
// anonymized streams of one verified joined run, so a report repeats no host
// identity; it is still private, since it describes one host's responses.
//
//	finding-stream compare --findings findings.jsonl.gz --actions actions.jsonl.gz --status status.json
//
// Each daemon run is reported alone, and only the run the host's status
// was taken in is judged: the status names the entries that run expects.
// It passes the gate once it spans compareMinWindow with nothing
// unexplained and every expected entry covered; an entry still short of
// its floor holds the gate until the run spans compareMaxWindow, and is
// then named unproven.

const errCompareUsage cliError = "usage: finding-stream compare --findings FILE --actions FILE [--status FILE]"

const (
	errCompareWrite  cliError = "comparison output failed"
	errCompareCount  cliError = "comparison count overflow"
	errCompareStatus cliError = "status file does not name the admission owner's run and block entries"
)

const (
	// compareMinWindow is the shortest run the gate accepts.
	compareMinWindow = 48 * time.Hour
	// compareMaxWindow is the longest a run waits for entries short of
	// their floor before the gate names them unproven.
	compareMaxWindow = 7 * 24 * time.Hour
	// compareFloor is how many matched blocks cover an entry, or a scan
	// check that blocked.
	compareFloor = 3
)

// blockEntries are the entries whose automatic IP blocks admission runs,
// the only ones a status file may expect.
var blockEntries = map[string]bool{"scan": true, "challenge_timeout": true, "incident": true, "incident_spray": true, "central": true}

// legacyAutomatic are the reason kinds of the legacy automatic block paths.
var legacyAutomatic = map[string]bool{
	"scan": true, "scan_subnet": true, "asn_crawl": true, "challenge_timeout": true, "credential_spray": true,
	"incident": true, "netblock": true, "permblock": true, "central_intel": true,
}

// designedRefusals explain only the listed scan provenance gaps and derived
// responses without a retained root. Other refusals remain unexplained.
var designedRefusals = []string{"attribution", "policy"}

// compareShown bounds the unexplained blocks a report lists.
const compareShown = 20

type summaryKey struct {
	hourEnd  time.Time
	check    string
	decision string
	refusal  string
	entry    string
	kind     string
}

// Shape checks cannot prove a token was emitted by a particular run; the
// joined run's verifier does that. They refuse raw identities and unknown
// vocabulary before a comparison can print any input-derived field.
func compareToken(s, prefix string, bytes int) bool {
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+2*bytes {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(s, prefix))
	return err == nil && len(decoded) == bytes && strings.ToLower(s) == s
}

func compareActionShape(o anonAction) bool {
	a := NewAnonymizer(make([]byte, 32))
	for s, kind := range map[string]idKind{o.FindingID: idFinding, o.ActionID: idAction, o.IncidentID: idIncident, o.UndoOf: idAction} {
		if s != "" {
			if !compareToken(s, idPrefixes[kind]+"-", 16) {
				return false
			}
			a.ids[s] = kind
		}
	}
	for _, item := range []struct{ value, prefix string }{{o.Hostname, "host-"}, {o.Account, "acct-"}} {
		if item.value != "" {
			if !compareToken(item.value, item.prefix, 3) {
				return false
			}
			a.remember(item.value)
		}
	}
	for _, value := range []string{o.Target, o.ActorIP} {
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		switch {
		case err == nil && addr.String() == value && (anonIPv4Space.Contains(addr) || anonIPv6Space.Contains(addr)):
			a.remember(value)
		case compareToken(value, "tid-", 16):
			a.ids[value] = idTarget
			a.remember(value)
		default:
			return false
		}
	}
	return a.VerifyAction(o) == nil
}

func legacyEntry(o anonAction) string {
	switch o.ReasonKind {
	case "scan":
		return "scan"
	case "scan_subnet":
		// The mail spray subnet block, submitted with its constituents.
		return "mail_subnet"
	case "asn_crawl":
		return "asn_crawl"
	case "credential_spray":
		// The incident spray block of one address.
		return "incident_spray"
	case "central_intel":
		return "central"
	default:
		return o.ReasonKind
	}
}

func legacyKind(o anonAction) string {
	switch o.Action {
	case "block":
		return "block_ip"
	case "block_subnet":
		return "block_subnet"
	case "permblock", "promote":
		return "block_ip"
	default:
		return ""
	}
}

// listedRule identifies the exact intentionally unsupported provenance
// paths. Other policy or attribution refusals remain unexplained.
func listedRule(o anonAction, check, reason string) (string, bool) {
	entry := legacyEntry(o)
	if reason == "policy" && (entry == "netblock" || entry == "permblock" || entry == "challenge_timeout" || entry == "incident" || entry == "incident_spray") {
		return "unknown", true
	}
	if check == "" || check == "local_threat_score" {
		return "", false
	}
	scanPass := false
	for _, producer := range checks.ProducerTable() {
		if slices.Contains(producer.Spec.Checks, check) {
			scanPass = scanPass || producer.Spec.Observation == admission.ObservationScanPass
		}
	}
	if reason == "attribution" && scanPass {
		if entry == "scan" {
			return check, true
		}
		for _, derived := range checks.DerivedEntries() {
			if derived.Entry.String() == entry && slices.Contains(derived.Checks, check) &&
				(entry == "central" || entry == "incident" || entry == "incident_spray" || entry == "asn_crawl" || entry == "mail_subnet") {
				return check, true
			}
		}
	}
	return "", false
}

type compareStepKey struct {
	finding string
	kind    string
	target  anonTarget
}

func compare(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var findingsPath, actionsPath, statusPath string
	fs.StringVar(&findingsPath, "findings", "", "anonymized finding stream")
	fs.StringVar(&actionsPath, "actions", "", "anonymized action stream")
	fs.StringVar(&statusPath, "status", "", "csm status --json snapshot of the host")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || findingsPath == "" || actionsPath == "" {
		return errCompareUsage
	}
	var status *compareStatus
	if statusPath != "" {
		var err error
		if status, err = readStatus(statusPath); err != nil {
			return err
		}
	}
	checks := map[string]string{}
	if _, err := readStream(findingsPath, kindFindings, 1, func(_ int, data []byte) (time.Time, error) {
		var e alert.AuditEvent
		if err := decodeStrict(data, &e); err != nil {
			return time.Time{}, err
		}
		// Older recordings retain unstamped findings. Their IDs and checks
		// still join actions; the action summaries establish the window.
		if e.V != alert.AuditSchemaVersion || !checkName(e.Check) || e.Check == "unknown" ||
			(e.FindingID != "" && !compareToken(e.FindingID, "fid-", 16)) {
			return time.Time{}, errRowUnverified
		}
		if e.FindingID != "" {
			if prior, exists := checks[e.FindingID]; exists && prior != e.Check {
				return time.Time{}, errRowUnverified
			}
			checks[e.FindingID] = e.Check
		}
		return e.Timestamp, nil
	}); err != nil {
		return err
	}
	var actions []anonAction
	if _, err := readStream(actionsPath, kindActions, 1, func(_ int, data []byte) (time.Time, error) {
		var o anonAction
		if err := decodeStrict(data, &o); err != nil {
			return time.Time{}, err
		}
		if !compareActionShape(o) {
			return time.Time{}, errRowUnverified
		}
		actions = append(actions, o)
		return o.Timestamp, nil
	}); err != nil {
		return err
	}
	report, err := compareRuns(checks, actions, status)
	if err != nil {
		return err
	}
	if _, err = io.WriteString(stdout, report); err != nil {
		return errCompareWrite
	}
	return nil
}

// compareStatus is what a csm status --json snapshot tells compare: the
// run it was taken in, the ledger's ingress generation that the run's
// summaries carry as their epoch, and the entries whose automatic IP
// blocks the admission owner may run.
type compareStatus struct {
	run     uint64
	entries []string
}

// readStatus reads one status snapshot of at most maxStatusBytes. It reads
// nothing else from the file and repeats none of it in an error.
func readStatus(path string) (*compareStatus, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied local input
	if err != nil {
		return nil, errCompareStatus
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusBytes+1))
	if err != nil || len(data) > maxStatusBytes {
		return nil, errCompareStatus
	}
	var doc struct {
		Snapshot struct {
			Admission *struct {
				Ledger *struct {
					Ingress struct {
						Generation uint64 `json:"generation"`
					} `json:"ingress"`
				} `json:"ledger"`
				Owner *struct {
					BlockEntries []string `json:"block_entries"`
				} `json:"owner"`
			} `json:"admission"`
		} `json:"snapshot"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err = dec.Decode(&doc); err != nil {
		return nil, errCompareStatus
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, errCompareStatus
	}
	a := doc.Snapshot.Admission
	if a == nil || a.Ledger == nil || a.Ledger.Ingress.Generation == 0 || a.Owner == nil {
		return nil, errCompareStatus
	}
	status := &compareStatus{run: a.Ledger.Ingress.Generation, entries: []string{}}
	for _, e := range a.Owner.BlockEntries {
		if !blockEntries[e] {
			return nil, errCompareStatus
		}
		if !slices.Contains(status.entries, e) {
			status.entries = append(status.entries, e)
		}
	}
	return status, nil
}

// maxStatusBytes bounds the status snapshot compare reads.
const maxStatusBytes = 64 << 20

// compareReport judges the records without a status file.
func compareReport(checks map[string]string, actions []anonAction) (string, error) {
	return compareRuns(checks, actions, nil)
}

// compareRun is one daemon run's summaries: their epoch, zero for
// summaries recorded before they named their run.
type compareRun struct {
	summaries         map[summaryKey]uint64
	first, last       time.Time
	invalid, overflow uint64
}

// compareRuns reports each run apart and passes when the run the status
// was taken in passes the gate; status is nil without a status file.
func compareRuns(checks map[string]string, actions []anonAction, status *compareStatus) (string, error) {
	runs := map[uint64]*compareRun{}
	steps := map[compareStepKey][]time.Time{}
	seenAttempts := map[string]bool{}
	for _, o := range actions {
		switch {
		case o.Count != 0:
			r := runs[o.Epoch]
			if r == nil {
				r = &compareRun{summaries: map[summaryKey]uint64{}}
				runs[o.Epoch] = r
			}
			key := summaryKey{o.Timestamp.UTC(), o.Check, o.Result, o.Refusal, o.Entry, o.Action}
			if o.Count > math.MaxUint64-r.summaries[key] {
				return "", errCompareCount
			}
			r.summaries[key] += o.Count
			if r.first.IsZero() || o.Timestamp.Before(r.first) {
				r.first = o.Timestamp
			}
			if o.Timestamp.After(r.last) {
				r.last = o.Timestamp
			}
			switch o.Refusal {
			case "invalid":
				if o.Count > math.MaxUint64-r.invalid {
					return "", errCompareCount
				}
				r.invalid += o.Count
			case "queue_overflow":
				if o.Count > math.MaxUint64-r.overflow {
					return "", errCompareCount
				}
				r.overflow += o.Count
			}
		case strings.HasPrefix(o.ReasonKind, "admission_") && o.FindingID != "" && o.Result == "observe" && !seenAttempts[o.ActionID]:
			seenAttempts[o.ActionID] = true
			k := compareStepKey{o.FindingID, o.Action, o.anonTarget}
			steps[k] = append(steps[k], o.Timestamp)
		}
	}
	var b strings.Builder
	b.WriteString("admission comparison\n")
	b.WriteString("coverage: the window starts at the first summary, whose hour may be partial; counts are lower bounds; verify collector coverage, idle or missing hours and clean-stop completion\n")
	if len(runs) == 0 {
		b.WriteString("window: no admission summaries: FAIL\n")
	}
	passed := false
	for _, epoch := range slices.Sorted(maps.Keys(runs)) {
		label := "unmarked"
		if epoch != 0 {
			label = strconv.FormatUint(epoch, 10)
		}
		fmt.Fprintf(&b, "run %s\n", label)
		if runs[epoch].report(&b, checks, actions, steps, epoch, status) {
			passed = true
		}
	}
	b.WriteString("read elsewhere: Critical deferrals and queue evictions (csm status, admission outcomes), handoff p99 (csm_admission_handoff_seconds), corruption/damage (csm status and doctor), collection and clean-stop coverage (collector inventory)\n")
	switch {
	case status == nil:
		b.WriteString("verdict: FAIL: no status file\n")
	case runs[status.run] == nil:
		fmt.Fprintf(&b, "verdict: FAIL: no summaries of run %d\n", status.run)
	case passed:
		fmt.Fprintf(&b, "verdict: pass (run %d)\n", status.run)
	default:
		fmt.Fprintf(&b, "verdict: FAIL: run %d does not pass the gate\n", status.run)
	}
	return b.String(), nil
}

// report writes one run's comparison and gate, and says whether it is the
// status's run and passed.
func (r *compareRun) report(b *strings.Builder, checks map[string]string, actions []anonAction, steps map[compareStepKey][]time.Time, epoch uint64, status *compareStatus) bool {
	// A summary is stamped with the end of the hour it counts, which may
	// have begun before the run: blocks are judged from the start of that
	// hour, but the window counts from the stamp.
	start := r.first.Add(-time.Hour)
	var legacy []anonAction
	for _, o := range actions {
		if o.Count == 0 && o.Op == "respond.block_ip" && o.Actor == "daemon" && legacyKind(o) != "" && legacyAutomatic[o.ReasonKind] &&
			(o.Result == "applied" || o.Result == "dry_run") && !o.Timestamp.Before(start) && o.Timestamp.Before(r.last) {
			legacy = append(legacy, o)
		}
	}
	slices.SortStableFunc(legacy, func(a, b anonAction) int { return a.Timestamp.Compare(b.Timestamp) })
	var stepped, coalesced int
	designed := map[string]int{}
	var unexplained []anonAction
	blocked, matched := map[string]int{}, map[string]int{}
	for i, decision := range matchComparison(checks, legacy, steps, r.summaries) {
		target := legacyEntry(legacy[i])
		if target == "scan" {
			check := checks[legacy[i].FindingID]
			if check == "" {
				check = "unknown"
			}
			target += " " + check
		}
		blocked[target]++
		switch decision {
		case "step":
			stepped++
			matched[target]++
		case "coalesced":
			coalesced++
			matched[target]++
		case "":
			unexplained = append(unexplained, legacy[i])
		default:
			designed[decision]++
		}
	}
	verdict := func(ok bool) string {
		if ok {
			return "pass"
		}
		return "FAIL"
	}
	span := r.last.Sub(r.first)
	fmt.Fprintf(b, "window: %s to %s, %s: %s", r.first.UTC().Format(time.RFC3339), r.last.UTC().Format(time.RFC3339), span, verdict(span >= compareMinWindow))
	if span < compareMinWindow {
		fmt.Fprintf(b, " (needs %s)", compareMinWindow)
	}
	b.WriteString("\n")
	fmt.Fprintf(b, "legacy automatic actions: %d\n", len(legacy))
	fmt.Fprintf(b, "  matched by an admission step: %d\n", stepped)
	fmt.Fprintf(b, "  matched by a coalesced admission: %d\n", coalesced)
	total, parts := 0, []string{}
	for _, reason := range designedRefusals {
		if designed[reason] > 0 {
			total += designed[reason]
			parts = append(parts, fmt.Sprintf("%s %d", reason, designed[reason]))
		}
	}
	fmt.Fprintf(b, "  explained by a designed refusal: %d", total)
	if len(parts) > 0 {
		fmt.Fprintf(b, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintf(b, "\n  unexplained: %d: %s\n", len(unexplained), verdict(len(unexplained) == 0))
	for _, o := range unexplained[:min(len(unexplained), compareShown)] {
		id, check := o.FindingID, checks[o.FindingID]
		if id == "" {
			id, check = "no finding id", ""
		}
		line := strings.Join(slices.DeleteFunc([]string{id, check, o.ReasonKind, o.Timestamp.UTC().Format(time.RFC3339)}, func(s string) bool { return s == "" }), " ")
		fmt.Fprintf(b, "    %s\n", line)
	}
	fmt.Fprintf(b, "invalid refusals: %d: %s\n", r.invalid, verdict(r.invalid == 0))
	fmt.Fprintf(b, "queue overflow refusals: %d: %s\n", r.overflow, verdict(r.overflow == 0))
	switch {
	case epoch == 0:
		b.WriteString("gate: FAIL: summaries name no run\n")
		return false
	case status == nil:
		b.WriteString("gate: FAIL: no status file\n")
		return false
	case epoch != status.run:
		fmt.Fprintf(b, "gate: not judged: the status is of run %d\n", status.run)
		return false
	}
	expected := status.entries
	// The floor covers each expected entry; a scan check counts apart once
	// it blocked, and an expected scan entry that never blocked is short.
	targets := map[string]bool{}
	for _, e := range expected {
		if e != "scan" {
			targets[e] = true
		}
	}
	scanBlocked := false
	for target := range blocked {
		if strings.HasPrefix(target, "scan ") && slices.Contains(expected, "scan") {
			targets[target], scanBlocked = true, true
		}
	}
	if slices.Contains(expected, "scan") && !scanBlocked {
		targets["scan"] = true
	}
	fmt.Fprintf(b, "coverage floor: %d matched blocks for each expected entry and each scan check that blocked\n", compareFloor)
	var short []string
	for _, target := range slices.Sorted(maps.Keys(targets)) {
		state := "pass"
		if matched[target] < compareFloor {
			state = "short"
			short = append(short, target)
		}
		fmt.Fprintf(b, "  %s: %d legacy, %d matched: %s\n", target, blocked[target], matched[target], state)
	}
	var reasons []string
	if span < compareMinWindow {
		reasons = append(reasons, "needs "+compareMinWindow.String())
	}
	if len(unexplained) > 0 || r.invalid > 0 || r.overflow > 0 {
		reasons = append(reasons, "unexplained, invalid or queue overflow decisions")
	}
	if len(short) > 0 && span < compareMaxWindow {
		reasons = append(reasons, "coverage short until "+compareMaxWindow.String())
	}
	switch {
	case len(reasons) > 0:
		fmt.Fprintf(b, "gate: FAIL: %s\n", strings.Join(reasons, "; "))
		return false
	case len(short) > 0:
		fmt.Fprintf(b, "gate: pass; unproven: %s\n", strings.Join(short, ", "))
	default:
		b.WriteString("gate: pass\n")
	}
	return true
}
