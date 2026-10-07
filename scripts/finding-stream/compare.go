package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// compare sets the legacy path's automatic blocks against what the
// admission preview did with the same findings (ruling R11). It reads the
// anonymized streams of one verified joined run, so a report repeats no host
// identity; it is still private, since it describes one host's responses.
//
//	finding-stream compare --findings findings.jsonl.gz --actions actions.jsonl.gz

const errCompareUsage cliError = "usage: finding-stream compare --findings FILE --actions FILE"

// compareMinWindow is the shortest preview the comparison accepts (R11).
const compareMinWindow = 7 * 24 * time.Hour

// legacyAutomatic are the reason kinds of the legacy automatic block paths.
var legacyAutomatic = map[string]bool{
	"scan": true, "scan_subnet": true, "asn_crawl": true, "challenge_timeout": true, "credential_spray": true,
	"incident": true, "netblock": true, "permblock": true, "central_intel": true,
}

// designedRefusals explain a legacy block admission did not take: a finding
// without provenance (attribution, plan 2) and a path admission does not
// serve yet (policy: an unregistered producer or entry, or a derived path
// without a retained root, ruling R7).
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
	case "scan", "scan_subnet":
		return "scan"
	case "asn_crawl":
		return "asn_crawl"
	case "credential_spray":
		return "mail_subnet"
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
	if reason == "policy" && (entry == "netblock" || entry == "permblock" || entry == "challenge_timeout" || entry == "incident") {
		return "unknown", true
	}
	if check == "" || check == "local_threat_score" {
		return "", false
	}
	registered, scanPass := false, false
	for _, producer := range checks.ProducerTable() {
		if slices.Contains(producer.Spec.Checks, check) {
			registered = true
			scanPass = scanPass || producer.Spec.Observation == admission.ObservationScanPass
		}
	}
	if reason == "attribution" && scanPass && (entry == "scan" || entry == "central" || entry == "incident" || entry == "asn_crawl" || entry == "mail_subnet") {
		return check, true
	}
	if reason == "policy" && !registered && entry == "scan" && checks.AddressEvidence(check, alert.Critical) {
		return check, true
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
	var findingsPath, actionsPath string
	fs.StringVar(&findingsPath, "findings", "", "anonymized finding stream")
	fs.StringVar(&actionsPath, "actions", "", "anonymized action stream")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || findingsPath == "" || actionsPath == "" {
		return errCompareUsage
	}
	checks := map[string]string{}
	if _, err := readStream(findingsPath, kindFindings, 1, func(_ int, data []byte) (time.Time, error) {
		var e alert.AuditEvent
		if err := decodeStrict(data, &e); err != nil {
			return time.Time{}, err
		}
		if e.V != alert.AuditSchemaVersion || e.Timestamp.IsZero() || !checkName(e.Check) || e.Check == "unknown" ||
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
	_, err := io.WriteString(stdout, compareReport(checks, actions))
	return err
}

func compareReport(checks map[string]string, actions []anonAction) string {
	summaries := map[summaryKey]uint64{}
	steps := map[compareStepKey][]time.Time{}
	seenAttempts := map[string]bool{}
	var first, last time.Time
	var invalid, overflow uint64
	for _, o := range actions {
		switch {
		case o.Count != 0:
			summaries[summaryKey{o.Timestamp.UTC(), o.Check, o.Result, o.Refusal, o.Entry, o.Action}] += o.Count
			if first.IsZero() || o.Timestamp.Before(first) {
				first = o.Timestamp
			}
			if o.Timestamp.After(last) {
				last = o.Timestamp
			}
			switch o.Refusal {
			case "invalid":
				invalid += o.Count
			case "queue_overflow":
				overflow += o.Count
			}
		case strings.HasPrefix(o.ReasonKind, "admission_") && o.FindingID != "" && o.Result == "observe" && !seenAttempts[o.ActionID]:
			seenAttempts[o.ActionID] = true
			k := compareStepKey{o.FindingID, o.Action, o.anonTarget}
			steps[k] = append(steps[k], o.Timestamp)
		}
	}
	// A summary is stamped with the end of the hour it counts.
	start := first.Add(-time.Hour)
	var legacy []anonAction
	for _, o := range actions {
		if o.Count == 0 && o.Op == "respond.block_ip" && o.Actor == "daemon" && legacyKind(o) != "" && legacyAutomatic[o.ReasonKind] &&
			(o.Result == "applied" || o.Result == "dry_run") && !first.IsZero() && !o.Timestamp.Before(start) && o.Timestamp.Before(last) {
			legacy = append(legacy, o)
		}
	}
	slices.SortStableFunc(legacy, func(a, b anonAction) int { return a.Timestamp.Compare(b.Timestamp) })
	// take spends one counted decision for check in the same or an adjacent
	// hour, since either handoff or legacy completion can cross the hour.
	take := func(at time.Time, check, decision, refusal, entry, kind string) bool {
		end := at.UTC().Truncate(time.Hour).Add(time.Hour)
		for _, hourEnd := range []time.Time{end, end.Add(-time.Hour), end.Add(time.Hour)} {
			k := summaryKey{hourEnd, check, decision, refusal, entry, kind}
			if summaries[k] > 0 {
				summaries[k]--
				return true
			}
		}
		return false
	}
	var stepped, coalesced int
	designed := map[string]int{}
	var unexplained []anonAction
	for _, o := range legacy {
		check := checks[o.FindingID]
		switch {
		case func() bool {
			if o.Action == "permblock" || o.Action == "promote" {
				return false
			}
			key := compareStepKey{o.FindingID, legacyKind(o), o.anonTarget}
			for i, at := range steps[key] {
				if d := at.Sub(o.Timestamp); d >= -time.Hour && d <= time.Hour {
					steps[key] = slices.Delete(steps[key], i, i+1)
					return true
				}
			}
			return false
		}():
			stepped++
		case o.FindingID != "" && take(o.Timestamp, check, "coalesced", "", legacyEntry(o), legacyKind(o)):
			coalesced++
		default:
			explained := false
			for _, reason := range designedRefusals {
				if ruleCheck, listed := listedRule(o, check, reason); listed && take(o.Timestamp, ruleCheck, "refused", reason, legacyEntry(o), legacyKind(o)) {
					designed[reason]++
					explained = true
					break
				}
			}
			if !explained {
				unexplained = append(unexplained, o)
			}
		}
	}
	verdict := func(ok bool) string {
		if ok {
			return "pass"
		}
		return "FAIL"
	}
	var b strings.Builder
	b.WriteString("admission comparison\n")
	b.WriteString("coverage: summary-hour span is nominal; counts are lower bounds; boundary hours may be partial; verify collector coverage, idle or missing hours and clean-stop completion\n")
	if first.IsZero() {
		b.WriteString("window: no admission summaries: FAIL\n")
	} else {
		span := last.Sub(start)
		fmt.Fprintf(&b, "window: %s to %s, %s: %s", start.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339), span, verdict(span >= compareMinWindow))
		if span < compareMinWindow {
			fmt.Fprintf(&b, " (needs %s)", compareMinWindow)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "legacy automatic actions: %d\n", len(legacy))
	fmt.Fprintf(&b, "  matched by an admission step: %d\n", stepped)
	fmt.Fprintf(&b, "  matched by a coalesced admission: %d\n", coalesced)
	total, parts := 0, []string{}
	for _, reason := range designedRefusals {
		if designed[reason] > 0 {
			total += designed[reason]
			parts = append(parts, fmt.Sprintf("%s %d", reason, designed[reason]))
		}
	}
	fmt.Fprintf(&b, "  explained by a designed refusal: %d", total)
	if len(parts) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintf(&b, "\n  unexplained: %d: %s\n", len(unexplained), verdict(len(unexplained) == 0))
	for _, o := range unexplained[:min(len(unexplained), compareShown)] {
		id, check := o.FindingID, checks[o.FindingID]
		if id == "" {
			id, check = "no finding id", ""
		}
		line := strings.Join(slices.DeleteFunc([]string{id, check, o.ReasonKind, o.Timestamp.UTC().Format(time.RFC3339)}, func(s string) bool { return s == "" }), " ")
		fmt.Fprintf(&b, "    %s\n", line)
	}
	fmt.Fprintf(&b, "invalid refusals: %d: %s\n", invalid, verdict(invalid == 0))
	fmt.Fprintf(&b, "queue overflow refusals: %d: %s\n", overflow, verdict(overflow == 0))
	b.WriteString("read elsewhere: Critical deferrals and queue evictions (csm status, admission outcomes), handoff p99 (csm_admission_handoff_seconds), corruption/damage (csm status and doctor), collection and clean-stop coverage (collector inventory)\n")
	return b.String()
}
