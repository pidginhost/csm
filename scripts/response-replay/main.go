// Command response-replay replays a recorded finding stream through a model
// of the legacy scan admission path (the hourly block limit, the pending
// queue and the temporary deny limit) and writes an aggregate report.
//
//	response-replay --findings host.jsonl.gz --out report.json \
//	    --max-blocks-per-hour 200 --deny-temp-ip-limit 500 --seed 1 --hour-zone UTC \
//	    [--block-expiry 24h] [--manifest manifest.json] \
//	    [--challenge-enabled=true] [--http-scanner-action challenge] [--block-cpanel-logins]
//
// The report holds counts, distributions, the policy and assumptions it was
// computed under and the mechanisms it does not model; never an address, id,
// name, path or text from the recording. A replay is a hypothesis: it says
// what the model does with the recorded findings, not what the host did or
// whether any block was right.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // the hour zone must not depend on the replay host's zone files

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/responsereplay"
)

func main() {
	if err := newRun().execute(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "response-replay:", err)
		os.Exit(1)
	}
}

// cliError is a fixed message; no error repeats a path or input value.
type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage            cliError = "usage: response-replay --findings FILE --out FILE --max-blocks-per-hour N --deny-temp-ip-limit N --seed N --hour-zone ZONE [--block-expiry D] [--manifest FILE] [--challenge-enabled=BOOL] [--http-scanner-action challenge|block] [--block-cpanel-logins]"
	errPolicy           cliError = "invalid policy value"
	errRevision         cliError = "a report needs a build of a known source revision without local changes"
	errOutputAlias      cliError = "the report must not replace the recording or the manifest"
	errUnsafeOutput     cliError = "the report path exists and is not a regular file"
	errOutputExists     cliError = "the report path already exists; choose a new one"
	errWrite            cliError = "writing the report failed"
	errSeverity         cliError = "a finding has an unknown severity"
	errManifestMismatch cliError = "the manifest does not describe this recording"
)

// Offline defaults of the live path, fixed in its code rather than config.
const (
	pendingBound  = 1000
	pendingMaxAge = 2 * time.Hour
)

type toolRevision struct {
	Revision  string `json:"revision"`
	Dirty     bool   `json:"dirty"`
	GoVersion string `json:"go_version"`
}

func (t toolRevision) clean() bool {
	if t.Dirty || (len(t.Revision) != 40 && len(t.Revision) != 64) {
		return false
	}
	return strings.Trim(t.Revision, "0123456789abcdef") == ""
}

// readBuildRevision reads the VCS stamp go build embeds; a build without it,
// or without the modified flag, counts as unknown.
func readBuildRevision() toolRevision {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return toolRevision{Dirty: true}
	}
	t := toolRevision{GoVersion: info.GoVersion, Dirty: true}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			t.Revision = s.Value
		case "vcs.modified":
			t.Dirty = s.Value != "false"
		}
	}
	return t
}

// reportFile is the staged report file.
type reportFile interface {
	io.Writer
	Sync() error
	Close() error
	Name() string
}

// replayRun holds what a test may replace: the build stamp and the
// filesystem steps of publishing the report.
type replayRun struct {
	revision   func() toolRevision
	createTemp func(dir, pattern string) (reportFile, error)
	rename     func(oldpath, newpath string) error
}

func newRun() *replayRun {
	return &replayRun{
		revision:   readBuildRevision,
		createTemp: func(dir, pattern string) (reportFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
	}
}

type options struct {
	findings, out, manifest, hourZone, blockExpiry, scannerAction string
	maxPerHour, denyTempLimit                                     int
	seed                                                          int64
	challengeEnabled, blockCpanelLogins, reconstructReputation    bool
	set                                                           map[string]bool
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("response-replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o options
	fs.StringVar(&o.findings, "findings", "", "recorded finding stream (JSONL, plain or gzip)")
	fs.StringVar(&o.out, "out", "", "report path")
	fs.StringVar(&o.manifest, "manifest", "", "the recording tool's bundle manifest")
	fs.StringVar(&o.hourZone, "hour-zone", "", "zone the live clock formats its hour key in")
	fs.StringVar(&o.blockExpiry, "block-expiry", "", "scan block lease (default: the live default)")
	fs.StringVar(&o.scannerAction, "http-scanner-action", "challenge", "challenge or block")
	fs.IntVar(&o.maxPerHour, "max-blocks-per-hour", 0, "live cap; 0 or less means the live default")
	fs.IntVar(&o.denyTempLimit, "deny-temp-ip-limit", 0, "temporary deny limit; 0 means unlimited")
	fs.Int64Var(&o.seed, "seed", 0, "seed of the reproducible drain order")
	fs.BoolVar(&o.challengeEnabled, "challenge-enabled", true, "whether challenge routing is on")
	fs.BoolVar(&o.blockCpanelLogins, "block-cpanel-logins", false, "whether cPanel login checks may block")
	fs.BoolVar(&o.reconstructReputation, "reconstruct-reputation-source", false, "recover ip_reputation addresses from their message")
	// A flag error names the flag or value it rejected.
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return options{}, errUsage
	}
	o.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	for _, name := range []string{"findings", "out", "max-blocks-per-hour", "deny-temp-ip-limit", "seed", "hour-zone"} {
		if !o.set[name] {
			return options{}, errUsage
		}
	}
	if o.findings == "" || o.out == "" {
		return options{}, errUsage
	}
	return o, nil
}

// policyInfo is every effective setting, defaults and normalisations
// included, so a report says exactly what it assumed.
type policyInfo struct {
	MaxBlocksPerHour          int    `json:"max_blocks_per_hour"`
	MaxBlocksPerHourDefaulted bool   `json:"max_blocks_per_hour_defaulted"`
	DenyTempIPLimit           int    `json:"deny_temp_ip_limit"`
	BlockExpiryNS             int64  `json:"block_expiry_ns"`
	BlockExpiryDefaulted      bool   `json:"block_expiry_defaulted"`
	PendingBound              int    `json:"pending_bound"`
	PendingMaxAgeNS           int64  `json:"pending_max_age_ns"`
	HourZone                  string `json:"hour_zone"`
	ChallengeEnabled          bool   `json:"challenge_enabled"`
	HTTPScannerAction         string `json:"http_scanner_action"`
	BlockCpanelLogins         bool   `json:"block_cpanel_logins"`
	// The audit log does not record a finding's structured source address.
	// When set, ip_reputation addresses are recovered from the producer's
	// message form; the report counts and states it.
	ReconstructReputationSource bool `json:"reconstruct_reputation_source"`
}

func resolvePolicy(o options) (policyInfo, *time.Location, error) {
	p := policyInfo{
		MaxBlocksPerHour: o.maxPerHour, DenyTempIPLimit: o.denyTempLimit, PendingBound: pendingBound,
		PendingMaxAgeNS: int64(pendingMaxAge), HourZone: o.hourZone, ChallengeEnabled: o.challengeEnabled,
		HTTPScannerAction: o.scannerAction, BlockCpanelLogins: o.blockCpanelLogins,
		ReconstructReputationSource: o.reconstructReputation,
	}
	// The live path treats a cap of zero or less as the default, never as
	// "block nothing".
	if p.MaxBlocksPerHour <= 0 {
		p.MaxBlocksPerHour, p.MaxBlocksPerHourDefaulted = config.DefaultMaxBlocksPerHour, true
	}
	expiry := o.blockExpiry
	if !o.set["block-expiry"] {
		expiry, p.BlockExpiryDefaulted = config.DefaultBlockExpiry, true
	}
	d, err := time.ParseDuration(expiry)
	if err != nil || d <= 0 || p.DenyTempIPLimit < 0 || (p.HTTPScannerAction != "challenge" && p.HTTPScannerAction != "block") {
		return policyInfo{}, nil, errPolicy
	}
	p.BlockExpiryNS = int64(d)
	// "Local" is whatever zone the replay host has, so a report would not
	// reproduce elsewhere.
	loc, err := time.LoadLocation(o.hourZone)
	if err != nil || o.hourZone == "" || o.hourZone == "Local" {
		return policyInfo{}, nil, errPolicy
	}
	return p, loc, nil
}

func parseSeverity(s string) (alert.Severity, bool) {
	for _, sev := range []alert.Severity{alert.Warning, alert.High, alert.Critical} {
		if sev.String() == s {
			return sev, true
		}
	}
	return 0, false
}

func toAlert(f responsereplay.Finding) alert.Finding {
	sev, _ := parseSeverity(f.Severity)
	return alert.Finding{Check: f.Check, Severity: sev, Message: f.Message, Details: f.Details}
}

// newClassifier builds the model's decisions from the live registry
// wrappers, under the report's routing settings. The counter records how
// many addresses came from reconstruction.
func newClassifier(o options) (responsereplay.Classifier, *int) {
	reconstructed := new(int)
	cfg := &config.Config{}
	cfg.Challenge.Enabled = o.challengeEnabled
	cfg.AutoResponse.HTTPScannerAction = o.scannerAction
	cfg.AutoResponse.BlockCpanelLogins = o.blockCpanelLogins
	return responsereplay.Classifier{
		Blockable:      func(f responsereplay.Finding) bool { return checks.BlockableFinding(toAlert(f), o.blockCpanelLogins) },
		ChallengeFirst: func(f responsereplay.Finding) bool { return checks.ChallengeRoutesFinding(cfg, toAlert(f)) },
		SourceIP: func(f responsereplay.Finding) string {
			if ip := checks.ExtractIPFromFinding(toAlert(f)); ip != "" || !o.reconstructReputation {
				return ip
			}
			ip := checks.ReputationMessageSourceIP(toAlert(f))
			if ip != "" {
				*reconstructed++
			}
			return ip
		},
		ExemptBlock: func(f responsereplay.Finding) (responsereplay.ObservedBlock, bool) {
			obs, kind := classifyObservation(f)
			return obs, kind == observationNonScan
		},
	}, reconstructed
}

// autoBlockMessage is the live AUTO-BLOCK finding for one address.
var autoBlockMessage = regexp.MustCompile(`^AUTO-BLOCK: (\S+) blocked \(expires in (\S+)\)$`)

type observationKind int

const (
	observationNone             observationKind = iota // not an auto_block row
	observationUnclassified                            // an auto_block row that is not a single live block
	observationOther                                   // a live block from the scan path or an unknown path
	observationNonScan                                 // a live exempt block the model applies
	observationNonScanUnmodeled                        // an exempt block without a positive lease
	observationASNCrawl                                // an ASN-crawl subnet block
	observationSubnet                                  // a subnet spray block
	observationNetblock                                // a netblock escalation
	observationPermblock                               // a permanent promotion
	observationDryRun                                  // a dry-run notice
)

// The live forms of the other auto_block rows.
var (
	asnCrawlMessage  = regexp.MustCompile(`^AUTO-BLOCK-SUBNET: \S+ blocked \(asn-crawl\)$`)
	subnetMessage    = regexp.MustCompile(`^AUTO-BLOCK-SUBNET: \S+ blocked$`)
	netblockMessage  = regexp.MustCompile(`^AUTO-NETBLOCK: \S+ blocked \(\d+ IPs from same subnet\)$`)
	permblockMessage = regexp.MustCompile(`^AUTO-PERMBLOCK: \S+ promoted to permanent block \(\d+ temp blocks\)$`)
	dryRunMessage    = regexp.MustCompile(`^AUTO-(BLOCK|BLOCK-SUBNET|NETBLOCK) \[dry-run\]: `)
)

// classifyObservation recognises a recorded block from a path outside the
// scan budget by the reason ApplyBlock writes. It is a bounded parser of
// the live finding's form, not source attribution.
func classifyObservation(f responsereplay.Finding) (responsereplay.ObservedBlock, observationKind) {
	if f.Check != "auto_block" {
		return responsereplay.ObservedBlock{}, observationNone
	}
	critical := f.Severity == alert.Critical.String()
	switch {
	case dryRunMessage.MatchString(f.Message) && f.Severity == alert.Warning.String():
		return responsereplay.ObservedBlock{}, observationDryRun
	case critical && asnCrawlMessage.MatchString(f.Message):
		return responsereplay.ObservedBlock{}, observationASNCrawl
	case critical && subnetMessage.MatchString(f.Message):
		return responsereplay.ObservedBlock{}, observationSubnet
	case critical && netblockMessage.MatchString(f.Message):
		return responsereplay.ObservedBlock{}, observationNetblock
	case critical && permblockMessage.MatchString(f.Message):
		return responsereplay.ObservedBlock{}, observationPermblock
	}
	m := autoBlockMessage.FindStringSubmatch(f.Message)
	if !critical || m == nil || net.ParseIP(m[1]) == nil {
		return responsereplay.ObservedBlock{}, observationUnclassified
	}
	reason, ok := strings.CutPrefix(f.Details, "Reason: ")
	nonScan := false
	for _, prefix := range responsereplay.NonScanReasonPrefixes {
		nonScan = nonScan || (ok && strings.HasPrefix(reason, prefix))
	}
	if !nonScan {
		return responsereplay.ObservedBlock{}, observationOther
	}
	ttl, err := time.ParseDuration(m[2])
	if err != nil || ttl <= 0 {
		return responsereplay.ObservedBlock{}, observationNonScanUnmodeled
	}
	return responsereplay.ObservedBlock{IP: m[1], TTL: ttl}, observationNonScan
}

type report struct {
	ReportVersion int              `json:"report_version"`
	Model         string           `json:"model"`
	ModelVersion  int              `json:"model_version"`
	Source        toolRevision     `json:"source"`
	Order         orderInfo        `json:"order"`
	Policy        policyInfo       `json:"policy"`
	Input         inputInfo        `json:"input"`
	Manifest      *manifestInfo    `json:"manifest,omitempty"`
	Coverage      coverageInfo     `json:"coverage"`
	Recorded      recordedInfo     `json:"recorded"`
	Hypothetical  hypotheticalInfo `json:"hypothetical"`
	Distributions distributionInfo `json:"distributions"`
	Assumptions   []string         `json:"assumptions"`
	Gaps          []string         `json:"gaps"`
}

type orderInfo struct {
	Algorithm string `json:"algorithm"`
	Seed      int64  `json:"seed"`
}

type inputInfo struct {
	SHA256    string     `json:"sha256"`
	Rows      int        `json:"rows"`
	Unstamped int        `json:"unstamped"`
	Findings  int        `json:"findings"`
	Batches   int        `json:"batches"`
	FirstTS   *time.Time `json:"first_ts,omitempty"`
	LastTS    *time.Time `json:"last_ts,omitempty"`
}

type manifestInfo struct {
	SHA256        string                    `json:"sha256"`
	Coverage      map[string]string         `json:"coverage"`
	ActionResults map[string]int            `json:"action_results"`
	Join          responsereplay.BundleJoin `json:"join"`
}

type coverageInfo struct {
	// A stream anonymized before manifests existed carries no statement of
	// what was collected with it.
	LegacyManifestUnavailable bool `json:"legacy_manifest_unavailable"`
}

// recordedInfo counts what the recording says happened, apart from what the
// model would do.
type recordedInfo struct {
	BlockRows        int `json:"block_rows"`
	NonScanBlocks    int `json:"nonscan_blocks"`
	NonScanUnmodeled int `json:"nonscan_unmodeled"`
	OtherBlocks      int `json:"other_blocks"`
	// Paths the model leaves out. ASN-crawl subnets spend the hourly budget
	// the model gives single addresses; subnet spray and netblock subnets do
	// not, and permanent promotion keeps a block past its lease.
	ASNCrawlBlockRows         int `json:"asn_crawl_block_rows"`
	SubnetBlockRows           int `json:"subnet_block_rows"`
	NetblockRows              int `json:"netblock_rows"`
	PermblockRows             int `json:"permblock_rows"`
	DryRunRows                int `json:"dry_run_rows"`
	UnclassifiedAutoBlockRows int `json:"unclassified_auto_block_rows"`
	// Demand for those paths: Critical ASN-crawl findings and subnet spray
	// findings.
	ASNCrawlDemandRows    int `json:"asn_crawl_demand_rows"`
	SubnetSprayDemandRows int `json:"subnet_spray_demand_rows"`
}

type ratio struct {
	Numerator   int `json:"numerator"`
	Denominator int `json:"denominator"`
}

type hypotheticalInfo struct {
	ScanBlocked int `json:"scan_blocked"`
	// SourceIPReconstructed counts eligible rows whose address came from
	// reconstruction rather than the live extraction.
	SourceIPReconstructed int `json:"source_ip_reconstructed"`
	ExemptBlocked         int `json:"exempt_blocked"`
	Evicted               int `json:"evicted"`
	AgedOut               int `json:"aged_out"`
	Overflowed            int `json:"overflowed"`
	FinalPending          int `json:"final_pending"`
	// LostInQueue counts candidates the queue dropped: aged out or
	// overflowed. FinalPending is apart: censored by the recording's end.
	LostInQueue       int   `json:"lost_in_queue"`
	NewCandidates     int   `json:"new_candidates"`
	FirstQueued       int   `json:"first_queued"`
	DelayedShare      ratio `json:"delayed_share"`
	Eligible          int   `json:"eligible"`
	MissingIP         int   `json:"missing_ip"`
	ChallengeSkipped  int   `json:"challenge_skipped"`
	AlreadyBlocked    int   `json:"already_blocked"`
	InvalidPending    int   `json:"invalid_pending"`
	IneligiblePending int   `json:"ineligible_pending"`
	PendingSatisfied  int   `json:"pending_satisfied"`
	PendingHighWater  int   `json:"pending_high_water"`
	LiveHighWater     int   `json:"live_high_water"`
}

// distributionInfo: queue delay is first queueing to the eventual block;
// residence is block to eviction; hourly counts cover every elapsed hour
// from the first recorded row to the last, zero hours included.
type distributionInfo struct {
	QueueDelayNS        responsereplay.Distribution `json:"queue_delay_ns"`
	EvictionResidenceNS responsereplay.Distribution `json:"eviction_residence_ns"`
	HourlyScanBlocks    responsereplay.Distribution `json:"hourly_scan_blocks"`
	HourlyAllBlocks     responsereplay.Distribution `json:"hourly_all_blocks"`
}

const reconstructionAssumption = "reputation_source_reconstructed_from_message"

var (
	assumptions = []string{
		"demand_is_audit_dispatch_record", "empty_initial_state", "batches_inferred_from_equal_timestamps", "no_empty_scans_between_rows",
		"challenge_list_available", "engine_applies_every_block", "nonscan_blocks_applied_as_recorded_before_scan_stage",
		"random_drain_order_not_go_map_order",
	}
	gaps = []string{
		"infra_and_allowlist_protection", "verdict_callback", "subnet_spray_asn_crawl_netblock", "permanent_escalation",
		"durable_retry_and_engine_failure", "manual_unblocks", "action_outcomes_unreviewed", "source_attribution",
		"address_map_not_topology_preserving",
	}
	reportVocabulary = func() map[string]bool {
		v := map[string]bool{reconstructionAssumption: true}
		for _, s := range append(append([]string{}, assumptions...), gaps...) {
			v[s] = true
		}
		return v
	}()
)

func (r *replayRun) execute(args []string, stdout io.Writer) error {
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	policy, loc, err := resolvePolicy(o)
	if err != nil {
		return err
	}
	if err = checkOutput(&o); err != nil {
		return err
	}
	tool := r.revision()
	if !tool.clean() {
		return errRevision
	}
	rec, err := responsereplay.ReadFindings(o.findings)
	if err != nil {
		return err
	}
	for _, f := range rec.Findings {
		if _, ok := parseSeverity(f.Severity); !ok {
			return errSeverity
		}
	}
	rep := report{
		ReportVersion: 1, Model: "legacy_scan_admission", ModelVersion: 1, Source: tool,
		Order:  orderInfo{Algorithm: "sorted_keys_math_rand_shuffle", Seed: o.seed},
		Policy: policy, Assumptions: assumptions, Gaps: gaps,
		Input: inputInfo{SHA256: rec.SHA256, Rows: rec.Rows, Unstamped: rec.Unstamped, Findings: len(rec.Findings)},
	}
	if o.manifest == "" {
		rep.Coverage.LegacyManifestUnavailable = true
	} else {
		m, digest, readErr := responsereplay.ReadBundleManifest(o.manifest)
		if readErr != nil {
			return readErr
		}
		out, _ := m.FindingsOutput()
		if out.SHA256 != rec.SHA256 || out.Records != rec.Rows {
			return errManifestMismatch
		}
		rep.Manifest = &manifestInfo{SHA256: digest, Coverage: m.Coverage, ActionResults: m.ActionResults, Join: m.Join}
	}
	if err = replay(&rep, rec, policy, loc, o); err != nil {
		return err
	}
	if err = r.writeReport(o.out, rep); err != nil {
		return err
	}
	h := rep.Hypothetical
	fmt.Fprintln(stdout, "report: written")
	fmt.Fprintf(stdout, "rows: %d\n", rep.Input.Rows)
	fmt.Fprintf(stdout, "scan blocks: %d\n", h.ScanBlocked)
	fmt.Fprintf(stdout, "exempt blocks: %d\n", h.ExemptBlocked)
	fmt.Fprintf(stdout, "evictions: %d\n", h.Evicted)
	fmt.Fprintf(stdout, "delayed: %d of %d\n", h.DelayedShare.Numerator, h.DelayedShare.Denominator)
	return nil
}

func replay(rep *report, rec responsereplay.Recording, policy policyInfo, loc *time.Location, o options) error {
	classes, reconstructed := newClassifier(o)
	model, err := responsereplay.NewLegacy(responsereplay.LegacyConfig{
		MaxPerHour: policy.MaxBlocksPerHour, DenyTempLimit: policy.DenyTempIPLimit, BlockTTL: time.Duration(policy.BlockExpiryNS),
		PendingBound: policy.PendingBound, PendingMaxAge: time.Duration(policy.PendingMaxAgeNS), HourLocation: loc, Seed: o.seed,
	}, classes, responsereplay.LegacyState{})
	if err != nil {
		return err
	}
	for _, f := range rec.Findings {
		switch {
		case f.Check == "http_asn_crawl" && f.Severity == alert.Critical.String():
			rep.Recorded.ASNCrawlDemandRows++
		case f.Check == "smtp_subnet_spray" || f.Check == "mail_subnet_spray":
			rep.Recorded.SubnetSprayDemandRows++
		}
		switch _, kind := classifyObservation(f); kind {
		case observationASNCrawl:
			rep.Recorded.ASNCrawlBlockRows++
		case observationSubnet:
			rep.Recorded.SubnetBlockRows++
		case observationNetblock:
			rep.Recorded.NetblockRows++
		case observationPermblock:
			rep.Recorded.PermblockRows++
		case observationDryRun:
			rep.Recorded.DryRunRows++
		case observationUnclassified:
			rep.Recorded.UnclassifiedAutoBlockRows++
		case observationOther:
			rep.Recorded.BlockRows++
			rep.Recorded.OtherBlocks++
		case observationNonScan:
			rep.Recorded.BlockRows++
			rep.Recorded.NonScanBlocks++
		case observationNonScanUnmodeled:
			rep.Recorded.BlockRows++
			rep.Recorded.NonScanUnmodeled++
		}
	}
	batches := responsereplay.Batches(rec.Findings)
	rep.Input.Batches = len(batches)
	var delays, residences []int64
	var scanTimes, allTimes []time.Time
	h := &rep.Hypothetical
	for _, b := range batches {
		out, err := model.Step(b)
		if err != nil {
			return err
		}
		h.ScanBlocked += out.Blocked
		h.ExemptBlocked += out.ExemptBlocked
		h.Evicted += out.Evicted
		h.AgedOut += out.AgedOut
		h.Overflowed += out.Overflowed
		h.NewCandidates += out.NewCandidates
		h.FirstQueued += out.FirstQueued
		h.Eligible += out.Eligible
		h.MissingIP += out.MissingIP
		h.ChallengeSkipped += out.ChallengeSkipped
		h.AlreadyBlocked += out.AlreadyBlocked
		h.InvalidPending += out.InvalidPending
		h.IneligiblePending += out.IneligiblePending
		h.PendingSatisfied += out.PendingSatisfied
		h.PendingHighWater = max(h.PendingHighWater, out.PendingHighWater)
		h.LiveHighWater = max(h.LiveHighWater, out.LiveHighWater)
		h.FinalPending = out.Requeued
		for _, d := range out.QueueDelays {
			delays = append(delays, int64(d))
		}
		for _, d := range out.EvictionResidences {
			residences = append(residences, int64(d))
		}
		for range out.Blocked {
			scanTimes = append(scanTimes, b.At)
		}
		for range out.Blocked + out.ExemptBlocked {
			allTimes = append(allTimes, b.At)
		}
	}
	h.LostInQueue = h.AgedOut + h.Overflowed
	h.DelayedShare = ratio{Numerator: h.FirstQueued, Denominator: h.NewCandidates}
	h.SourceIPReconstructed = *reconstructed
	if o.reconstructReputation {
		rep.Assumptions = append(slices.Clone(rep.Assumptions), reconstructionAssumption)
	}
	rep.Distributions.QueueDelayNS = responsereplay.Distribute(delays)
	rep.Distributions.EvictionResidenceNS = responsereplay.Distribute(residences)
	if len(batches) > 0 {
		first, last := batches[0].At.UTC(), batches[len(batches)-1].At.UTC()
		rep.Input.FirstTS, rep.Input.LastTS = &first, &last
		rep.Distributions.HourlyScanBlocks = responsereplay.HourlyDistribution(scanTimes, first, last)
		rep.Distributions.HourlyAllBlocks = responsereplay.HourlyDistribution(allTimes, first, last)
	}
	return nil
}

// checkOutput runs before anything is read or written: the report must not
// be the recording or the manifest, by path, through a symlinked directory
// or as a hard link, and an existing report path must be a regular file.
func checkOutput(o *options) error {
	if info, err := os.Lstat(o.out); err == nil && !info.Mode().IsRegular() {
		return errUnsafeOutput
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errWrite
	}
	out, err := resolve(o.out)
	if err != nil {
		return errWrite
	}
	for _, p := range []string{o.findings, o.manifest} {
		if p == "" {
			continue
		}
		other, err := resolve(p)
		if err != nil {
			return errWrite
		}
		if out.path == other.path || (out.info != nil && other.info != nil && os.SameFile(out.info, other.info)) {
			return errOutputAlias
		}
	}
	// A report never replaces anything: a mistyped path could otherwise
	// destroy another host's recording or the salt.
	if out.info != nil {
		return errOutputExists
	}
	// Stage and publish beside the exact destination that was checked.
	o.out = out.path
	return nil
}

type resolved struct {
	path string
	info os.FileInfo
}

// Resolve links before '..', including in destinations not created yet.
// Cleaning the spelling first can hide an alias of a protected input.
func resolve(p string) (resolved, error) {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return resolved{}, errWrite
		}
		p = wd + string(filepath.Separator) + p
	}
	path := string(filepath.Separator)
	parts := strings.Split(p, string(filepath.Separator))
	links := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			path = filepath.Dir(path)
			continue
		}
		next := filepath.Join(path, part)
		info, err := os.Lstat(next)
		if errors.Is(err, os.ErrNotExist) {
			path = next
			continue
		}
		if err != nil {
			return resolved{}, errWrite
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 255 {
				return resolved{}, errWrite
			}
			target, err := os.Readlink(next)
			if err != nil {
				return resolved{}, errWrite
			}
			if filepath.IsAbs(target) {
				path = string(filepath.Separator)
			}
			parts = append(strings.Split(target, string(filepath.Separator)), parts...)
			continue
		}
		if len(parts) > 0 && !info.IsDir() {
			return resolved{}, errWrite
		}
		path = next
	}
	info, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return resolved{}, errWrite
	}
	return resolved{path, info}, nil
}

// writeReport publishes the report whole or not at all, owner-only.
func (r *replayRun) writeReport(path string, rep report) error {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return errWrite
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return errWrite
	}
	f, err := r.createTemp(dir, ".response-replay-*")
	if err != nil {
		return errWrite
	}
	_, writeErr := f.Write(append(raw, '\n'))
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		_ = os.Remove(f.Name())
		return errWrite
	}
	if err := r.rename(f.Name(), path); err != nil {
		_ = os.Remove(f.Name())
		return errWrite
	}
	return nil
}
