package main

import (
	"encoding/hex"
	"reflect"
	"runtime/debug"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// streamKind names an input or output stream. Every value is fixed here, so
// a manifest never carries a name taken from input.
type streamKind string

const (
	kindFindings      streamKind = "findings"
	kindActions       streamKind = "actions"
	kindFirewall      streamKind = "firewall_audit"
	kindLedger        streamKind = "ledger"
	kindReview        streamKind = "review"
	kindInputManifest streamKind = "input_manifest"
)

const manifestFormatVersion = 1

// runManifest is the completion marker of a published bundle: consumers
// check every output's digest against it and refuse a bundle without one.
type runManifest struct {
	FormatVersion   int               `json:"format_version"`
	Tool            toolRevision      `json:"tool"`
	SaltFingerprint string            `json:"salt_fingerprint"`
	AddressMap      string            `json:"address_map"`
	Inputs          []streamFile      `json:"inputs"`
	Outputs         []streamFile      `json:"outputs"`
	InputManifest   *inventoryDigest  `json:"input_manifest,omitempty"`
	Join            joinCounts        `json:"join"`
	DroppedFields   map[string]int    `json:"dropped_fields"`
	ActionResults   map[string]int    `json:"action_results"`
	Coverage        map[string]string `json:"coverage"`
}

// streamFile describes the exact bytes of one input or output file.
type streamFile struct {
	Kind    streamKind `json:"kind"`
	Ordinal int        `json:"ordinal"`
	SHA256  string     `json:"sha256"`
	Records int        `json:"records"`
	MinTS   *time.Time `json:"min_ts,omitempty"`
	MaxTS   *time.Time `json:"max_ts,omitempty"`
}

func (f *streamFile) observe(ts time.Time) {
	ts = ts.UTC()
	if f.MinTS == nil || ts.Before(*f.MinTS) {
		f.MinTS = &ts
	}
	if f.MaxTS == nil || ts.After(*f.MaxTS) {
		f.MaxTS = &ts
	}
}

type inventoryDigest struct {
	SHA256  string `json:"sha256"`
	Records int    `json:"records"`
}

// toolRevision identifies the build that produced a bundle.
type toolRevision struct {
	Revision      string `json:"revision"`
	Dirty         bool   `json:"dirty"`
	GoVersion     string `json:"go_version"`
	ModuleVersion string `json:"module_version"`
}

// clean reports a known commit built without local changes. A bundle from an
// unknown or modified tree cannot be reproduced, so it is not published.
func (t toolRevision) clean() bool {
	if t.Dirty || (len(t.Revision) != 40 && len(t.Revision) != 64) {
		return false
	}
	_, err := hex.DecodeString(t.Revision)
	return err == nil
}

// readBuildRevision reads the VCS stamp go build embeds. A build without the
// stamp, or without the modified flag, counts as unknown.
func readBuildRevision() toolRevision {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return toolRevision{Dirty: true}
	}
	t := toolRevision{GoVersion: info.GoVersion, ModuleVersion: info.Main.Version, Dirty: true}
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

// inputManifest is the collector's inventory: which streams exist on the
// host and the exact files taken from it. It holds no paths or names.
type inputManifest struct {
	V       int                  `json:"v"`
	Streams []inputManifestEntry `json:"streams"`
}

type inputManifestEntry struct {
	Kind         string `json:"kind"`
	Availability string `json:"availability"`
	SHA256       string `json:"sha256,omitempty"`
	Records      int    `json:"records,omitempty"`
}

var inventoryKinds = map[string]bool{
	string(kindFindings): true, string(kindActions): true, string(kindFirewall): true,
	string(kindLedger): true, string(kindReview): true,
}

// absent: the collector looked and found none. not_recorded: the host does
// not keep that stream at all.
var inventoryAvailability = map[string]bool{"present": true, "absent": true, "not_recorded": true}

// coverage says, for every stream kind, whether it was supplied, stated
// unavailable by the inventory or simply not supplied. Ledger and review
// streams have no schema yet, so they are never accepted as payloads.
func coverage(files []streamFile, supplied map[streamKind]bool, inv *inputManifest) (map[string]string, error) {
	cov := map[string]string{
		string(kindFindings): "present", string(kindActions): "not_supplied", string(kindFirewall): "not_supplied",
		string(kindLedger): "unavailable", string(kindReview): "unavailable", "firewall_id_join": "not_applicable",
	}
	for _, kind := range []streamKind{kindActions, kindFirewall} {
		if supplied[kind] {
			cov[string(kind)] = "present"
		}
	}
	if supplied[kindFirewall] {
		// Legacy firewall entries carry no ids, so nothing joins them to an
		// action or a finding.
		cov["firewall_id_join"] = "unavailable"
	}
	if inv == nil {
		return cov, nil
	}
	if inv.V != 1 {
		return nil, errInputManifest
	}
	type fileKey struct {
		kind    string
		sha256  string
		records int
	}
	present := map[fileKey]int{}
	presentKinds := map[string]bool{}
	stated := map[string]string{}
	for _, e := range inv.Streams {
		if !inventoryKinds[e.Kind] || !inventoryAvailability[e.Availability] {
			return nil, errInputManifest
		}
		if e.Availability == "present" {
			digest, err := hex.DecodeString(e.SHA256)
			if e.Kind == string(kindLedger) || e.Kind == string(kindReview) || err != nil || len(digest) != 32 ||
				hex.EncodeToString(digest) != e.SHA256 || e.Records < 0 {
				return nil, errInputManifest
			}
			present[fileKey{e.Kind, e.SHA256, e.Records}]++
			presentKinds[e.Kind] = true
			continue
		}
		if _, repeated := stated[e.Kind]; repeated || e.SHA256 != "" || e.Records != 0 {
			return nil, errInputManifest
		}
		stated[e.Kind] = e.Availability
	}
	for _, f := range files {
		k := fileKey{string(f.Kind), f.SHA256, f.Records}
		if present[k] == 0 {
			return nil, errInputManifest
		}
		present[k]--
	}
	for _, n := range present {
		if n != 0 {
			return nil, errInputManifest
		}
	}
	for kind, availability := range stated {
		if presentKinds[kind] {
			return nil, errInputManifest
		}
		cov[kind] = availability
	}
	return cov, nil
}

// joinCounts is what the streams say about each other. Matched means only
// that an action names a finding id present in the finding stream.
type joinCounts struct {
	FindingRows                int `json:"finding_rows"`
	UniqueFindingIDs           int `json:"unique_finding_ids"`
	DuplicateFindingRows       int `json:"duplicate_finding_rows"`
	FindingRowsWithoutID       int `json:"finding_rows_without_id"`
	ActionRows                 int `json:"action_rows"`
	ActionRowsWithFindingID    int `json:"action_rows_with_finding_id"`
	ActionRowsMatched          int `json:"action_rows_matched"`
	ActionRowsMissingFinding   int `json:"action_rows_missing_finding"`
	ActionRowsWithoutFindingID int `json:"action_rows_without_finding_id"`
	DurableRows                int `json:"durable_rows"`
	DurableKeys                int `json:"durable_keys"`
	DurableIdenticalDuplicates int `json:"durable_identical_duplicates"`
	DurableConflictingKeys     int `json:"durable_conflicting_keys"`
	FirewallRows               int `json:"firewall_rows"`
}

// joinRecords counts join coverage and action outcomes on the raw records.
// A durable row repeated byte for byte is a retransmission and does not count
// as another outcome; a key with differing rows is ambiguous evidence and is
// reported, never resolved by taking the latest.
func joinRecords(findings []alert.AuditEvent, actions []actionlog.Record, audits []firewall.AuditEntry) (joinCounts, map[string]int) {
	var c joinCounts
	ids := map[string]bool{}
	for _, e := range findings {
		c.FindingRows++
		switch {
		case e.FindingID == "":
			c.FindingRowsWithoutID++
		case ids[e.FindingID]:
			c.DuplicateFindingRows++
		default:
			ids[e.FindingID] = true
		}
	}
	c.UniqueFindingIDs = len(ids)

	results := map[string]int{}
	for r := range actionResults {
		results[r] = 0
	}
	type durableKey struct {
		id      string
		version uint64
	}
	variants := map[durableKey][]actionlog.Record{}
	conflicting := map[durableKey]bool{}
	for _, r := range actions {
		c.ActionRows++
		switch {
		case r.FindingID == "":
			c.ActionRowsWithoutFindingID++
		case ids[r.FindingID]:
			c.ActionRowsWithFindingID++
			c.ActionRowsMatched++
		default:
			c.ActionRowsWithFindingID++
			c.ActionRowsMissingFinding++
		}
		if r.ActionID != "" {
			c.DurableRows++
			key := durableKey{r.ActionID, r.ActionVersion}
			if slices.ContainsFunc(variants[key], func(v actionlog.Record) bool { return sameRecord(v, r) }) {
				c.DurableIdenticalDuplicates++
				continue
			}
			if len(variants[key]) > 0 {
				conflicting[key] = true
			}
			variants[key] = append(variants[key], r)
		}
		results[string(r.Result)]++
	}
	c.DurableKeys = len(variants)
	c.DurableConflictingKeys = len(conflicting)
	c.FirewallRows = len(audits)
	return c, results
}

// sameRecord compares every field, the instant by value: two decodings of
// one timestamp need not share a location pointer.
func sameRecord(a, b actionlog.Record) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return false
	}
	a.Timestamp, b.Timestamp = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}
