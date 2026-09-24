package responsereplay

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"
)

// BundleManifest is the manifest the recording tool writes last, as the
// completion marker of an anonymized bundle. The recording tool's tests read
// what it writes back through ReadBundleManifest, so the two cannot drift.
type BundleManifest struct {
	FormatVersion   int               `json:"format_version"`
	Tool            BundleTool        `json:"tool"`
	SaltFingerprint string            `json:"salt_fingerprint"`
	AddressMap      string            `json:"address_map"`
	Addresses       BundleAddresses   `json:"addresses"`
	Inputs          []BundleFile      `json:"inputs"`
	Outputs         []BundleFile      `json:"outputs"`
	InputManifest   *BundleInventory  `json:"input_manifest,omitempty"`
	Join            BundleJoin        `json:"join"`
	DroppedFields   map[string]int    `json:"dropped_fields"`
	ActionResults   map[string]int    `json:"action_results"`
	Coverage        map[string]string `json:"coverage"`
}

type BundleTool struct {
	Revision      string `json:"revision"`
	Dirty         bool   `json:"dirty"`
	GoVersion     string `json:"go_version"`
	ModuleVersion string `json:"module_version"`
}

type BundleFile struct {
	Kind    string     `json:"kind"`
	Ordinal int        `json:"ordinal"`
	SHA256  string     `json:"sha256"`
	Records int        `json:"records"`
	MinTS   *time.Time `json:"min_ts,omitempty"`
	MaxTS   *time.Time `json:"max_ts,omitempty"`
}

// BundleAddresses counts distinct addresses and the distinct pseudonyms
// they became, per family. Fewer pseudonyms than addresses means distinct
// addresses were merged, which replay cannot undo.
type BundleAddresses struct {
	IPv4Addresses  int `json:"ipv4_addresses"`
	IPv4Pseudonyms int `json:"ipv4_pseudonyms"`
	IPv6Addresses  int `json:"ipv6_addresses"`
	IPv6Pseudonyms int `json:"ipv6_pseudonyms"`
}

type BundleInventory struct {
	SHA256  string `json:"sha256"`
	Records int    `json:"records"`
}

// BundleJoin is the recording tool's join counts. Matched means only that an
// action named a finding id present in the recording.
type BundleJoin struct {
	FindingRows                int `json:"finding_rows"`
	UniqueFindingIDs           int `json:"unique_finding_ids"`
	DuplicateFindingRows       int `json:"duplicate_finding_rows"`
	FindingRowsWithoutID       int `json:"finding_rows_without_id"`
	FindingRowsUnstamped       int `json:"finding_rows_unstamped"`
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

var errBundle = errors.New("replay: manifest is not a valid recording bundle manifest")

// The closed vocabularies a manifest may carry. A report copies coverage and
// results, so nothing outside these reaches it.
var (
	bundleCoverageKinds  = map[string]bool{"findings": true, "actions": true, "firewall_audit": true, "ledger": true, "review": true, "firewall_id_join": true}
	bundleCoverageValues = map[string]bool{"present": true, "absent": true, "not_recorded": true, "not_supplied": true, "unavailable": true, "not_applicable": true}
	bundleResults        = map[string]bool{"applied": true, "dry_run": true, "failed": true, "refused": true, "verified": true, "unknown": true}
	bundleKinds          = map[string]bool{"findings": true, "actions": true, "firewall_audit": true}
)

// NonScanReasonPrefixes are the reasons automatic blocks from outside the
// scan budget record in their finding details: challenge timeout, central
// intel, credential spray and incident blocks.
var NonScanReasonPrefixes = []string{"challenge timeout: ", "central-intel (locally corroborated)", "CSM credential_spray: ", "CSM incident: "}

// ReadBundleManifest reads a recording manifest strictly and returns it with
// the SHA-256 of its exact bytes.
func ReadBundleManifest(path string) (BundleManifest, string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-chosen manifest
	if err != nil {
		return BundleManifest{}, "", readError{0, errOpen}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxLineBytes+1))
	if err != nil {
		return BundleManifest{}, "", readError{0, errRead}
	}
	var m BundleManifest
	if err := decodeStrict(data, &m); err != nil {
		return BundleManifest{}, "", err
	}
	if !validBundle(m) {
		return BundleManifest{}, "", errBundle
	}
	sum := sha256.Sum256(data)
	return m, hex.EncodeToString(sum[:]), nil
}

func validBundle(m BundleManifest) bool {
	if m.FormatVersion != 1 {
		return false
	}
	for _, files := range [][]BundleFile{m.Inputs, m.Outputs} {
		for _, f := range files {
			if !bundleKinds[f.Kind] || !sha256Hex(f.SHA256) || f.Records < 0 || f.Ordinal < 1 {
				return false
			}
		}
	}
	if _, ok := m.FindingsOutput(); !ok {
		return false
	}
	for k, v := range m.Coverage {
		if !bundleCoverageKinds[k] || !bundleCoverageValues[v] {
			return false
		}
	}
	for k, count := range m.ActionResults {
		if !bundleResults[k] || count < 0 {
			return false
		}
	}
	for _, count := range m.DroppedFields {
		if count < 0 {
			return false
		}
	}
	ad := m.Addresses
	if ad.IPv4Addresses < 0 || ad.IPv4Pseudonyms < 0 || ad.IPv6Addresses < 0 || ad.IPv6Pseudonyms < 0 ||
		ad.IPv4Pseudonyms > ad.IPv4Addresses || ad.IPv6Pseudonyms > ad.IPv6Addresses {
		return false
	}
	j := m.Join
	for _, count := range []int{j.FindingRows, j.UniqueFindingIDs, j.DuplicateFindingRows, j.FindingRowsWithoutID, j.FindingRowsUnstamped,
		j.ActionRows, j.ActionRowsWithFindingID, j.ActionRowsMatched, j.ActionRowsMissingFinding, j.ActionRowsWithoutFindingID,
		j.DurableRows, j.DurableKeys, j.DurableIdenticalDuplicates, j.DurableConflictingKeys, j.FirewallRows} {
		if count < 0 {
			return false
		}
	}
	return true
}

// FindingsOutput returns the bundle's single finding stream.
func (m BundleManifest) FindingsOutput() (BundleFile, bool) {
	var found BundleFile
	n := 0
	for _, f := range m.Outputs {
		if f.Kind == "findings" {
			found = f
			n++
		}
	}
	return found, n == 1
}

func sha256Hex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}
