package responsereplay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var bundleFixture = `{
  "format_version": 1,
  "tool": {"revision": "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "dirty": false, "go_version": "go1.27.1", "module_version": "(devel)"},
  "salt_fingerprint": "0123456789ab",
  "address_map": "salted_not_topology_preserving",
  "inputs": [{"kind": "findings", "ordinal": 1, "sha256": "` + zeros64 + `", "records": 2, "min_ts": "2026-09-08T10:00:00Z", "max_ts": "2026-09-08T10:01:00Z"}],
  "outputs": [{"kind": "findings", "ordinal": 1, "sha256": "` + ones64 + `", "records": 2, "min_ts": "2026-09-08T10:00:00Z", "max_ts": "2026-09-08T10:01:00Z"}],
  "join": {"finding_rows": 2, "unique_finding_ids": 2, "duplicate_finding_rows": 0, "finding_rows_without_id": 0, "action_rows": 0, "action_rows_with_finding_id": 0, "action_rows_matched": 0, "action_rows_missing_finding": 0, "action_rows_without_finding_id": 0, "durable_rows": 0, "durable_keys": 0, "durable_identical_duplicates": 0, "durable_conflicting_keys": 0, "firewall_rows": 0},
  "dropped_fields": {"action.reason": 0},
  "action_results": {"applied": 0, "verified": 0},
  "coverage": {"findings": "present", "actions": "not_supplied", "firewall_audit": "not_supplied", "ledger": "unavailable", "review": "unavailable", "firewall_id_join": "not_applicable"}
}
`

var (
	zeros64 = strings.Repeat("0", 64)
	ones64  = strings.Repeat("1", 64)
)

func writeBundle(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alice-manifest.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadBundleManifest(t *testing.T) {
	path := writeBundle(t, bundleFixture)
	m, digest, err := ReadBundleManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(bundleFixture))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", digest)
	}
	out, ok := m.FindingsOutput()
	if !ok || out.SHA256 != ones64 || out.Records != 2 || m.Join.FindingRows != 2 || m.Coverage["actions"] != "not_supplied" {
		t.Fatalf("manifest: %+v", m)
	}
	for name, body := range map[string]string{
		"unknown key":          strings.Replace(bundleFixture, `"format_version": 1,`, `"format_version": 1, "note": "alice",`, 1),
		"duplicate map key":    strings.Replace(bundleFixture, `"applied": 0,`, `"applied": 0, "applied": 1,`, 1),
		"unknown join field":   strings.Replace(bundleFixture, `"firewall_rows": 0}`, `"firewall_rows": 0, "alice": 1}`, 1),
		"format":               strings.Replace(bundleFixture, `"format_version": 1,`, `"format_version": 2,`, 1),
		"coverage value":       strings.Replace(bundleFixture, `"actions": "not_supplied"`, `"actions": "alice"`, 1),
		"coverage key":         strings.Replace(bundleFixture, `"review": "unavailable"`, `"alice": "unavailable"`, 1),
		"result key":           strings.Replace(bundleFixture, `"verified": 0`, `"alice": 0`, 1),
		"no findings output":   strings.Replace(bundleFixture, `"outputs": [{"kind": "findings"`, `"outputs": [{"kind": "actions"`, 1),
		"two findings outputs": strings.Replace(bundleFixture, `"outputs": [`, `"outputs": [{"kind": "findings", "ordinal": 2, "sha256": "`+ones64+`", "records": 1}, `, 1),
		"bad digest":           strings.Replace(bundleFixture, `"sha256": "`+ones64+`"`, `"sha256": "alice"`, 1),
		"trailing data":        bundleFixture + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ReadBundleManifest(writeBundle(t, body))
			if !errors.Is(err, errBundle) && !errors.Is(err, errUnknownField) && !errors.Is(err, errDuplicateKey) && !errors.Is(err, errTrailing) {
				t.Fatalf("accepted or wrong refusal: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "alice") {
				t.Fatalf("error carries input: %v", err)
			}
		})
	}
}

func TestNonScanReasonPrefixesAreTheApplyBlockReasons(t *testing.T) {
	want := []string{"challenge timeout: ", "central-intel (locally corroborated)", "CSM credential_spray: ", "CSM incident: "}
	if strings.Join(NonScanReasonPrefixes, "|") != strings.Join(want, "|") {
		t.Fatalf("prefixes = %q", NonScanReasonPrefixes)
	}
}

func TestBundleRejectsNegativeCounters(t *testing.T) {
	for _, field := range []string{"applied", "action.reason", "finding_rows", "unique_finding_ids", "duplicate_finding_rows", "finding_rows_without_id",
		"action_rows", "action_rows_with_finding_id", "action_rows_matched", "action_rows_missing_finding", "action_rows_without_finding_id",
		"durable_rows", "durable_keys", "durable_identical_duplicates", "durable_conflicting_keys", "firewall_rows"} {
		t.Run(field, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(bundleFixture), &m); err != nil {
				t.Fatal(err)
			}
			section := "join"
			switch field {
			case "applied":
				section = "action_results"
			case "action.reason":
				section = "dropped_fields"
			}
			m[section].(map[string]any)[field] = -1
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadBundleManifest(writeBundle(t, string(body))); !errors.Is(err, errBundle) {
				t.Fatalf("negative %s accepted: %v", field, err)
			}
		})
	}
}
