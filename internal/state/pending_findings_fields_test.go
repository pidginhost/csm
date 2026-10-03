package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
)

// The public Finding JSON leaves out the subnets and spray targets, but the
// automatic response reads them: a crawl finding parked at shutdown must still
// carry its subnets when it replays, or its subnet block never happens.
func TestPendingFindingsKeepResponseFields(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	parked := []alert.Finding{
		{Severity: alert.Critical, Check: "http_asn_crawl", Message: "crawl", CIDRs: []string{"198.51.100.0/24", "203.0.113.0/25"}, Timestamp: now},
		{Severity: alert.High, Check: "credential_stuffing", Message: "spray", SourceIP: "192.0.2.7", SprayTargets: []string{"alice", "bob"}, Timestamp: now},
	}
	if appendErr := st.AppendPendingFindings(parked); appendErr != nil {
		t.Fatal(appendErr)
	}

	var replayed []alert.Finding
	if replayErr := st.ReplayPendingFindings(func(got []alert.Finding) { replayed = got }); replayErr != nil {
		t.Fatal(replayErr)
	}
	if len(replayed) != 2 {
		t.Fatalf("replayed %d findings, want 2", len(replayed))
	}
	if !reflect.DeepEqual(replayed[0].CIDRs, parked[0].CIDRs) {
		t.Errorf("CIDRs = %v, want %v", replayed[0].CIDRs, parked[0].CIDRs)
	}
	if !reflect.DeepEqual(replayed[1].SprayTargets, parked[1].SprayTargets) {
		t.Errorf("SprayTargets = %v, want %v", replayed[1].SprayTargets, parked[1].SprayTargets)
	}
}

// Delivery provenance is process-local on purpose: a finding read back from
// storage gets a fresh evaluation.
func TestPendingFindingsDropProcessLocalProvenance(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parked := []alert.Finding{{Check: "webshell_realtime", Message: "x", AutoFileResponseEvaluated: true, ScanCarryForward: true, Timestamp: time.Now()}}
	if appendErr := st.AppendPendingFindings(parked); appendErr != nil {
		t.Fatal(appendErr)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AutoFileResponseEvaluated || got[0].ScanCarryForward {
		t.Fatalf("replayed %+v, want one finding with process-local provenance cleared", got)
	}
}

// A file parked by an older daemon holds plain Finding objects and must still
// replay.
func TestPendingFindingsReadOlderFile(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	older, err := json.Marshal([]alert.Finding{{Severity: alert.Critical, Check: "auto_block", Message: "older", SourceIP: "203.0.113.9", Timestamp: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(filepath.Join(dir, pendingFindingsFile), older, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Message != "older" || got[0].SourceIP != "203.0.113.9" {
		t.Fatalf("replayed %+v, want the older finding", got)
	}
}

// The queue identity decides whether a failed write landed; two batches that
// differ only in a response field are different batches.
func TestPendingIdentityCoversResponseFields(t *testing.T) {
	base := alert.Finding{Check: "http_asn_crawl", Message: "crawl"}
	withCIDR, otherCIDR := base, base
	withCIDR.CIDRs = []string{"198.51.100.0/24"}
	otherCIDR.CIDRs = []string{"203.0.113.0/24"}
	if pendingIdentity([]alert.Finding{withCIDR}) == pendingIdentity([]alert.Finding{otherCIDR}) {
		t.Fatal("identity ignores CIDRs")
	}
	withTargets, otherTargets := base, base
	withTargets.SprayTargets = []string{"alice"}
	otherTargets.SprayTargets = []string{"bob"}
	if pendingIdentity([]alert.Finding{withTargets}) == pendingIdentity([]alert.Finding{otherTargets}) {
		t.Fatal("identity ignores SprayTargets")
	}
}

func TestPendingFindingsNullRemainsNil(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(filepath.Join(st.path, pendingFindingsFile), []byte("null"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("null file returned %#v, want nil", got)
	}
}

func TestPendingFindingsDowngradeKeepsPublicPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := alert.Finding{
		Severity: alert.Critical, Check: "http_asn_crawl", Message: "crawl", Details: "fixture",
		SourceIP: "192.0.2.7", CIDRs: []string{"198.51.100.0/24"}, SprayTargets: []string{"alice", "bob"},
		Timestamp:                 time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		AutoFileResponseEvaluated: true, ScanCarryForward: true,
	}
	if appendErr := st.AppendPendingFindings([]alert.Finding{f}); appendErr != nil {
		t.Fatal(appendErr)
	}
	data, err := os.ReadFile(filepath.Join(st.path, pendingFindingsFile))
	if err != nil {
		t.Fatal(err)
	}
	// Older daemons decode plain Finding objects and ignore storage-only keys.
	var older []alert.Finding
	if decodeErr := json.Unmarshal(data, &older); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	// The subnets are public now; the spray targets stay storage-only.
	f.SprayTargets = nil
	f.AutoFileResponseEvaluated, f.ScanCarryForward = false, false
	if !reflect.DeepEqual(older, []alert.Finding{f}) {
		t.Fatalf("downgrade payload = %+v, want %+v", older, f)
	}
}

func TestPendingQueueResponseFieldWriteReadback(t *testing.T) {
	for _, field := range []string{"cidrs", "spray_targets"} {
		t.Run(field, func(t *testing.T) {
			for _, outcome := range []string{"retained", "committed", "different_response"} {
				t.Run(outcome, func(t *testing.T) {
					st, err := Open(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					old := alert.Finding{Check: "fixture", Message: "same"}
					if appendErr := st.AppendPendingFindings([]alert.Finding{old}); appendErr != nil {
						t.Fatal(appendErr)
					}
					incoming, different := old, old
					if field == "cidrs" {
						incoming.CIDRs = []string{"198.51.100.0/24"}
						different.CIDRs = []string{"203.0.113.0/24"}
					} else {
						incoming.SprayTargets = []string{"alice" + string([]byte{0xff})}
						different.SprayTargets = []string{"bob"}
					}
					// Log text can also be cut in the middle of a UTF-8 character.
					incoming.Details = "fixture " + string([]byte{0xff})
					different.Details = incoming.Details
					writeErr := errors.New("fixture write error")
					st.writePendingFile = func(path string, mode os.FileMode, value any) error {
						if outcome == "different_response" {
							value = toPendingRecords([]alert.Finding{old, different})
						}
						if outcome != "retained" {
							if atomicErr := atomicio.AtomicWriteJSON(path, mode, value); atomicErr != nil {
								return atomicErr
							}
						}
						return writeErr
					}
					if appendErr := st.AppendPendingFindings([]alert.Finding{incoming}); appendErr != writeErr {
						t.Fatalf("append error = %v, want %v", appendErr, writeErr)
					}
					row := st.QueueStatuses(time.Now())["pending"]
					wantDepth, wantLoss := 2, uint64(0)
					if outcome == "retained" {
						wantDepth, wantLoss = 1, 1
					}
					if row.Depth != wantDepth || row.DroppedTotal != wantLoss || row.DroppedLowerBound != (outcome == "different_response") || row.DepthUnavailable || row.InFlight != 0 || row.Reason != "state_io" {
						t.Fatalf("write readback accounting = %+v", row)
					}
					got, err := st.TakePendingFindings()
					if err != nil {
						t.Fatal(err)
					}
					if len(got) != wantDepth {
						t.Fatalf("replayed %d findings, want %d", len(got), wantDepth)
					}
					if outcome == "committed" {
						last := got[1]
						if last.Details != "fixture \ufffd" {
							t.Fatalf("repaired details = %q", last.Details)
						}
						if field == "cidrs" && !reflect.DeepEqual(last.CIDRs, []string{"198.51.100.0/24"}) {
							t.Fatalf("replayed CIDRs = %v", last.CIDRs)
						}
						if field == "spray_targets" && !reflect.DeepEqual(last.SprayTargets, []string{"alice\ufffd"}) {
							t.Fatalf("repaired targets = %q", last.SprayTargets)
						}
					}
				})
			}
		})
	}
}
