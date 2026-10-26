package admissionowner

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
)

// The status wire contract preserves the unknown sentinel, including zero.
func TestShadowDrainWireContract(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 5400} {
		s := testShadow(t, freshCeiling(t, 2000), nil)
		s.adm = &firewall.BlockAdmission{Unclaimed: 1, Drain: time.Duration(seconds) * time.Second}
		view := &health.AdmissionStatus{Owner: &health.AdmissionOwner{DryRun: &health.AdmissionDryRun{Occupancy: s.occupancyStatus()}}}
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		for _, key := range []string{"owner", "dry_run", "occupancy"} {
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			raw = wire[key]
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		if string(wire["drain_seconds"]) != strconv.FormatInt(seconds, 10) {
			t.Fatalf("drain wire = %s, want %d", wire["drain_seconds"], seconds)
		}
		var decoded health.AdmissionDryRunOccupancy
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded.DrainSeconds != seconds {
			t.Fatalf("decoded: %+v %v", decoded, err)
		}
	}
}

func TestShadowOverfullImportsWait(t *testing.T) {
	for _, count := range []int{10, 12} {
		s := testShadow(t, freshCeiling(t, 2000), nil)
		adm := firewall.BlockAdmission{Limit: 10, Imported: count}
		before := s.ceiling
		pred, change, err := s.admit("203.0.113.90", admission.KindBlockIP, shadowExpiry, directGen, shadowT0, adm)
		if err != nil || pred != admission.PredictSetFull || change != nil || s.ceiling != before {
			t.Fatalf("overfull imports: %s %+v %v", pred, change, err)
		}
	}
}
