package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
)

// Freeze the existing preview wording independently of the mode-aware renderer.
// Held execution warns while admission previews or forecasts (ruling C2).
func baselineOwnerDoctorChecks(a *health.AdmissionStatus) []DoctorCheck {
	o := a.Owner
	if o == nil {
		return nil
	}
	owner := DoctorCheck{Name: "admission owner", Status: "ok", Message: admission.PreviewUnaffected}
	if o.Error != "" {
		owner = DoctorCheck{
			Name: "admission owner", Status: "warn", Message: "the admission ledger is not running: " + o.Error + "; " + admission.PreviewUnaffected,
			Fix: "the daemon retries at every tick; keep the state database, which existing blocking still uses, and report the error",
		}
	}
	clock := DoctorCheck{Name: "admission clock", Status: "ok", Message: admission.PreviewUnaffected}
	switch {
	case o.TickError != "":
		clock = DoctorCheck{
			Name: "admission clock", Status: "warn", Message: "the last clock reading was refused: " + o.TickError + "; " + admission.PreviewUnaffected,
			Fix: "nothing is admitted until a reading succeeds; check the system clock and /proc/sys/kernel/random/boot_id",
		}
	case o.ClockDegraded:
		clock = DoctorCheck{
			Name: "admission clock", Status: "warn",
			Message: "the wall clock is behind the ledger's time or disagrees with the time since boot; wall time alone proves nothing new until they agree; " + admission.PreviewUnaffected,
			Fix:     "check time synchronisation",
		}
	}
	rows := []DoctorCheck{owner, clock}
	if o.TurnError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission turns", Status: "warn", Message: "the last admission turn failed: " + o.TurnError + "; " + admission.PreviewUnaffected,
			Fix: "the owner retries from one second, backing off to once a minute; keep the state database, which existing blocking still uses, and report the error",
		})
	}
	if o.RetirementError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission retirement", Status: "warn", Message: "retiring uncertain blocks failed: " + o.RetirementError + "; " + admission.PreviewUnaffected,
			Fix: "each uncertain block stays held and is retried, backing off to once a minute; keep the state database, which existing blocking still uses, and report the error",
		})
	}
	if a.Ledger != nil && a.Ledger.Ceiling.Error == "" && a.Ledger.Ceiling.Limit > 0 {
		limit := a.Ledger.Ceiling.Limit
		c := DoctorCheck{Name: "admission ceiling", Status: "ok", Message: fmt.Sprintf("%d automatic responses per hour (%s)", limit, o.CeilingSource) + "; " + admission.PreviewUnaffected}
		switch {
		case o.CeilingSource == config.CeilingClamped:
			c.Status = "warn"
			c.Message = fmt.Sprintf("auto_response.max_blocks_per_hour exceeds the largest ceiling the ledger accepts; it uses %d", limit) + "; " + admission.PreviewUnaffected
			c.Fix = fmt.Sprintf("set auto_response.max_blocks_per_hour to at most %d", admission.MaxCeiling)
		case limit == 1:
			c.Status = "warn"
			c.Message = "a ceiling of 1 runs only the reserved lane: only direct compromise and corroborated responses can be served; " + admission.PreviewUnaffected
			c.Fix = "raise auto_response.max_blocks_per_hour, or remove it to use the default"
		}
		rows = append(rows, c)
	}
	if imp := o.Import; imp != nil {
		c := DoctorCheck{Name: "admission legacy import", Status: "ok", Message: "the legacy hourly count held no blocks of the last hour; " + admission.PreviewUnaffected}
		switch {
		case imp.Error != "":
			c.Status = "warn"
			c.Message = "the legacy hourly count could not be read (" + imp.Error + "); the ledger started without saved credit; " + admission.PreviewUnaffected
			c.Fix = "none needed: credit refills at the ceiling's rate"
		case imp.Units > 0:
			c.Message = fmt.Sprintf("%d blocks imported from the legacy hourly count; they count at least until %s", imp.Units, imp.At.Add(admission.CeilingWindow).UTC().Format(time.RFC3339)) + "; " + admission.PreviewUnaffected
		}
		rows = append(rows, c)
	}
	if o.InventoryError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission inventory", Status: "warn", Message: "the last hosting inventory read failed: " + o.InventoryError + "; " + admission.PreviewUnaffected,
			Fix: "admission keeps the previous accounts; check the account registry and home directories",
		})
	}
	if o.ExecutionHeld != "" {
		fix := "admission probes the firewall from one second, backing off to once a minute, and keeps uncertain actions held; an apply fault clears when the next batch applies; check the firewall rows and the storage under the state directory"
		if o.ExecutionHeldBy == "policy" {
			fix = "correct the setting the message names; held block work waits until the daemon installs a valid policy"
		}
		rows = append(rows, DoctorCheck{
			Name: "admission execution", Status: "warn", Message: "automatic blocks are held: " + o.ExecutionHeld + "; " + admission.PreviewUnaffected,
			Fix: fix,
		})
	}
	if o.DamageError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission ledger damage", Status: "warn", Message: "responses naming a damaged ledger record are discarded: " + o.DamageError + "; " + admission.PreviewUnaffected,
			Fix: "restart csm.service so opening the ledger proves every record; keep the state database, which existing blocking still uses, and report the damage",
		})
	}
	return rows
}

func TestDoctorOwnerModeMatrix(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for _, change := range []func(*health.AdmissionStatus){
		func(a *health.AdmissionStatus) {},
		func(a *health.AdmissionStatus) { a.Owner.Error = "fixture stop" },
		func(a *health.AdmissionStatus) { a.Owner.TickError = "fixture clock" },
		func(a *health.AdmissionStatus) { a.Owner.ClockDegraded = true },
		func(a *health.AdmissionStatus) { a.Owner.TurnError = "fixture turn" },
		func(a *health.AdmissionStatus) { a.Owner.RetirementError = "fixture retirement" },
		func(a *health.AdmissionStatus) { a.Owner.CeilingSource = config.CeilingClamped },
		func(a *health.AdmissionStatus) { a.Ledger.Ceiling.Limit = 1 },
		func(a *health.AdmissionStatus) { a.Owner.Import.Error = "fixture import" },
		func(a *health.AdmissionStatus) { a.Owner.Import.Units = 2 },
		func(a *health.AdmissionStatus) { a.Owner.InventoryError = "fixture inventory" },
		func(a *health.AdmissionStatus) { a.Owner.ExecutionHeld = "fixture hold" },
		func(a *health.AdmissionStatus) {
			a.Owner.ExecutionHeld, a.Owner.ExecutionHeldBy = "fixture policy", "policy"
		},
		func(a *health.AdmissionStatus) { a.Owner.DamageError = "fixture damage" },
	} {
		a := &health.AdmissionStatus{CheckedAt: at,
			Ledger: &admission.LedgerStatus{Ceiling: admission.CeilingStatus{Limit: 2000}},
			Owner:  &health.AdmissionOwner{CeilingSource: "default", Import: &health.AdmissionImport{At: at}},
		}
		change(a)
		want := baselineOwnerDoctorChecks(a)
		if got := ownerDoctorChecks(a); !reflect.DeepEqual(got, want) {
			t.Fatalf("preview bytes changed: got %+v, want %+v", got, want)
		}
		a.Owner.Executing = true
		for i := range want {
			r := &want[i]
			r.Message = strings.ReplaceAll(r.Message, admission.PreviewUnaffected, admission.ExecutionAffected)
			r.Fix = strings.ReplaceAll(r.Fix, ", which existing blocking still uses", "")
			if r.Status == "warn" && (r.Name == "admission owner" || r.Name == "admission turns" || r.Name == "admission execution" || r.Name == "admission ledger damage" || (r.Name == "admission clock" && a.Owner.TickError != "")) {
				r.Status = "fail"
			}
		}
		if got := ownerDoctorChecks(a); !reflect.DeepEqual(got, want) {
			t.Fatalf("executing rows = %+v, want %+v", got, want)
		}
	}
}
