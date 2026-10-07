package main

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
)

// admissionDoctorChecks renders the admission rules for a snapshot whose
// daemon owns a ledger, judged at the time the daemon read it.
func admissionDoctorChecks(a *health.AdmissionStatus) []DoctorCheck {
	if a == nil {
		return nil
	}
	rows := admission.DoctorChecks(a.Ledger, a.Ingress, a.CheckedAt)
	checks := make([]DoctorCheck, 0, len(rows))
	for _, r := range rows {
		checks = append(checks, DoctorCheck{Name: r.Name, Status: r.Status, Message: r.Message, Fix: r.Fix})
	}
	return append(checks, ownerDoctorChecks(a)...)
}

// ownerDoctorChecks renders what only the ledger's owner knows: whether it
// runs, its clock, the ceiling's source, the legacy import and the
// inventory reads.
func ownerDoctorChecks(a *health.AdmissionStatus) []DoctorCheck {
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
	if o.DamageError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission ledger damage", Status: "warn", Message: "responses naming a damaged ledger record are discarded: " + o.DamageError + "; " + admission.PreviewUnaffected,
			Fix: "restart csm.service so opening the ledger proves every record; keep the state database, which existing blocking still uses, and report the damage",
		})
	}
	return rows
}
