package main

import (
	"fmt"
	"strings"
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
	if o.ExecutionHeld != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission execution", Status: "fail", Message: "automatic blocks are held: " + o.ExecutionHeld,
			Fix: "admission probes the firewall from one second, backing off to once a minute and keeps uncertain actions held; check the firewall rows and the storage under the state directory",
		})
	}
	if o.DamageError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission ledger damage", Status: "warn", Message: "responses naming a damaged ledger record are discarded: " + o.DamageError + "; " + admission.PreviewUnaffected,
			Fix: "restart csm.service so opening the ledger proves every record; keep the state database, which existing blocking still uses, and report the damage",
		})
	}
	return append(rows, dryRunDoctorChecks(o.DryRun)...)
}

// dryRunDoctorChecks renders the dry-run forecast of an owner that runs
// blocks (spec 3.8). A dry run alone is not a failure, and a prediction is
// never a block: a held forecast, model limits, modelled waits and lost or
// stale examples warn. Real safety state keeps its own rows.
func dryRunDoctorChecks(d *health.AdmissionDryRun) []DoctorCheck {
	if d == nil {
		return nil
	}
	session := "no forecast session has started"
	if d.SessionID != nil && d.Since != nil && d.ResetReason != nil {
		session = fmt.Sprintf("forecast session %s, started %s (%s)", *d.SessionID, d.Since.UTC().Format(time.RFC3339), *d.ResetReason)
	}
	run := DoctorCheck{Name: "admission dry run", Status: "ok",
		Message: fmt.Sprintf("dry run: %s; it models %s capacity for %s only; predictions are forecasts, not blocks",
			session, strings.ReplaceAll(d.PredictionScope, "_", " "), strings.Join(d.ModelledKinds, ", "))}
	if !d.Active {
		run.Message = "dry run is off; " + session + "; nothing is forecast"
	}
	if d.ForecastError != nil {
		run.Status = "warn"
		run.Message += "; forecasting is held: " + *d.ForecastError
		if d.LastErrorAt != nil {
			run.Message += " since " + d.LastErrorAt.UTC().Format(time.RFC3339)
		}
		run.Fix = "the owner retries at its next turn; check the firewall engine, the admission clock, the state database or the configuration the code names"
	}
	rows := []DoctorCheck{run}
	if d.Active && d.Occupancy != nil && d.Ceiling != nil {
		rows = append(rows, dryRunCapacityCheck(d))
	}
	examples := DoctorCheck{Name: "admission dry-run examples", Status: "ok", Message: "no forecast examples or summaries were lost"}
	var problems []string
	if d.ExamplesLost > 0 || d.RecordErrors > 0 {
		problems = append(problems, fmt.Sprintf("%d examples lost, %d failed example writes or maintenance steps", d.ExamplesLost, d.RecordErrors))
	}
	if d.SummariesLost > 0 {
		problems = append(problems, fmt.Sprintf("%d summaries lost", d.SummariesLost))
	}
	if d.ExamplesStale {
		problems = append(problems, "examples of earlier sessions wait for a purge")
	}
	if len(problems) > 0 {
		examples.Status, examples.Message = "warn", strings.Join(problems, "; ")
		examples.Fix = "examples are previews only; check that the state database is writable, and expect the purge to resume on its own"
	}
	if d.ComparisonIncomplete {
		examples.Message += "; examples and comparison counts are incomplete after a restart or a loss"
	}
	return append(rows, examples)
}

// dryRunCapacityCheck compares real and predicted temporary capacity and
// the modelled ceiling, and warns on model limits and modelled waits.
func dryRunCapacityCheck(d *health.AdmissionDryRun) DoctorCheck {
	occ, ceil := d.Occupancy, d.Ceiling
	limit := fmt.Sprintf("of %d", occ.Limit)
	if occ.Unlimited {
		limit = "of an unlimited set"
	}
	c := DoctorCheck{Name: "admission dry-run capacity", Status: "ok", Message: fmt.Sprintf(
		"%d real temporary blocks, %d %s predicted with %d forecast blocks; the modelled ceiling has %d general and %d reserved units left",
		occ.Actual, occ.Predicted, limit, occ.ShadowOnly, ceil.GeneralBudget, ceil.ReservedBudget)}
	var warnings []string
	if occ.Unlimited {
		warnings = append(warnings, "the temporary set is unlimited, which the forecast follows only in staging")
	}
	if occ.Limited {
		warnings = append(warnings, "the forecast models no more active blocks")
	}
	var waits []string
	for _, name := range []string{"ceiling", "set_full", "pending_recovery", "forecast_limited"} {
		if n := d.LastHour[name]; n > 0 {
			waits = append(waits, fmt.Sprintf("%d %s", n, name))
		}
	}
	if len(waits) > 0 {
		warnings = append(warnings, "in the last hour live admission would have waited: "+strings.Join(waits, ", "))
	}
	if len(warnings) > 0 {
		c.Status, c.Message = "warn", c.Message+"; "+strings.Join(warnings, "; ")
		c.Fix = "a forecast wait is a model result, not a block; review auto_response.max_blocks_per_hour and firewall.deny_temp_ip_limit before going live"
	}
	return c
}
