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
	rows := admission.DoctorChecks(a.Ledger, a.Ingress, a.CheckedAt, admissionExecuting(a))
	checks := make([]DoctorCheck, 0, len(rows))
	for _, r := range rows {
		checks = append(checks, DoctorCheck{Name: r.Name, Status: r.Status, Message: r.Message, Fix: r.Fix})
	}
	return append(checks, ownerDoctorChecks(a)...)
}

// admissionExecuting says whether the snapshot's admission runs automatic
// blocks rather than previewing them.
func admissionExecuting(a *health.AdmissionStatus) bool {
	return a != nil && a.Owner != nil && a.Owner.Executing
}

// ownerDoctorChecks renders what only the ledger's owner knows: whether it
// runs, its clock, its turns, the ceiling's source, the legacy import and
// the inventory reads. Once admission executes, a stopped owner, a refused
// clock reading, a failing turn and discarded responses stop automatic
// blocks and fail.
func ownerDoctorChecks(a *health.AdmissionStatus) []DoctorCheck {
	o := a.Owner
	if o == nil {
		return nil
	}
	closing, outage := admission.DoctorImpact(o.Executing)
	keep := "keep the state database, which existing blocking still uses"
	if o.Executing {
		keep = "keep the state database"
	}
	owner := DoctorCheck{Name: "admission owner", Status: "ok", Message: closing}
	if o.Error != "" {
		owner = DoctorCheck{
			Name: "admission owner", Status: outage, Message: "the admission ledger is not running: " + o.Error + "; " + closing,
			Fix: "the daemon retries at every tick; " + keep + ", and report the error",
		}
	}
	clock := DoctorCheck{Name: "admission clock", Status: "ok", Message: closing}
	switch {
	case o.TickError != "":
		clock = DoctorCheck{
			Name: "admission clock", Status: outage, Message: "the last clock reading was refused: " + o.TickError + "; " + closing,
			Fix: "nothing is admitted until a reading succeeds; check the system clock and /proc/sys/kernel/random/boot_id",
		}
	case o.ClockDegraded:
		clock = DoctorCheck{
			Name: "admission clock", Status: "warn",
			Message: "the wall clock is behind the ledger's time or disagrees with the time since boot; wall time alone proves nothing new until they agree; " + closing,
			Fix:     "check time synchronisation",
		}
	}
	rows := []DoctorCheck{owner, clock}
	if o.TurnError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission turns", Status: outage, Message: "the last admission turn failed: " + o.TurnError + "; " + closing,
			Fix: "the owner retries from one second, backing off to once a minute; " + keep + ", and report the error",
		})
	}
	if o.RetirementError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission retirement", Status: "warn", Message: "retiring uncertain blocks failed: " + o.RetirementError + "; " + closing,
			Fix: "each uncertain block stays held and is retried, backing off to once a minute; " + keep + ", and report the error",
		})
	}
	if o.AuditError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission audit delivery", Status: "warn",
			Message: "audit delivery is pending: " + o.AuditError + "; " + closing,
			Fix:     "keep the state database and pending rows; repair the named storage error; delivery retries automatically and never repeats enforcement",
		})
	}
	if a.Ledger != nil && a.Ledger.Ceiling.Error == "" && a.Ledger.Ceiling.Limit > 0 {
		limit := a.Ledger.Ceiling.Limit
		c := DoctorCheck{Name: "admission ceiling", Status: "ok", Message: fmt.Sprintf("%d automatic responses per hour (%s)", limit, o.CeilingSource) + "; " + closing}
		switch {
		case o.CeilingSource == config.CeilingClamped:
			c.Status = "warn"
			c.Message = fmt.Sprintf("auto_response.max_blocks_per_hour exceeds the largest ceiling the ledger accepts; it uses %d", limit) + "; " + closing
			c.Fix = fmt.Sprintf("set auto_response.max_blocks_per_hour to at most %d", admission.MaxCeiling)
		case limit == 1:
			c.Status = "warn"
			c.Message = "a ceiling of 1 runs only the reserved lane: only direct compromise and corroborated responses can be served; " + closing
			c.Fix = "raise auto_response.max_blocks_per_hour, or remove it to use the default"
		}
		rows = append(rows, c)
	}
	if imp := o.Import; imp != nil {
		c := DoctorCheck{Name: "admission legacy import", Status: "ok", Message: "the legacy hourly count held no blocks of the last hour; " + closing}
		switch {
		case imp.Error != "":
			c.Status = "warn"
			c.Message = "the legacy hourly count could not be read (" + imp.Error + "); the ledger started without saved credit; " + closing
			c.Fix = "none needed: credit refills at the ceiling's rate"
		case imp.Units > 0:
			c.Message = fmt.Sprintf("%d blocks imported from the legacy hourly count; they count at least until %s", imp.Units, imp.At.Add(admission.CeilingWindow).UTC().Format(time.RFC3339)) + "; " + closing
		}
		rows = append(rows, c)
	}
	if o.InventoryError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission inventory", Status: "warn", Message: "the last hosting inventory read failed: " + o.InventoryError + "; " + closing,
			Fix: "admission keeps the previous accounts; check the account registry and home directories",
		})
	}
	if o.ExecutionHeld != "" {
		fix := "admission probes the firewall from one second, backing off to once a minute, and keeps uncertain actions held; an apply fault clears when the next batch applies; check the firewall rows and the storage under the state directory"
		if o.ExecutionHeldBy == "policy" {
			fix = "correct the setting the message names; held block work waits until the daemon installs a valid policy"
		}
		rows = append(rows, DoctorCheck{
			Name: "admission execution", Status: outage, Message: "automatic blocks are held: " + o.ExecutionHeld + "; " + closing,
			Fix: fix,
		})
	}
	if o.DamageError != "" {
		rows = append(rows, DoctorCheck{
			Name: "admission ledger damage", Status: outage, Message: "responses naming a damaged ledger record are discarded: " + o.DamageError + "; " + closing,
			Fix: "restart csm.service so opening the ledger proves every record; " + keep + ", and report the damage",
		})
	}
	if o.Set != nil || o.SetError != "" {
		rows = append(rows, setDoctorCheck(o, closing))
	}
	return append(rows, dryRunDoctorChecks(o.DryRun)...)
}

// setDoctorCheck shows the temporary set the owner's last turn budgeted
// block work by (spec 5.6): the partitions of the automatic slots, the
// entries admission never evicts with their drain time and the previews
// of the last hour that took a lower-priority block's slot. It warns as
// the forecast's model does, when the turn could not read the set and
// when a preview of the last hour rotated an equal-priority block out.
func setDoctorCheck(o *health.AdmissionOwner, closing string) DoctorCheck {
	if o.Set == nil {
		return DoctorCheck{Name: "admission set", Status: "warn",
			Message: "the temporary set could not be read: " + o.SetError + "; block work has no slot budget until a turn reads it" +
				replacedNote(o.PreviewReplacementsLastHour, "previews") + rotatedNote(o.PreviewRotationsLastHour, "previews") + "; " + closing,
			Fix: "the owner reads the set again at its next turn; check the firewall engine and the blocked sets"}
	}
	s := o.Set
	of := fmt.Sprintf("of %d", s.Limit)
	if s.Unlimited {
		of = "of an unlimited set"
	}
	c := DoctorCheck{Name: "admission set", Status: "ok", Message: fmt.Sprintf("automatic blocks use %d of %d general and %d of %d reserved temporary slots %s",
		s.General.Used, s.General.Size, s.Reserved.Used, s.Reserved.Size, of) + setOccupants(s.Unclaimed, s.Imported, s.DrainSeconds) +
		replacedNote(o.PreviewReplacementsLastHour, "previews")}
	warnings, note := setWarnings(s.Unlimited, s.Capacity, s.DrainSeconds, s.General, s.Reserved)
	c.Message += note
	if n := o.PreviewRotationsLastHour; n > 0 {
		warnings = append(warnings, rotatedWarning(n, "previews"))
	}
	if len(warnings) > 0 {
		c.Status, c.Message = "warn", c.Message+"; "+strings.Join(warnings, "; ")
		c.Fix = "block work waits for a free slot unless it outranks an automatic block it may replace or a new attack may rotate out an equal-priority block held for 30 minutes; inspect existing blocks and their expiries, and review firewall.deny_temp_ip_limit"
	}
	c.Message += "; " + closing
	return c
}

// replacedNote names the replacements of lower-priority automatic blocks
// in the last hour, which are admissions, not waits; empty without any.
func replacedNote(n uint64, what string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; in the last hour %d %s would have replaced lower-priority automatic blocks", n, what)
}

// rotatedNote names the rotations of equal-priority automatic blocks in
// the last hour; empty without any.
func rotatedNote(n uint64, what string) string {
	if n == 0 {
		return ""
	}
	return "; " + rotatedWarning(n, what)
}

// rotatedWarning says that n of what in the last hour would have rotated
// an equal-priority automatic block out: the set is too small for the
// attack (spec 5.17).
func rotatedWarning(n uint64, what string) string {
	return fmt.Sprintf("in the last hour %d %s would have rotated out an equal-priority automatic block held for at least 30 minutes; the set is too small for the attack", n, what)
}

// sharesNote names how many scopes share each partition and the fewest
// slots each is due; empty without a scope.
func sharesNote(s health.AdmissionDryRunShares) string {
	var parts []string
	for _, p := range []struct {
		name  string
		share health.AdmissionDryRunShare
	}{{"general", s.General}, {"reserved", s.Reserved}} {
		if p.share.Scopes > 0 {
			parts = append(parts, fmt.Sprintf("%s slots shared by scopes: %d, at least %d each", p.name, p.share.Scopes, p.share.Share))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "; " + strings.Join(parts, "; ")
}

// setOccupants describes the entries automatic admission never evicts and
// the legacy automatic blocks with their drain time; empty without either.
func setOccupants(unclaimed, imported int, drainSeconds int64) string {
	if unclaimed == 0 && imported == 0 {
		return ""
	}
	s := fmt.Sprintf("; %d entries automatic admission never evicts and %d legacy automatic blocks", unclaimed, imported)
	if drainSeconds < 0 {
		return s + " have an unknown drain time"
	}
	return s + fmt.Sprintf(" have an estimated drain time of %s", time.Duration(drainSeconds)*time.Second)
}

// setWarnings are the warnings of a set as automatic admission divides it:
// an unknown drain, the modelled capacity of an unlimited set, a set the
// entries admission never evicts fill and no free automatic slot. note
// explains a set where only the reserve has room.
func setWarnings(unlimited bool, capacity int, drainSeconds int64, general, reserved health.AdmissionDryRunPartition) (warnings []string, note string) {
	if drainSeconds < 0 {
		warnings = append(warnings, "a remaining kernel expiry is unavailable; inspect the affected blocks")
	}
	if unlimited {
		warnings = append(warnings, fmt.Sprintf("the temporary set is unlimited for operator blocks; automatic admission is modelled at %d slots", capacity))
	}
	if general.Size+reserved.Size == 0 {
		warnings = append(warnings, "entries automatic admission never evicts fill the set; review these blocks or wait for expiry")
	}
	if general.Free+reserved.Free == 0 && general.Size+reserved.Size > 0 {
		warnings = append(warnings, "the temporary set has no free automatic slot; review existing blocks or wait for expiry")
	}
	if general.Free == 0 && reserved.Free > 0 {
		note = "; only direct or corroborated work has a set slot; general work waits for more capacity"
	}
	return warnings, note
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

// dryRunCapacityCheck compares real and predicted temporary capacity, the
// modelled partitions of the automatic slots and the modelled ceiling,
// names modelled replacements, and warns on model limits and modelled
// waits.
func dryRunCapacityCheck(d *health.AdmissionDryRun) DoctorCheck {
	occ, ceil := d.Occupancy, d.Ceiling
	limit := fmt.Sprintf("of %d", occ.Limit)
	if occ.Unlimited {
		limit = "of an unlimited set"
	}
	c := DoctorCheck{Name: "admission dry-run capacity", Status: "ok", Message: fmt.Sprintf(
		"%d real temporary elements, %d %s predicted with %d forecast blocks; automatic blocks use %d of %d general and %d of %d reserved slots; the modelled ceiling has %d general and %d reserved units left",
		occ.Actual, occ.Predicted, limit, occ.ShadowOnly, occ.General.Used, occ.General.Size, occ.Reserved.Used, occ.Reserved.Size, ceil.GeneralBudget, ceil.ReservedBudget)}
	c.Message += setOccupants(occ.Unclaimed, occ.Imported, occ.DrainSeconds)
	if occ.Replaced > 0 {
		c.Message += fmt.Sprintf("; legacy automatic blocks the forecast counts as replaced: %d", occ.Replaced)
	}
	c.Message += replacedNote(d.LastHour["capacity_evict"], "forecast blocks") + sharesNote(occ.Shares)
	warnings, note := setWarnings(occ.Unlimited, occ.Capacity, occ.DrainSeconds, occ.General, occ.Reserved)
	c.Message += note
	if occ.Limited {
		warnings = append(warnings, "the forecast models no more active blocks")
	}
	if n := d.LastHour["capacity_rotate"]; n > 0 {
		warnings = append(warnings, rotatedWarning(n, "forecast blocks"))
	}
	var waits []string
	for _, name := range []string{"ceiling", "set_full", "equal_tier_wait", "pending_recovery", "forecast_limited"} {
		if n := d.LastHour[name]; n > 0 {
			waits = append(waits, fmt.Sprintf("%d %s", n, name))
		}
	}
	if len(waits) > 0 {
		warnings = append(warnings, "in the last hour live admission would have waited: "+strings.Join(waits, ", "))
	}
	if len(warnings) > 0 {
		c.Status, c.Message = "warn", c.Message+"; "+strings.Join(warnings, "; ")
		c.Fix = "a forecast wait is a model result, not a block; inspect existing blocks and their expiries, then review auto_response.max_blocks_per_hour and firewall.deny_temp_ip_limit before going live"
		if occ.Unclaimed > 0 || occ.Imported > 0 {
			c.Fix += "; the drain estimate can change with renewals or new blocks; a missing kernel expiry needs operator review"
		}
	}
	return c
}
