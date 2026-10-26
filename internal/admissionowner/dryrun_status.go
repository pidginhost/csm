package admissionowner

import (
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
)

// predictionScope names what the forecast models (spec 3.1).
const predictionScope = "ceiling_and_temporary_capacity"

// dryRunStatus reads the forecast for status (spec 3.8). While the owner
// forecasts it shows the session's model and counts, and no identity until
// a session starts; otherwise only the last session's identity. Loss and
// error counters cover the process.
func (o *Owner) dryRunStatus() *health.AdmissionDryRun {
	d := &health.AdmissionDryRun{
		Active: o.forecasting(), ModelledKinds: []string{admission.KindBlockIP.String()}, PredictionScope: predictionScope,
		ExamplesLost: o.out.examplesLost, SummariesLost: o.out.summariesLost, RecordErrors: o.out.recordErrors, ExamplesStale: o.out.stale,
		ComparisonIncomplete: o.out.restarted || o.out.examplesLost > 0 || o.out.summariesLost > 0 || o.compare.droppedRows() > 0,
	}
	var picks, recent [admission.PredictionSlots]uint64
	// An earlier session's identity shows only once the owner stops
	// forecasting; an active forecast without a session shows none.
	var session sessionInfo
	if !d.Active {
		session = o.out.last
	}
	if s := o.shadow; s != nil {
		session = sessionInfo{id: s.id, since: s.since, reset: s.reset}
		if d.Active {
			picks, recent = s.picks, s.recent.total(monoNow())
			d.Occupancy, d.Ceiling = s.occupancyStatus(), s.ceilingStatus()
		}
	}
	if session.id != "" {
		id, since, reset := session.id, session.since, session.reset.String()
		d.SessionID, d.Since, d.ResetReason = &id, &since, &reset
	}
	d.Picks, d.LastHour = predictionMap(picks), predictionMap(recent)
	if o.forecastErr != "" {
		code := string(o.forecastErr)
		d.ForecastError = &code
	}
	if !o.forecastErrAt.IsZero() {
		at := o.forecastErrAt
		d.LastErrorAt = &at
	}
	return d
}

// predictionMap names every prediction's count, zeros included.
func predictionMap(counts [admission.PredictionSlots]uint64) map[string]uint64 {
	out := make(map[string]uint64, admission.PredictionSlots-1)
	for p := admission.Prediction(1); p.Valid(); p++ {
		out[p.String()] = counts[p]
	}
	return out
}

// occupancyStatus is the temporary capacity as the last snapshot saw it,
// with the forecast blocks the real sets do not hold; nil without one.
func (s *shadow) occupancyStatus() *health.AdmissionDryRunOccupancy {
	if s.adm == nil {
		return nil
	}
	only := max(len(s.entries)-len(s.adm.ShadowHeld), 0)
	return &health.AdmissionDryRunOccupancy{
		Actual: s.adm.Temporary, ShadowOnly: only, Predicted: s.adm.Temporary + only, Limit: s.adm.Limit,
		Unlimited: s.adm.Limit == 0, Limited: s.limited(),
	}
}

func (s *shadow) ceilingStatus() *health.AdmissionDryRunCeiling {
	c := s.ceiling
	return &health.AdmissionDryRunCeiling{
		Limit: c.Limit, GeneralUsed: c.General.Used, ReservedUsed: c.Reserved.Used,
		GeneralBudget: c.Budget(admission.LaneGeneral), ReservedBudget: c.Budget(admission.LaneDirect),
	}
}
