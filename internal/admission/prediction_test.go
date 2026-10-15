package admission

import "testing"

// Every prediction has a fixed, distinct name.
func TestPredictionNames(t *testing.T) {
	want := map[Prediction]string{
		PredictCapacityAdmit: "capacity_admit", PredictExistingActual: "existing_actual", PredictExistingShadow: "existing_shadow",
		PredictCeiling: "ceiling", PredictSetFull: "set_full", PredictPendingRecovery: "pending_recovery",
		PredictForecastLimited: "forecast_limited", PredictNotModelled: "not_modelled",
	}
	if len(want) != PredictionSlots-1 {
		t.Fatalf("%d names for %d predictions", len(want), PredictionSlots-1)
	}
	for p, name := range want {
		if got := p.String(); got != name || !p.Valid() {
			t.Errorf("prediction %d = %q, want %q", p, got, name)
		}
	}
	if Prediction(0).Valid() || predictionEnd.Valid() {
		t.Fatal("an out-of-range prediction is valid")
	}
}
