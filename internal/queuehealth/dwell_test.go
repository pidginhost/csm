package queuehealth

import (
	"testing"
	"time"
)

func TestDwellRequiresContinuousCondition(t *testing.T) {
	now := time.Unix(1000, 0)
	var d Dwell
	if d.Held(now, false, MeasurementWindow) {
		t.Fatal("absent condition reported as held")
	}
	if d.Held(now, true, MeasurementWindow) {
		t.Fatal("a single sample reported as a sustained condition")
	}
	if d.Held(now.Add(MeasurementWindow-time.Second), true, MeasurementWindow) {
		t.Fatal("condition held before the window elapsed")
	}
	if !d.Held(now.Add(MeasurementWindow), true, MeasurementWindow) {
		t.Fatal("sustained condition never held")
	}
	if d.Held(now.Add(MeasurementWindow+time.Second), false, MeasurementWindow) {
		t.Fatal("recovered condition still held")
	}
	if d.Held(now.Add(2*MeasurementWindow), true, MeasurementWindow) {
		t.Fatal("a recurrence inherited the earlier window")
	}
}
