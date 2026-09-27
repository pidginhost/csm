package crawlreplay

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestHourOfWeekStartsMonday(t *testing.T) {
	monday := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC).Unix() / 60
	sunday := time.Date(2026, 9, 27, 23, 59, 0, 0, time.UTC).Unix() / 60
	if got := hourOfWeek(monday); got != 0 {
		t.Fatalf("Monday 00:00 = slot %d, want 0", got)
	}
	if got := hourOfWeek(sunday); got != 167 {
		t.Fatalf("Sunday 23:59 = slot %d, want 167", got)
	}
	if hourOfWeek(monday+59) != 0 || hourOfWeek(monday+60) != 1 {
		t.Fatal("slot must change exactly on the hour")
	}
}

func TestBaselineColdTrainedAndZero(t *testing.T) {
	p := BaselineParams{Alpha: 0.5, MinObs: 2, MinAge: 2 * 60 * 24 * 7, FloorPerMin: 3}
	start := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC).Unix() / 60
	b := NewBaseline(p, start)
	if got := b.Expected(start); got != 3 {
		t.Fatalf("cold key = %v, want floor 3", got)
	}
	week := int64(60 * 24 * 7)
	b.Observe(start, 10)
	b.Observe(start+week, 20)
	if got := b.Expected(start + week); got != 3 {
		t.Fatalf("slot observed but key too young = %v, want floor", got)
	}
	if got := b.Expected(start + 2*week); got != 15 {
		t.Fatalf("trained slot = %v, want EWMA 15", got)
	}
	if got := b.Expected(start + 2*week + 60); got != 3 {
		t.Fatalf("untrained neighbour slot = %v, want floor", got)
	}
	z := NewBaseline(p, start)
	z.Observe(start, 0)
	z.Observe(start+week, 0)
	if got := z.Expected(start + 2*week); got != 3 {
		t.Fatalf("zero expectation = %v, want floor", got)
	}
}

func TestBaselineParamsValidate(t *testing.T) {
	good := BaselineParams{Alpha: 0.1, MinObs: 1, MinAge: 0, FloorPerMin: 1}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]BaselineParams{
		"alpha zero":  {Alpha: 0, MinObs: 1, FloorPerMin: 1},
		"alpha big":   {Alpha: 1.5, MinObs: 1, FloorPerMin: 1},
		"alpha nan":   {Alpha: math.NaN(), MinObs: 1, FloorPerMin: 1},
		"obs":         {Alpha: 0.1, MinObs: 0, FloorPerMin: 1},
		"age":         {Alpha: 0.1, MinObs: 1, MinAge: -1, FloorPerMin: 1},
		"floor zero":  {Alpha: 0.1, MinObs: 1},
		"floor inf":   {Alpha: 0.1, MinObs: 1, FloorPerMin: math.Inf(1)},
		"floor nan":   {Alpha: 0.1, MinObs: 1, FloorPerMin: math.NaN()},
		"floor below": {Alpha: 0.1, MinObs: 1, FloorPerMin: -2},
	} {
		if err := p.Validate(); !errors.Is(err, ErrParams) {
			t.Errorf("%s: %v, want ErrParams", name, err)
		}
	}
}
