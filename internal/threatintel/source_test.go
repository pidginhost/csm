package threatintel

import (
	"context"
	"errors"
	"testing"
)

func TestAggregator_AveragesScores(t *testing.T) {
	a := NewAggregator()
	a.Register(stubSource{name: "abuseipdb", score: 80})
	a.Register(stubSource{name: "rspamd", score: 40})

	got, err := a.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got.AggregatedScore != 60 {
		t.Fatalf("expected average=60, got %d", got.AggregatedScore)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(got.Sources))
	}
}

func TestAggregator_OneSourceErrorDoesNotKillRest(t *testing.T) {
	a := NewAggregator()
	a.Register(stubSource{name: "abuseipdb", score: 80})
	a.Register(stubSource{name: "broken", err: errStubFailed})

	got, err := a.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err) // aggregator should swallow per-source errors
	}
	if got.AggregatedScore != 80 {
		t.Fatalf("expected score=80, got %d", got.AggregatedScore)
	}
}

func TestAggregator_ZeroScoresExcludedFromAverage(t *testing.T) {
	a := NewAggregator()
	a.Register(stubSource{name: "rspamd", score: 0})
	a.Register(stubSource{name: "abuseipdb", score: 60})

	got, err := a.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got.AggregatedScore != 60 {
		t.Fatalf("expected only-rspamd-zero to leave average=60, got %d", got.AggregatedScore)
	}
}

func TestAggregator_AllZeroIsZero(t *testing.T) {
	a := NewAggregator()
	a.Register(stubSource{name: "a", score: 0})
	a.Register(stubSource{name: "b", score: 0})

	got, err := a.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got.AggregatedScore != 0 {
		t.Fatalf("expected 0, got %d", got.AggregatedScore)
	}
}

type stubSource struct {
	name  string
	score int
	err   error
}

func (s stubSource) Name() string { return s.name }
func (s stubSource) Score(_ context.Context, _ string) (int, error) {
	return s.score, s.err
}

var errStubFailed = errors.New("boom")
