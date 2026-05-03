// Package threatintel defines a pluggable interface for IP reputation
// providers and an Aggregator that combines their scores. CSM uses this
// to consult AbuseIPDB plus optional rspamd / upstream sources without
// hardcoding multiple lookup paths in the reputation check.
package threatintel

import "context"

// Source is a single scoring provider. Score returns 0..100 (higher is
// worse). A source that has no opinion on the IP must return 0, nil -
// that score is excluded from the aggregator's average. Errors are
// per-source and non-fatal at the aggregator level (other sources still
// run).
type Source interface {
	Name() string
	Score(ctx context.Context, ip string) (int, error)
}

// Aggregator runs every registered source and averages their non-zero scores.
type Aggregator struct {
	sources []Source
}

// NewAggregator constructs an empty Aggregator.
func NewAggregator() *Aggregator { return &Aggregator{} }

// Register adds a Source to the aggregator. Order matters only for the
// `Sources` field of Result (which preserves registration order); the
// aggregated score is order-independent.
func (a *Aggregator) Register(s Source) { a.sources = append(a.sources, s) }

// Result holds the aggregated value and per-source breakdown.
type Result struct {
	AggregatedScore int            `json:"aggregated_score"`
	Sources         map[string]int `json:"sources"`
}

// Score queries every registered source. Per-source errors are swallowed
// (the source contributes "no signal"). The aggregated score is the mean
// of non-zero scores; if every source returned 0 (or errored), the
// aggregated score is 0.
func (a *Aggregator) Score(ctx context.Context, ip string) (Result, error) {
	out := Result{Sources: map[string]int{}}
	sum, n := 0, 0
	for _, s := range a.sources {
		score, err := s.Score(ctx, ip)
		if err != nil {
			continue
		}
		out.Sources[s.Name()] = score
		if score > 0 {
			sum += score
			n++
		}
	}
	if n > 0 {
		out.AggregatedScore = sum / n
	}
	return out, nil
}
