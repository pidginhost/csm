package threatintel

import "context"

// AbuseIPDBSource adapts the existing reputation lookup function to the
// Source interface. The underlying function lives in internal/checks/
// and is injected at construction (avoids an import cycle).
type AbuseIPDBSource struct {
	lookup func(ctx context.Context, ip string) (int, error)
}

// NewAbuseIPDBSource wraps the provided lookup function. The caller
// (typically internal/checks/reputation.go) supplies a closure over its
// existing AbuseIPDB query path.
func NewAbuseIPDBSource(lookup func(context.Context, string) (int, error)) *AbuseIPDBSource {
	return &AbuseIPDBSource{lookup: lookup}
}

func (a *AbuseIPDBSource) Name() string { return "abuseipdb" }
func (a *AbuseIPDBSource) Score(ctx context.Context, ip string) (int, error) {
	return a.lookup(ctx, ip)
}
