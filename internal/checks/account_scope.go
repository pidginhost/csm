package checks

import "context"

type accountScopeKey struct{}

// ContextWithAccountScope returns a derived context that restricts
// filesystem-based checks to a single cPanel/Linux account. Callers
// pass the resulting context into every check; helpers like
// GetScanHomeDirs read the scope back out. Empty account is a no-op
// (returns ctx unchanged, equivalent to a full host scan).
func ContextWithAccountScope(ctx context.Context, account string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if account == "" {
		return ctx
	}
	return context.WithValue(ctx, accountScopeKey{}, account)
}

// AccountFromContext returns the account scope previously attached by
// ContextWithAccountScope, or "" when no scope is set.
func AccountFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(accountScopeKey{}).(string)
	return v
}
