package alert

import "github.com/pidginhost/csm/internal/config"

// EmitForTest drives emitAudit with no audit sinks so callers (often in
// other packages' tests) can trigger observer fan-out without setting up
// jsonl/syslog. Lives in a non-test file because Go tests cannot import
// _test.go symbols across packages.
func EmitForTest(f Finding) {
	emitAudit(&config.Config{Hostname: "test"}, []Finding{f})
}
