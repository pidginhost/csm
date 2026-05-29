package firewall

// RuleCounts holds firewall rule cardinalities sourced from the engine
// state file, which is the authoritative store. The parallel bbolt
// fw:* buckets are written only during migration, so anything counting
// live rules must read the engine, not the store. Expired temp bans are
// excluded.
type RuleCounts struct {
	Blocked     int
	Allowed     int
	Subnets     int
	PortAllowed int
}

// Total returns the sum across all rule categories.
func (c RuleCounts) Total() int {
	return c.Blocked + c.Allowed + c.Subnets + c.PortAllowed
}
