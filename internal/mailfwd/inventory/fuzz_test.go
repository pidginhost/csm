package inventory

import (
	"strings"
	"testing"
)

// FuzzParseForwarderLine feeds attacker-controlled valias/alias content
// (forwarders are writable by panel users) and asserts the parser never
// panics and keeps its invariants.
func FuzzParseForwarderLine(f *testing.F) {
	seeds := []string{
		"contact: psi@yahoo.com",
		"owner: owner@x.test, ext@gmail.com",
		"app: |/usr/local/bin/x",
		"void: :blackhole:",
		"# comment",
		"",
		":::::",
		"a:@",
		"weird: \x00\x01@\xff.com",
		strings.Repeat("a", 5000) + ": b@c.com",
	}
	for _, s := range seeds {
		f.Add("dom.test", s)
	}
	local := map[string]bool{"x.test": true}
	f.Fuzz(func(t *testing.T, domain, line string) {
		fwd, ok := parseForwarderLine(domain, line, local)
		if !ok {
			return
		}
		if fwd.Source == "" {
			t.Errorf("ok forwarder has empty Source: line=%q", line)
		}
		if len(fwd.Destinations) == 0 {
			t.Errorf("ok forwarder has no destinations: line=%q", line)
		}
		// ForwardOnly and KeepLocal are mutually exclusive and one must hold
		// once there is at least one address destination.
		if fwd.ForwardOnly == fwd.KeepLocal {
			t.Errorf("ForwardOnly/KeepLocal must differ: %+v line=%q", fwd, line)
		}
		// HasFreeProvider implies HasExternal.
		if fwd.HasFreeProvider() && !fwd.HasExternal() {
			t.Errorf("free provider without external: %+v", fwd)
		}
	})
}
