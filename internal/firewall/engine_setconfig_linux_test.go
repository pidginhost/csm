//go:build linux

package firewall

import "testing"

// The engine applied the FirewallConfig it was constructed with forever.
// SetConfig replaces the ruleset input so a re-apply builds the edited
// rules; Config exposes what the next Apply will use.
func TestSetConfigReplacesRulesetInput(t *testing.T) {
	e := &Engine{cfg: &FirewallConfig{TCPIn: []int{22}}}
	e.SetConfig(&FirewallConfig{TCPIn: []int{22, 8443}})
	got := e.Config()
	if got == nil || len(got.TCPIn) != 2 || got.TCPIn[1] != 8443 {
		t.Fatalf("engine config after SetConfig = %+v", got)
	}
	e.SetConfig(nil)
	if e.Config() != got {
		t.Fatal("nil SetConfig replaced the configuration")
	}
}
