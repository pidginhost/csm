//go:build linux

package daemon

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestProtocolAllowStatusFollowsEngineConfig(t *testing.T) {
	c := newListenerForTest(t)
	before := &firewall.FirewallConfig{Enabled: true}
	c.d.cfg = &config.Config{StatePath: t.TempDir(), Firewall: before}
	config.SetActive(c.d.cfg)
	c.d.fwEngine = &firewall.Engine{}
	after := *before
	after.ProtocolAllow = []firewall.ProtocolAllowRule{{Protocol: "vrrp", Peers: []string{"192.0.2.11", "2001:db8::11"}}}

	// Re-apply and rollback replace the engine config while the daemon's
	// restart-required snapshot stays at its startup value.
	for _, step := range []struct {
		name string
		cfg  *firewall.FirewallConfig
		want []string
	}{
		{"startup", before, []string{}},
		{"reapply", &after, []string{"vrrp 192.0.2.11, 2001:db8::11"}},
		{"rollback", before, []string{}},
	} {
		t.Run(step.name, func(t *testing.T) {
			c.d.fwEngine.SetConfig(step.cfg)
			raw, err := c.handleFirewallStatus(nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := raw.(control.FirewallStatusResult).ProtocolAllow; !reflect.DeepEqual(got, step.want) {
				t.Errorf("status protocols = %q, want %q", got, step.want)
			}
			raw, err = c.handleFirewallPorts(nil)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, line := range raw.(control.FirewallListResult).Lines {
				if strings.HasPrefix(line, "  vrrp ") {
					got = append(got, strings.TrimSpace(line))
				}
			}
			if strings.Join(got, "\n") != strings.Join(step.want, "\n") {
				t.Errorf("ports protocols = %q, want %q", got, step.want)
			}
		})
	}
}
