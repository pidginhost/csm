//go:build linux

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallPortHandlersReportPersistenceFailure(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "add", true: "remove"}[remove], func(t *testing.T) {
			dir := t.TempDir()
			e, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, dir)
			if err != nil {
				t.Fatal(err)
			}
			if remove {
				if err = e.AllowIPPort("192.0.2.10", 443, "tcp", "via CLI"); err != nil {
					t.Fatal(err)
				}
			}
			// A nonempty legacy staging directory forces the writer to fail while
			// leaving the prior state readable, including for the removal handler.
			blocker := filepath.Join(dir, "firewall", "state.json.tmp")
			if err = os.Mkdir(blocker, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(blocker, "held"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			c := &ControlListener{d: &Daemon{fwEngine: e}}
			args := json.RawMessage(`{"ip":"192.0.2.10","port":443,"proto":"tcp"}`)
			handler := c.handleFirewallAllowPort
			if remove {
				handler = c.handleFirewallRemovePort
			}
			result, err := handler(args)
			if err == nil || !strings.Contains(err.Error(), "persisting port allow change") || result != nil {
				t.Fatalf("handler returned result=%v, error=%v after write failure", result, err)
			}
		})
	}
}

func TestFirewallPortHandlerDescribesDeferredApply(t *testing.T) {
	e, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &ControlListener{d: &Daemon{fwEngine: e}}
	args := json.RawMessage(`{"ip":"192.0.2.10","port":443,"proto":"tcp"}`)
	for _, handler := range []func(json.RawMessage) (any, error){c.handleFirewallAllowPort, c.handleFirewallRemovePort} {
		result, err := handler(args)
		if err != nil {
			t.Fatal(err)
		}
		ack, ok := result.(control.FirewallAckResult)
		if !ok || !strings.Contains(ack.Message, "takes effect after firewall reload") {
			t.Fatalf("misleading ack: %+v", result)
		}
	}
}
