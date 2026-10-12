package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallStartupRetriesAndRetainsFailure(t *testing.T) {
	for _, failAt := range []string{"constructor", "apply"} {
		t.Run(failAt, func(t *testing.T) {
			cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
			d := New(cfg, nil, nil, "")
			attempts, applies := 0, 0
			var events []string
			failure := errors.New("fixture nftables failure")
			d.startFirewallUsing(firewallStartupOps{
				newEngine: func(*firewall.FirewallConfig, string) (*firewall.Engine, error) {
					attempts++
					events = append(events, "new")
					if failAt == "constructor" {
						return nil, failure
					}
					return new(firewall.Engine), nil
				},
				apply:  func(*firewall.Engine) error { applies++; events = append(events, "apply"); return failure },
				delays: []time.Duration{0, 0},
			})
			if attempts != 3 || d.fwEngine != nil || !strings.Contains(d.fwStartupError, failure.Error()) {
				t.Fatalf("startup did not retain bounded failure: attempts=%d engine=%p error=%q", attempts, d.fwEngine, d.fwStartupError)
			}
			if failAt == "constructor" && applies != 0 || failAt == "apply" && applies != 3 {
				t.Fatalf("unexpected apply count %d", applies)
			}
			wantEvents := "new,new,new"
			if failAt == "apply" {
				wantEvents = "new,apply,new,apply,new,apply"
			}
			if strings.Join(events, ",") != wantEvents {
				t.Fatalf("unexpected startup sequence: %v", events)
			}
			status := d.AutomationStatus()
			if !status.FirewallEnabled || status.FirewallManaged || status.FirewallStartupError != d.fwStartupError {
				t.Fatalf("failure was not propagated to status: %+v", status)
			}
		})
	}
}

// An attempt that kept an unreadable state file aside reports it whatever
// later attempts do: they find no file and start empty.
func TestFirewallStartupReportsStateSetAside(t *testing.T) {
	const kept = "/var/lib/csm/firewall/state.json.unreadable-20260301T120000Z"
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	first := new(firewall.Engine)
	attempts := 0
	d.startFirewallUsing(firewallStartupOps{
		newEngine: func(*firewall.FirewallConfig, string) (*firewall.Engine, error) {
			attempts++
			if attempts == 1 {
				return first, nil
			}
			return new(firewall.Engine), nil
		},
		apply: func(*firewall.Engine) error { return errors.New("fixture netlink failure") },
		setAside: func(e *firewall.Engine) string {
			if e == first {
				return kept
			}
			return ""
		},
		delays: []time.Duration{0, 0},
	})
	if attempts != 3 || d.fwStateAside != kept {
		t.Fatalf("attempts=%d set aside=%q; want three attempts and the kept file", attempts, d.fwStateAside)
	}
	if got := d.AutomationStatus().FirewallStateSetAside; got != kept {
		t.Fatalf("status reports %q, want %q", got, kept)
	}
	var found []alert.Finding
	for len(d.alertCh) > 0 {
		if f := <-d.alertCh; f.Check == "firewall_state_unreadable" {
			found = append(found, f)
		}
	}
	if len(found) != 1 || found[0].Severity != alert.Critical || !strings.Contains(found[0].Message, kept) {
		t.Fatalf("findings = %+v; want one critical finding naming the kept file", found)
	}
}

func TestFirewallStartupRetryRecoversOnce(t *testing.T) {
	for _, successAt := range []int{1, 2, 3} {
		calls := 0
		want := new(firewall.Engine)
		got, err := retryFirewallStartup(make(chan struct{}), []time.Duration{0, 0}, func() (*firewall.Engine, error) {
			calls++
			if calls == successAt {
				return want, nil
			}
			return nil, errors.New("temporary startup error")
		})
		if err != nil || got != want || calls != successAt {
			t.Fatalf("recovery at %d returned %p, %v after %d attempts", successAt, got, err, calls)
		}
	}
}

func TestFirewallStartupRetryStopsDuringBackoff(t *testing.T) {
	stop := make(chan struct{})
	attempted := make(chan struct{})
	done := make(chan error, 1)
	calls := 0
	go func() {
		_, err := retryFirewallStartup(stop, []time.Duration{time.Hour}, func() (*firewall.Engine, error) {
			calls++
			close(attempted)
			return nil, errors.New("unavailable")
		})
		done <- err
	}()
	<-attempted
	close(stop)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("shutdown returned %v after %d attempts", err, calls)
		}
	case <-time.After(time.Second):
		t.Fatal("startup retry ignored shutdown")
	}
	_, err := retryFirewallStartup(stop, nil, func() (*firewall.Engine, error) { t.Fatal("attempt ran after shutdown"); return nil, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("closed shutdown returned %v", err)
	}
}

func TestFirewallStartupDisabledDoesNotAttempt(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.startFirewallUsing(firewallStartupOps{newEngine: func(*firewall.FirewallConfig, string) (*firewall.Engine, error) {
		t.Fatal("disabled firewall initialized")
		return nil, nil
	}})
	if d.fwEngine != nil || d.fwStartupError != "" {
		t.Fatal("disabled firewall changed startup state")
	}
}

func TestControlStatusRetainsFirewallStartupError(t *testing.T) {
	listener := newListenerForTest(t)
	listener.d.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	listener.d.fwStartupError = "fixture apply failure"
	result, err := listener.handleStatus(nil)
	if err != nil {
		t.Fatal(err)
	}
	status := result.(control.StatusResult)
	if status.Snapshot == nil {
		t.Fatal("control status omitted snapshot")
	}
	automation := status.Snapshot.Automation
	if !automation.FirewallEnabled || automation.FirewallManaged || automation.FirewallStartupError != listener.d.fwStartupError {
		t.Fatalf("control status lost startup failure: %+v", automation)
	}
}
