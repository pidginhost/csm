package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

func TestFirewallStartupStateAlertBypassesFullFindingQueue(t *testing.T) {
	const kept = "/var/lib/csm/firewall/state.json.unreadable-20260301T120000Z"
	var delivered atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { delivered.Add(1) }))
	t.Cleanup(webhook.Close)
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = webhook.URL
	cfg.Alerts.MaxPerHour = 1
	cfg.Suppressions.SuppressBlockedAlerts = true
	st, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SaveSuppressions([]state.SuppressionRule{{Check: "firewall_state_unreadable"}}); err != nil {
		t.Fatal(err)
	}
	d := New(cfg, st, nil, "")
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "fixture_backlog"}
	d.startFirewallUsing(firewallStartupOps{
		newEngine: func(*firewall.FirewallConfig, string) (*firewall.Engine, error) { return new(firewall.Engine), nil },
		apply:     func(*firewall.Engine) error { return errors.New("fixture netlink failure") },
		setAside:  func(*firewall.Engine) string { return kept },
		delays:    []time.Duration{0, 0},
	})
	if calls := delivered.Load(); calls != 1 {
		t.Fatalf("startup health alert reached the webhook %d times, want once despite the full queue", calls)
	}
	history, total := st.ReadHistory(10, 0)
	if total != 1 || len(history) != 1 || history[0].Check != "firewall_state_unreadable" || history[0].Severity != alert.Critical {
		t.Fatalf("startup alert missing from history: total=%d findings=%+v", total, history)
	}
	if len(d.alertCh) != 1 || (<-d.alertCh).Check != "fixture_backlog" {
		t.Fatal("startup health delivery consumed the existing backlog")
	}
}

func TestFirewallStateAsideStatusDuringStartup(t *testing.T) {
	const kept = "/var/lib/csm/firewall/state.json.unreadable-20260301T120000Z"
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	start := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		close(start)
		for i := 0; i < 1000; i++ {
			if aside := d.AutomationStatus().FirewallStateSetAside; aside != "" && aside != kept {
				t.Errorf("status read a partial kept path: %q", aside)
			}
		}
	}()
	<-start
	for i := 0; i < 1000; i++ {
		_, err := d.prepareFirewall(cfg.Firewall, firewallStartupOps{
			newEngine: func(*firewall.FirewallConfig, string) (*firewall.Engine, error) { return new(firewall.Engine), nil },
			apply:     func(*firewall.Engine) error { return errors.New("fixture netlink failure") },
			setAside:  func(*firewall.Engine) string { return kept },
		})
		if err == nil {
			t.Fatal("fixture startup failure was lost")
		}
	}
	readers.Wait()
	if aside := d.AutomationStatus().FirewallStateSetAside; aside != kept {
		t.Fatalf("startup lost kept path: %q", aside)
	}
}

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
	var found []alert.Finding
	previousHook := alert.CentralHook
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == "firewall_state_unreadable" {
			found = append(found, f)
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
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
