package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func latestTrustedProxyFindings(st *state.Store) []alert.Finding {
	var out []alert.Finding
	for _, f := range st.LatestFindings() {
		if f.Check == "trusted_proxy_unusable" {
			out = append(out, f)
		}
	}
	return out
}

// An unusable trusted_proxies entry leaves that proxy untrusted, so its own
// address reads as the client and can be blocked. The running config's
// skipped entries are a High finding until a config without them runs.
func TestTrustedProxyFindingFollowsTheRunningConfig(t *testing.T) {
	d := newTestDaemon(t)
	bad := &config.Config{}
	bad.WebServer.TrustedProxies = []string{"198.51.100.10", "not-an-address"}
	bad.Challenge.TrustedProxies = []string{"0.0.0.0/0"}
	useActiveConfig(t, bad)

	d.refreshTrustedProxyFinding()

	found := latestTrustedProxyFindings(d.store)
	if len(found) != 1 {
		t.Fatalf("latest trusted_proxy_unusable findings = %+v, want one", found)
	}
	f := found[0]
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	text := f.Message + "\n" + f.Details
	for _, want := range []string{"web_server.trusted_proxies", "not-an-address", "challenge.trusted_proxies", "0.0.0.0/0"} {
		if !strings.Contains(text, want) {
			t.Errorf("finding does not name %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "198.51.100.10") {
		t.Errorf("finding names the usable entry:\n%s", text)
	}
	select {
	case got := <-d.alertCh:
		if got.Check != "trusted_proxy_unusable" {
			t.Errorf("alert = %s, want trusted_proxy_unusable", got.Check)
		}
	default:
		t.Error("finding was not sent for alerting")
	}

	fixed := &config.Config{}
	fixed.WebServer.TrustedProxies = []string{"198.51.100.10"}
	config.SetActive(fixed)
	d.reconcileHotReloadables()

	if found := latestTrustedProxyFindings(d.store); len(found) != 0 {
		t.Fatalf("finding kept after the config was fixed: %+v", found)
	}
}
