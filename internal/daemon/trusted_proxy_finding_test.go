package daemon

import (
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/clientaddr"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
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

// A dismissal acknowledges one episode. Repeated reloads keep it muted, but
// recovery must let the same mistake notify again, including after restart.
func TestTrustedProxyFindingDismissalEndsOnRecovery(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{}, st, nil, "")
	t.Cleanup(func() { _ = d.store.Close() })
	bad := &config.Config{}
	bad.WebServer.TrustedProxies = []string{"not-an-address"}
	useActiveConfig(t, bad)

	notices := 0
	previous := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(previous) })
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == checkTrustedProxyUnusable {
			notices++
		}
	})
	refresh := func() {
		d.refreshTrustedProxyFinding()
		d.dispatchBatch(drainAlertCh(d))
	}
	refresh()
	found := latestTrustedProxyFindings(d.store)
	if notices != 1 || len(found) != 1 {
		t.Fatalf("first episode: %d notices, findings %+v", notices, found)
	}
	for range 3 {
		refresh()
	}
	if notices != 1 {
		t.Fatalf("unchanged config sent %d notices, want 1", notices)
	}
	if undo := d.store.DismissFindingWithUndo(found[0].Key()); undo.DismissalID == "" {
		t.Fatal("finding could not be dismissed")
	}
	refresh()
	if notices != 1 {
		t.Fatalf("dismissed episode sent %d notices, want 1", notices)
	}

	config.SetActive(&config.Config{})
	refresh()
	if found := latestTrustedProxyFindings(d.store); len(found) != 0 {
		t.Fatalf("recovered config retained findings: %+v", found)
	}
	if closeErr := d.store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.store = reopened
	config.SetActive(bad)
	refresh()
	if notices != 2 {
		t.Fatalf("recurring mistake sent %d notices, want 2", notices)
	}
}

// Proxy lists require restart. A disk edit must neither clear a running
// warning nor raise one about settings that have not been applied.
func TestTrustedProxyFindingKeepsRunningListsOnReload(t *testing.T) {
	for _, section := range []string{"web_server", "challenge"} {
		for _, startsBad := range []bool{false, true} {
			name := section + "/introduce"
			if startsBad {
				name = section + "/repair"
			}
			t.Run(name, func(t *testing.T) {
				d := newTestDaemon(t)
				path := filepath.Join(t.TempDir(), "csm.yaml")
				cfg := &config.Config{ConfigDir: t.TempDir()}
				setList := func(cfg *config.Config, bad bool) {
					entries := []string{"198.51.100.10"}
					if bad {
						entries = append(entries, "not-an-address")
					}
					if section == "web_server" {
						cfg.WebServer.TrustedProxies = entries
					} else {
						cfg.Challenge.TrustedProxies = entries
					}
				}
				setList(cfg, startsBad)
				seedConfigAtPath(t, path, cfg)
				loaded, err := config.LoadWithDir(path, cfg.ConfigDir)
				if err != nil {
					t.Fatal(err)
				}
				useActiveConfig(t, loaded)
				d.refreshTrustedProxyFinding()
				before := latestTrustedProxyFindings(d.store)
				drainAlertCh(d)

				edited := *cfg
				setList(&edited, !startsBad)
				seedConfigAtPath(t, path, &edited)
				onDisk, err := config.LoadWithDir(path, cfg.ConfigDir)
				if err != nil {
					t.Fatal(err)
				}
				if changes := config.Diff(loaded, onDisk); len(changes) != 1 || changes[0].Field != section {
					t.Fatalf("test must change only %s, got %+v", section, changes)
				}
				d.reloadConfig()
				alerts := drainAlertCh(d)
				if len(alerts) != 1 || alerts[0].Check != "config_reload_restart_required" {
					t.Fatalf("reload alerts = %+v, want restart required", alerts)
				}
				if !reflect.DeepEqual(d.currentCfg().WebServer.TrustedProxies, loaded.WebServer.TrustedProxies) ||
					!reflect.DeepEqual(d.currentCfg().Challenge.TrustedProxies, loaded.Challenge.TrustedProxies) {
					t.Fatal("restart-required reload changed the running proxy lists")
				}
				if after := latestTrustedProxyFindings(d.store); !reflect.DeepEqual(before, after) {
					t.Fatalf("restart-required reload changed findings: before %+v, after %+v", before, after)
				}
			})
		}
	}
}

// Replacing a dismissed error with a different error must still alert.
func TestTrustedProxyFindingChangedEntriesNotify(t *testing.T) {
	d := newTestDaemon(t)
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"not-an-address"}
	useActiveConfig(t, cfg)
	d.refreshTrustedProxyFinding()
	first := drainAlertCh(d)
	if len(first) != 1 {
		t.Fatalf("first findings = %+v, want one", first)
	}
	d.store.SetBaseline(first)

	changed := *cfg
	changed.WebServer.TrustedProxies = []string{"different-invalid-address"}
	config.SetActive(&changed)
	d.refreshTrustedProxyFinding()
	second := drainAlertCh(d)
	if got := d.store.FilterNew(second); len(got) != 1 || !strings.Contains(got[0].Details, "different-invalid-address") {
		t.Fatalf("changed entries did not produce a new alert: %+v", got)
	}
}

// Catch-all entries can suppress attribution entirely. The guidance must not
// promise that every forwarded request is charged to the proxy instead.
func TestTrustedProxyFindingDescribesAttributionLoss(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"192.0.2.0/0"}
	result, err := clientaddr.Resolve("198.51.100.10", "203.0.113.5", true, config.TrustedProxies(cfg))
	if !errors.Is(err, clientaddr.ErrCatchAllChain) || result.Client.IsValid() {
		t.Fatalf("catch-all attributed a client: %+v, %v", result, err)
	}
	findings := trustedProxyFindings(cfg)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	if !strings.Contains(findings[0].Details, "Requests may count against a proxy or against nobody.") {
		t.Fatalf("guidance does not describe both outcomes: %s", findings[0].Details)
	}
}

func TestTrustedProxyFindingExcludesUsableAndHostLocalEntries(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.10")}, nil
	}))
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.10", "192.0.2.10"}
	cfg.Challenge.TrustedProxies = []string{"2001:db8::/64", "192.0.2.0/24"}
	if config.WebServerLocalTrustError(cfg.WebServer.TrustedProxies) == nil ||
		config.ChallengeLocalTrustError(cfg.Challenge.TrustedProxies) == nil {
		t.Fatal("test must include host-local entries in both lists")
	}
	for _, c := range []*config.Config{nil, {}, cfg} {
		if found := trustedProxyFindings(c); len(found) != 0 {
			t.Fatalf("usable or host-local entries raised a finding: %+v", found)
		}
	}
}

func TestTrustedProxyFindingDeduplicatesSafeReloads(t *testing.T) {
	d := newTestDaemon(t)
	path := filepath.Join(t.TempDir(), "csm.yaml")
	cfg := &config.Config{ConfigDir: t.TempDir()}
	cfg.WebServer.TrustedProxies = []string{"not-an-address"}
	seedConfigAtPath(t, path, cfg)
	loaded, err := config.LoadWithDir(path, cfg.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	useActiveConfig(t, loaded)
	d.refreshTrustedProxyFinding()
	first := drainAlertCh(d)
	if len(first) != 1 {
		t.Fatalf("initial findings = %+v, want one", first)
	}
	d.dispatchBatch(first)
	for range 3 {
		cfg.Thresholds.MailQueueWarn++
		seedConfigAtPath(t, path, cfg)
		d.reloadConfig()
		if d.currentCfg().Thresholds.MailQueueWarn != cfg.Thresholds.MailQueueWarn {
			t.Fatal("unusable proxy entry prevented a safe reload")
		}
		queued := drainAlertCh(d)
		if len(queued) != 1 || queued[0].Key() != first[0].Key() {
			t.Fatalf("safe reload changed finding identity: %+v", queued)
		}
		if fresh := d.store.FilterNew(queued); len(fresh) != 0 {
			t.Fatalf("safe reload bypassed dispatcher dedup: %+v", fresh)
		}
		d.dispatchBatch(queued)
	}
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
