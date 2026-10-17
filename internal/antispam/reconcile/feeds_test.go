package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/eximlock"
)

func feedDesired(feeds ...string) Desired {
	d := desired(true)
	d.Settings.Feeds = feeds
	return d
}

// goodFeedFacts: every optional file writable, loopback resolver.
func goodFeedFacts() antispam.HostFacts {
	var targets []antispam.TargetFacts
	for _, tgt := range antispam.MutationTargets() {
		targets = append(targets, antispam.TargetFacts{Target: tgt, Missing: true,
			Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}})
	}
	return antispam.HostFacts{Targets: targets, RspamdOptions: antispam.CommandResult{Stdout: `{"dns":{}}`},
		RspamdVersion: antispam.CommandResult{Stdout: "Rspamd daemon version 4.2.2\n"},
		RspamdLog: antispam.LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log",
			File:    antispam.PathFacts{GID: 974, Mode: 0o640},
			Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}},
		ResolvConf: "nameserver 127.0.0.1\n", RspamdGID: 974}
}

func TestPassSendsResolvedFeeds(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	r.Feeds = NewFeedState()
	r.Collect = func(context.Context, string) antispam.HostFacts {
		f := goodFeedFacts()
		f.ResolvConf = "nameserver 198.51.100.53\n"
		return f
	}
	r.assess = func(bool, antispam.Settings, antispam.HostFacts) antispam.Assessment {
		return antispam.Assessment{Action: antispam.Install}
	}
	out := r.Pass(context.Background(), feedDesired(antispam.FeedPSBL, antispam.FeedRspamdMaps))
	if len(h.requests) != 1 || h.requests[0].Feeds == nil || *h.requests[0].Feeds != antispam.FeedRspamdMaps {
		t.Fatalf("requests %+v", h.requests)
	}
	var feed []string
	for _, f := range out.Findings {
		if f.Check == CheckFeed {
			feed = append(feed, f.DedupKey)
		}
	}
	if len(feed) != 1 || feed[0] != antispam.FeedPSBL {
		t.Fatalf("feed findings %v in %+v", feed, out.Findings)
	}
	if !containsCheck(out.Checks, CheckFeed) {
		t.Fatalf("checks %v must settle %s", out.Checks, CheckFeed)
	}
}

func TestPassBlocksFeedsAfterFeedsCheck(t *testing.T) {
	h := &fakeHost{result: antispam.Result{Operation: antispam.OpApply, FailedStep: antispam.FeedsCheckStep, Rollback: antispam.RollbackVerified, Error: "x"}}
	r := h.reconciler()
	r.Feeds = NewFeedState()
	r.Collect = func(context.Context, string) antispam.HostFacts { return goodFeedFacts() }
	r.assess = func(bool, antispam.Settings, antispam.HostFacts) antispam.Assessment {
		return antispam.Assessment{Action: antispam.Install}
	}
	d := feedDesired(antispam.FeedPSBL)
	r.Pass(context.Background(), d)
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true, Generation: strings.Repeat("a", 64)}
	out := r.Pass(context.Background(), d)
	if last := h.requests[len(h.requests)-1]; last.Feeds != nil {
		t.Fatalf("feeds sent again after a failed feeds check: %+v", last)
	}
	if !hasFindingKey(out.Findings, CheckFeed, antispam.FeedPSBL) {
		t.Fatalf("no feed finding while held: %+v", out.Findings)
	}
	r.Pass(context.Background(), feedDesired(antispam.FeedPSBL, antispam.FeedSEM))
	if last := h.requests[len(h.requests)-1]; last.Feeds == nil {
		t.Fatal("a feed config change must lift the hold")
	}
}

func TestPassReadsTheKeyOnlyForDQS(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	reads := 0
	r.ReadKey = func(string) antispam.KeyFacts { reads++; return antispam.KeyFacts{} }
	r.Collect = func(context.Context, string) antispam.HostFacts { return goodFeedFacts() }
	r.Pass(context.Background(), feedDesired(antispam.FeedPSBL))
	d := feedDesired(antispam.FeedSpamhausDQS)
	d.Settings.DQSKeyFile = "/etc/csm/k"
	r.Pass(context.Background(), d)
	if reads != 1 {
		t.Fatalf("key read %d times", reads)
	}
}

func containsCheck(checks []string, c string) bool {
	for _, x := range checks {
		if x == c {
			return true
		}
	}
	return false
}

func hasFindingKey(findings []alert.Finding, check, key string) bool {
	for _, f := range findings {
		if f.Check == check && f.DedupKey == key {
			return true
		}
	}
	return false
}

// Findings with one check and dedup key collapse into one alert, so feed
// problems sharing a key must arrive as one finding naming every cause.
func TestPassMergesFeedProblemsSharingAKey(t *testing.T) {
	h := &fakeHost{}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts {
		f := goodFeedFacts()
		for i := range f.Targets {
			switch f.Targets[i].Path {
			case antispam.RedirectPath(antispam.RedirectWhitelist), antispam.RedirectPath(antispam.RedirectMID):
				f.Targets[i].Missing = false
				f.Targets[i].File = antispam.PathFacts{Path: f.Targets[i].Path, Mode: 0o644}
				f.Targets[i].Content = "operator\n"
			}
		}
		return f
	}
	r.assess = func(bool, antispam.Settings, antispam.HostFacts) antispam.Assessment {
		return antispam.Assessment{Problems: []antispam.Problem{
			{Code: antispam.CodeFeed, Severity: antispam.Warning, Key: "rbl", Detail: "first difference"},
			{Code: antispam.CodeFeed, Severity: antispam.Warning, Key: "rbl", Detail: "second difference"},
		}}
	}
	out := r.Pass(context.Background(), feedDesired())
	byKey := map[string][]alert.Finding{}
	for _, f := range out.Findings {
		if f.Check == CheckFeed {
			byKey[f.DedupKey] = append(byKey[f.DedupKey], f)
		}
	}
	if len(byKey) != 2 || len(byKey[antispam.FeedRspamdMaps]) != 1 || len(byKey["rbl"]) != 1 {
		t.Fatalf("feed findings %+v", out.Findings)
	}
	maps := byKey[antispam.FeedRspamdMaps][0].Details
	if !strings.Contains(maps, antispam.RedirectPath(antispam.RedirectWhitelist)) || !strings.Contains(maps, antispam.RedirectPath(antispam.RedirectMID)) {
		t.Errorf("rspamd_maps finding must name both files: %s", maps)
	}
	if rbl := byKey["rbl"][0].Details; !strings.Contains(rbl, "first difference") || !strings.Contains(rbl, "second difference") {
		t.Errorf("rbl finding must carry both differences: %s", rbl)
	}
}

func TestPassReportsLeftoverRspamdComMaps(t *testing.T) {
	leftover := func(d Desired, action antispam.Action) []alert.Finding {
		h := &fakeHost{}
		r := h.reconciler()
		r.Collect = func(context.Context, string) antispam.HostFacts {
			f := goodFeedFacts()
			f.RspamdModules = antispam.CommandResult{Stdout: "Modules enabled: multimap, dkim\nModules disabled (explicitly): fuzzy_check\n"}
			f.RspamdConfig = antispam.CommandResult{Stdout: `{"multimap":{"custom":{"map":"https://maps.rspamd.com/custom.txt"}},` +
				`"fuzzy_check":{"rule":{"rspamd.com":{"servers":"service=fuzzy+rspamd.com"}}}}`}
			return f
		}
		r.assess = func(bool, antispam.Settings, antispam.HostFacts) antispam.Assessment {
			return antispam.Assessment{Action: action, Installed: true,
				Problems: []antispam.Problem{{Code: antispam.CodeGlobalEnable, Severity: antispam.Warning, Detail: "w"}}}
		}
		var out []alert.Finding
		for _, f := range r.Pass(context.Background(), d).Findings {
			if f.Check == CheckFeed {
				out = append(out, f)
			}
		}
		return out
	}
	got := leftover(feedDesired(), antispam.Keep)
	if len(got) != 1 || got[0].DedupKey != antispam.FeedRspamdMaps || !strings.Contains(got[0].Details, "multimap.custom.map") ||
		strings.Contains(got[0].Details, "fuzzy_check") {
		t.Fatalf("leftover findings %+v", got)
	}
	if got := leftover(feedDesired(antispam.FeedRspamdMaps), antispam.Keep); len(got) != 0 {
		t.Fatalf("rspamd_maps accepts rspamd.com maps: %+v", got)
	}
	if got := leftover(feedDesired(), antispam.Install); len(got) != 0 {
		t.Fatalf("a pass that installs has not loaded CSM's files yet: %+v", got)
	}
	observe := feedDesired()
	observe.Observe = true
	if got := leftover(observe, antispam.Keep); len(got) != 0 {
		t.Fatalf("observe mode reports no leftovers: %+v", got)
	}
}

func probeReconciler(h *fakeHost, answer func(name string) antispam.ProbeAnswer) Reconciler {
	r := h.reconciler()
	r.Feeds = NewFeedState()
	r.Collect = func(context.Context, string) antispam.HostFacts { return goodFeedFacts() }
	r.assess = func(bool, antispam.Settings, antispam.HostFacts) antispam.Assessment {
		return antispam.Assessment{Action: antispam.Keep, Installed: true}
	}
	r.Probe = func(_ context.Context, _ netip.AddrPort, name string) antispam.ProbeAnswer { return answer(name) }
	return r
}

func TestPassReportsNoAnswerOnThirdPass(t *testing.T) {
	r := probeReconciler(&fakeHost{}, func(string) antispam.ProbeAnswer { return antispam.ProbeAnswer{Failed: true} })
	d := feedDesired(antispam.FeedPSBL)
	for pass := 1; pass <= 3; pass++ {
		out := r.Pass(context.Background(), d)
		if got := hasFindingKey(out.Findings, CheckFeed, "psbl:no_answer"); got != (pass == 3) {
			t.Fatalf("pass %d: finding %v", pass, got)
		}
	}
}

func TestPassReportsListsAllAsCritical(t *testing.T) {
	r := probeReconciler(&fakeHost{}, func(name string) antispam.ProbeAnswer {
		return antispam.ProbeAnswer{Addrs: []string{"127.0.0.2"}}
	})
	out := r.Pass(context.Background(), feedDesired(antispam.FeedPSBL))
	for _, f := range out.Findings {
		if f.DedupKey == "psbl:lists_all" && f.Severity == alert.Critical {
			return
		}
	}
	t.Fatalf("no critical finding: %+v", out.Findings)
}

func TestDQSListsAllWarningRequiresOperatorAction(t *testing.T) {
	feed, _ := antispam.FeedByName(antispam.FeedSpamhausDQS)
	finding, ok := NewFeedState().probeFinding(feed, antispam.ProbeQuery{Zone: feed.Zones[0]},
		antispam.ProbeListsAll, "", antispam.ProbeAnswer{}, testNow)
	if !ok || finding.Severity != alert.Critical || strings.Contains(finding.Details, "rspamd stops") ||
		!strings.Contains(finding.Details, "turn the feed off") {
		t.Fatalf("DQS warning promised automatic protection: %+v", finding)
	}
}

func TestPassReportsMixedRefusalAndListingAsCritical(t *testing.T) {
	r := probeReconciler(&fakeHost{}, func(name string) antispam.ProbeAnswer {
		if strings.HasPrefix(name, "test.uribl.com.") {
			return antispam.ProbeAnswer{Addrs: []string{"127.0.0.14"}}
		}
		return antispam.ProbeAnswer{Addrs: []string{"127.0.0.1", "127.0.0.2"}}
	})
	out := r.Pass(context.Background(), feedDesired(antispam.FeedURIBL))
	if len(out.Findings) != 1 || out.Findings[0].DedupKey != "uribl:lists_all" || out.Findings[0].Severity != alert.Critical {
		t.Fatalf("mixed reply must report one critical lists-all finding: %+v", out.Findings)
	}
}

func TestProbeFindingsNeverCarryTheKey(t *testing.T) {
	key := strings.ToLower(rand.Text())[:26]
	for _, echo := range []func(name string) []string{
		func(name string) []string { return []string{"127.255.255.254", name} },
		func(name string) []string { return []string{name} },
	} {
		h := &fakeHost{}
		r := probeReconciler(h, func(name string) antispam.ProbeAnswer {
			return antispam.ProbeAnswer{Addrs: echo(name)}
		})
		r.ReadKey = func(string) antispam.KeyFacts {
			return antispam.KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: antispam.NewSecret(key)}
		}
		d := feedDesired(antispam.FeedSpamhausDQS)
		d.Settings.DQSKeyFile = "/etc/csm/k"
		out := r.Pass(context.Background(), d)
		if len(out.Findings) == 0 {
			t.Fatal("no findings")
		}
		for _, f := range out.Findings {
			if strings.Contains(f.Message+f.Details+f.DedupKey, key) {
				t.Fatal("finding carries the key")
			}
		}
	}
}

func TestPassResetsFeedProbesAfterKeyRotation(t *testing.T) {
	r := probeReconciler(&fakeHost{}, func(string) antispam.ProbeAnswer {
		return antispam.ProbeAnswer{Failed: true}
	})
	key := strings.ToLower(rand.Text())[:26]
	r.ReadKey = func(string) antispam.KeyFacts {
		return antispam.KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: antispam.NewSecret(key)}
	}
	d := feedDesired(antispam.FeedSpamhausDQS)
	d.Settings.DQSKeyFile = "/etc/csm/k"
	r.Pass(context.Background(), d)
	r.Pass(context.Background(), d)
	key = strings.ToLower(rand.Text())[:26]
	for pass := 1; pass <= 3; pass++ {
		out := r.Pass(context.Background(), d)
		if got := hasFindingKey(out.Findings, CheckFeed, "spamhaus_dqs:no_answer"); got != (pass == 3) {
			t.Fatalf("pass %d after key rotation: finding %v", pass, got)
		}
	}
}

func TestPassCanceledFeedProbesSettleNothing(t *testing.T) {
	r := probeReconciler(&fakeHost{}, func(string) antispam.ProbeAnswer {
		return antispam.ProbeAnswer{Failed: true}
	})
	d := feedDesired(antispam.FeedPSBL)
	r.Pass(context.Background(), d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := r.Probe
	r.Probe = func(ctx context.Context, server netip.AddrPort, name string) antispam.ProbeAnswer {
		cancel()
		return probe(ctx, server, name)
	}
	out := r.Pass(ctx, d)
	if !errors.Is(out.Err, context.Canceled) || len(out.Checks) != 0 || len(out.Findings) != 0 {
		t.Errorf("canceled probes settled checks or reported findings: %+v", out)
	}
	r.Probe = probe
	if out := r.Pass(context.Background(), d); hasFindingKey(out.Findings, CheckFeed, "psbl:no_answer") {
		t.Fatal("canceled probes counted toward the no-answer warning")
	}
	if out := r.Pass(context.Background(), d); !hasFindingKey(out.Findings, CheckFeed, "psbl:no_answer") {
		t.Fatal("completed probes did not retain their no-answer count")
	}
}

func TestPassResetsFeedProbesAfterInterruption(t *testing.T) {
	for _, interruption := range []string{"disabled", "disabled while busy", "observe", "feed removed", "feed unusable", "install", "blocked", "resolver changed"} {
		t.Run(interruption, func(t *testing.T) {
			r := probeReconciler(&fakeHost{}, func(string) antispam.ProbeAnswer {
				return antispam.ProbeAnswer{Failed: true}
			})
			d := feedDesired(antispam.FeedPSBL)
			r.Pass(context.Background(), d)
			r.Pass(context.Background(), d)
			interrupted := d
			collect, assess := r.Collect, r.assess
			invalidate := r.Invalidate
			switch interruption {
			case "disabled":
				interrupted.Enabled = false
			case "disabled while busy":
				interrupted.Enabled = false
				r.Invalidate = func(context.Context) error { return eximlock.ErrBusy }
			case "observe":
				interrupted.Observe = true
			case "feed removed":
				interrupted.Settings.Feeds = nil
			case "feed unusable":
				r.Collect = func(context.Context, string) antispam.HostFacts {
					f := goodFeedFacts()
					f.ResolvConf = "nameserver 192.0.2.53\n"
					return f
				}
			case "install", "blocked":
				r.assess = func(bool, antispam.Settings, antispam.HostFacts) antispam.Assessment {
					if interruption == "install" {
						return antispam.Assessment{Action: antispam.Install, Installed: true}
					}
					return antispam.Assessment{Installed: true, Problems: []antispam.Problem{{Severity: antispam.Temporary}}}
				}
			case "resolver changed":
				r.Collect = func(context.Context, string) antispam.HostFacts {
					f := goodFeedFacts()
					f.RspamdOptions.Stdout = `{"dns":{"nameserver":"[::1]:5353"}}`
					return f
				}
			}
			if out := r.Pass(context.Background(), interrupted); hasFindingKey(out.Findings, CheckFeed, "psbl:no_answer") {
				t.Fatal("interrupted or changed probes retained the old failure count")
			}
			r.Collect, r.assess = collect, assess
			r.Invalidate = invalidate
			for pass := 1; pass <= 3; pass++ {
				out := r.Pass(context.Background(), d)
				if got := hasFindingKey(out.Findings, CheckFeed, "psbl:no_answer"); got != (pass == 3) {
					t.Fatalf("resumed pass %d: finding %v", pass, got)
				}
			}
		})
	}
}

func TestPassProbesConfiguredResolverEndpoint(t *testing.T) {
	r := probeReconciler(&fakeHost{}, nil)
	r.Collect = func(context.Context, string) antispam.HostFacts {
		f := goodFeedFacts()
		f.RspamdOptions.Stdout = `{"dns":{"nameserver":"[::1]:5353:10"}}`
		return f
	}
	var calls atomic.Int32
	r.Probe = func(_ context.Context, server netip.AddrPort, _ string) antispam.ProbeAnswer {
		calls.Add(1)
		if server.String() != "[::1]:5353" {
			t.Errorf("probe endpoint = %s, want [::1]:5353", server)
		}
		return antispam.ProbeAnswer{NXDomain: true}
	}
	r.Pass(context.Background(), feedDesired(antispam.FeedPSBL))
	if calls.Load() != 2 {
		t.Fatalf("got %d queries, want 2", calls.Load())
	}
}

// Both queries of a zone can fail the same way; one finding per key.
func TestProbeFindingsOncePerKey(t *testing.T) {
	r := probeReconciler(&fakeHost{}, func(string) antispam.ProbeAnswer {
		return antispam.ProbeAnswer{Addrs: []string{"127.0.0.255"}}
	})
	out := r.Pass(context.Background(), feedDesired(antispam.FeedDNSWL))
	n := 0
	for _, f := range out.Findings {
		if f.DedupKey == "dnswl:refused" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d dnswl:refused findings in %+v", n, out.Findings)
	}
}

func TestPassPreservesConfiguredFeedsAcrossResolverRecovery(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Install},
		result: antispam.Result{Operation: antispam.OpApply, OK: true, Generation: strings.Repeat("a", 64)}}
	r := h.reconciler()
	f := goodFeedFacts()
	f.ResolvConf = "nameserver 198.51.100.53\n"
	r.Collect = func(context.Context, string) antispam.HostFacts { return f }
	d := feedDesired(antispam.FeedPSBL, antispam.FeedRspamdMaps)
	want := slices.Clone(d.Settings.Feeds)
	for range 2 {
		out := r.Pass(context.Background(), d)
		if !slices.Equal(d.Settings.Feeds, want) {
			t.Errorf("configured feeds changed: %v", d.Settings.Feeds)
		}
		if !hasFindingKey(out.Findings, CheckFeed, antispam.FeedPSBL) {
			t.Error("unavailable configured feed lost its warning")
		}
	}
	f.ResolvConf = "nameserver 127.0.0.1\n"
	out := r.Pass(context.Background(), d)
	if len(h.requests) != 3 {
		t.Fatalf("worker requests = %d, want 3", len(h.requests))
	}
	last := h.requests[2]
	if last.Feeds == nil || *last.Feeds != strings.Join(want, ",") {
		t.Error("resolver recovery did not restore the configured feeds")
	}
	if hasFindingKey(out.Findings, CheckFeed, antispam.FeedPSBL) {
		t.Error("recovered feed still has a warning")
	}
}

func TestPassHoldsOriginalConfigurationAfterDroppingOneFeed(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result: antispam.Result{Operation: antispam.OpApply, FailedStep: antispam.FeedsCheckStep,
			Rollback: antispam.RollbackVerified, Error: "loaded rules differ"},
	}
	r := h.reconciler()
	r.Feeds = NewFeedState()
	key := antispam.KeyFacts{Path: "/etc/csm/k", Missing: true}
	r.ReadKey = func(string) antispam.KeyFacts { return key }
	desiredFeeds := func() Desired {
		d := feedDesired(antispam.FeedPSBL, antispam.FeedSpamhausDQS)
		d.Settings.DQSKeyFile = "/etc/csm/k"
		return d
	}
	r.Pass(context.Background(), desiredFeeds())
	if len(h.requests) != 1 || h.requests[0].Feeds == nil || *h.requests[0].Feeds != antispam.FeedPSBL {
		t.Fatal("first apply must try only the usable feed")
	}
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true, Generation: strings.Repeat("a", 64)}
	key = antispam.KeyFacts{Path: "/etc/csm/k", Mode: 0o600,
		Key: antispam.NewSecret(strings.ToLower(rand.Text()[:26]))}
	// The daemon takes a fresh configuration snapshot for every pass.
	out := r.Pass(context.Background(), desiredFeeds())
	if len(h.requests) != 2 || h.requests[1].Feeds != nil {
		t.Fatal("unchanged configuration retried DNS feeds after a failed feeds check")
	}
	if !hasFindingKey(out.Findings, CheckFeed, antispam.FeedPSBL) ||
		!hasFindingKey(out.Findings, CheckFeed, antispam.FeedSpamhausDQS) {
		t.Fatal("both configured feeds must retain their hold warnings")
	}
}

// The daemon reads the DQS key file each pass; without a reader the feed
// can never pass its preconditions.
func TestPassSendsDQSOnlyWithAKeyReader(t *testing.T) {
	const key = "abcdefghijklmnopqrstu23456"
	send := func(read func(string) antispam.KeyFacts) *string {
		h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Install},
			result: antispam.Result{Operation: antispam.OpApply, OK: true, Generation: strings.Repeat("a", 64)}}
		r := h.reconciler()
		r.ReadKey = read
		d := feedDesired(antispam.FeedSpamhausDQS)
		d.Settings.DQSKeyFile = "/etc/csm/k"
		r.Pass(context.Background(), d)
		if len(h.requests) != 1 {
			t.Fatalf("requests %+v", h.requests)
		}
		return h.requests[0].Feeds
	}
	if feeds := send(func(string) antispam.KeyFacts {
		return antispam.KeyFacts{Path: "/etc/csm/k", Mode: 0o600, Key: antispam.NewSecret(key)}
	}); feeds == nil || *feeds != antispam.FeedSpamhausDQS {
		t.Fatalf("readable key: feeds %v", feeds)
	}
	if feeds := send(nil); feeds != nil {
		t.Fatalf("no key reader: feeds %q", *feeds)
	}
}

func TestPassProbesThroughTheResolverPort(t *testing.T) {
	r := probeReconciler(&fakeHost{}, nil)
	r.Collect = func(context.Context, string) antispam.HostFacts {
		f := goodFeedFacts()
		f.RspamdOptions = antispam.CommandResult{Stdout: `{"dns":{"nameserver":"127.0.0.1:5353"}}`}
		return f
	}
	var mu sync.Mutex
	var servers []string
	r.Probe = func(_ context.Context, server netip.AddrPort, _ string) antispam.ProbeAnswer {
		mu.Lock()
		defer mu.Unlock()
		servers = append(servers, server.String())
		return antispam.ProbeAnswer{NXDomain: true}
	}
	r.Pass(context.Background(), feedDesired(antispam.FeedPSBL))
	if len(servers) != 2 || servers[0] != "127.0.0.1:5353" || servers[1] != "127.0.0.1:5353" {
		t.Fatalf("probed %v", servers)
	}
}

func TestPassLeftoverMapsRequireCurrentReadableState(t *testing.T) {
	for _, name := range []string{"disabled", "not installed", "definite problem", "temporary problem", "config failed", "modules failed", "invalid config", "invalid modules"} {
		t.Run(name, func(t *testing.T) {
			h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep, Installed: true}}
			r := h.reconciler()
			d := feedDesired()
			f := goodFeedFacts()
			f.RspamdModules.Stdout = "Modules enabled: multimap\n"
			f.RspamdConfig.Stdout = `{"multimap":{"custom":{"map":"https://maps.rspamd.com/custom.txt"}}}`
			switch name {
			case "disabled":
				d.Enabled = false
			case "not installed":
				h.assessment.Installed = false
			case "definite problem":
				h.assessment.Problems = []antispam.Problem{{Code: antispam.CodeRspamdConfig, Severity: antispam.Definite}}
			case "temporary problem":
				h.assessment.Problems = []antispam.Problem{{Code: antispam.CodeRspamdConfig, Severity: antispam.Temporary}}
			case "config failed":
				f.RspamdConfig.Err = errors.New("command failed")
			case "modules failed":
				f.RspamdModules.Err = errors.New("command failed")
			case "invalid config":
				f.RspamdConfig.Stdout = `{"multimap":`
			case "invalid modules":
				f.RspamdModules.Stdout = "no module inventory"
			}
			r.Collect = func(context.Context, string) antispam.HostFacts { return f }
			r.Installed = func() antispam.HostFacts { return f }
			out := r.Pass(context.Background(), d)
			if hasFindingKey(out.Findings, CheckFeed, antispam.FeedRspamdMaps) || len(h.requests) != 0 || out.Err != nil {
				t.Fatal("unsettled or unreadable state reported leftover maps or changed core")
			}
		})
	}
}

func TestPassLeftoverMapDetailsAreBoundedAndRedacted(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep, Installed: true}}
	r := h.reconciler()
	key := strings.Repeat("a", 26)
	maps := map[string]any{key: map[string]string{"map": "https://maps.rspamd.com/" + key}}
	for i := range 11 {
		maps[fmt.Sprintf("custom%02d", i)] = map[string]string{"map": "https://maps.rspamd.com/custom.txt"}
	}
	dump, err := json.Marshal(map[string]any{"multimap": maps})
	if err != nil {
		t.Fatal("cannot encode test configuration")
	}
	f := goodFeedFacts()
	f.RspamdModules.Stdout = "Modules enabled: multimap\n"
	f.RspamdConfig.Stdout = string(dump)
	r.Collect = func(context.Context, string) antispam.HostFacts { return f }
	out := r.Pass(context.Background(), feedDesired())
	if out.Err != nil || len(h.requests) != 0 || len(out.Findings) != 1 {
		t.Fatal("leftover maps must produce one warning without changing core")
	}
	finding := out.Findings[0]
	if finding.Check != CheckFeed || finding.DedupKey != antispam.FeedRspamdMaps || finding.Severity != alert.Warning ||
		strings.Contains(finding.Details+finding.Message+finding.DedupKey, key) ||
		!strings.Contains(finding.Details, "multimap.[redacted].map") ||
		strings.Count(finding.Details, "multimap.") != 10 || !strings.Contains(finding.Details, "and 2 more") {
		t.Fatal("leftover warning lost its identity, exposed configuration, or did not bound its paths")
	}
	f.RspamdConfig.Stdout = `{"multimap":{"custom":{"map":"/etc/rspamd/maps.d/local.inc"}}}`
	out = r.Pass(context.Background(), feedDesired())
	if len(out.Findings) != 0 || !containsCheck(out.Checks, CheckFeed) || len(h.requests) != 0 {
		t.Fatal("redirecting the last remote map did not clear its warning without changing core")
	}
}

// The resolver advice must survive the finding text as a line an operator
// can paste into options.inc.
func TestResolverAdviceIsPasteable(t *testing.T) {
	f := goodFeedFacts()
	f.ResolvConf = "nameserver 198.51.100.53\n"
	_, problems := antispam.ResolveFeeds(feedDesired(antispam.FeedPSBL).Settings, f)
	if len(problems) != 1 {
		t.Fatalf("problems %+v", problems)
	}
	if got := feedFinding(problems[0], testNow).Details; !strings.Contains(got, "dns { nameserver = ['127.0.0.1']; }") {
		t.Fatalf("details %q", got)
	}
}

// A hold also follows a failed or unreadable check, so its text must not
// claim the rules differed.
func TestHeldFeedsDescribeTheFailedCheck(t *testing.T) {
	st := NewFeedState()
	configured := feedDesired(antispam.FeedPSBL).Settings
	st.hold(configured)
	_, problems := st.apply(configured, configured, nil)
	if len(problems) != 1 || !strings.Contains(problems[0].Detail, "could not confirm the blocklist rules rspamd loaded") {
		t.Fatalf("problems %+v", problems)
	}
}

// A wrong DQS key makes Spamhaus answer nothing, so the advice names the key.
func TestNoAnswerMentionsTheKeyForDQS(t *testing.T) {
	st := NewFeedState()
	dqs, _ := antispam.FeedByName(antispam.FeedSpamhausDQS)
	q := antispam.ProbeQuery{Feed: dqs.Name, Zone: dqs.Zones[0], Listed: true}
	var f alert.Finding
	for range 3 {
		f, _ = st.probeFinding(dqs, q, antispam.ProbeNoAnswer, "", antispam.ProbeAnswer{NXDomain: true}, testNow)
	}
	if !strings.Contains(f.Details, "DQS key") {
		t.Fatalf("details %q", f.Details)
	}
}

func TestUnexpectedEmptyAnswerSaysSo(t *testing.T) {
	psbl, _ := antispam.FeedByName(antispam.FeedPSBL)
	q := antispam.ProbeQuery{Feed: psbl.Name, Zone: psbl.Zones[0]}
	f, ok := NewFeedState().probeFinding(psbl, q, antispam.ProbeUnexpected, "", antispam.ProbeAnswer{}, testNow)
	if !ok || strings.Contains(f.Details, "Answer: .") || !strings.Contains(f.Details, "no address") {
		t.Fatalf("details %q", f.Details)
	}
}
