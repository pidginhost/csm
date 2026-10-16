package reconcile

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
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
