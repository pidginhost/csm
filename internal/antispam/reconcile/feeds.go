package reconcile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

// FeedState is what feed handling remembers between passes. Passes run one
// at a time; the mutex guards readers in tests and future callers.
type FeedState struct {
	mu sync.Mutex
	// held is the feed configuration whose apply failed the feeds check;
	// DNS feeds stay off while the configuration is unchanged.
	held string
	// scope fingerprints the resolver and queries without retaining a key.
	scope [32]byte
	// noAnswer counts consecutive completed probes, per zone and query kind.
	noAnswer map[string]int
}

// NewFeedState returns empty feed memory.
func NewFeedState() *FeedState { return &FeedState{noAnswer: map[string]int{}} }

func feedConfig(s antispam.Settings) string {
	return strings.Join(s.Feeds, ",") + "|" + s.DQSKeyFile
}

func (st *FeedState) hold(configured antispam.Settings) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.held = feedConfig(configured)
}

// apply drops DNS feeds from resolved while the configured feeds are held,
// with one Warning per feed. A changed configuration lifts the hold.
func (st *FeedState) apply(configured, resolved antispam.Settings, problems []antispam.Problem) (antispam.Settings, []antispam.Problem) {
	if st == nil {
		return resolved, problems
	}
	st.mu.Lock()
	held := st.held != "" && st.held == feedConfig(configured)
	if !held {
		st.held = ""
	}
	st.mu.Unlock()
	if !held {
		return resolved, problems
	}
	var keep []string
	for _, name := range resolved.Feeds {
		if f, _ := antispam.FeedByName(name); f.DNS() {
			problems = append(problems, antispam.Problem{Code: antispam.CodeFeed, Severity: antispam.Warning, Key: name,
				Detail: "feed " + name + " is off: at the last apply CSM could not confirm the blocklist rules rspamd loaded, or they differed from CSM's; CSM keeps DNS feeds off until the feed configuration changes or CSM restarts"})
			continue
		}
		keep = append(keep, name)
	}
	resolved.Feeds = keep
	if !resolved.HasFeed(antispam.FeedSpamhausDQS) {
		resolved.DQSKey = antispam.Secret{}
	}
	return resolved, problems
}

// mergeByKey joins feed problems that share a key, in first-seen order.
// Findings with one check and dedup key collapse into one alert, so each
// key must carry every cause in its details.
func mergeByKey(problems []antispam.Problem) []antispam.Problem {
	var out []antispam.Problem
	index := make(map[string]int)
	for _, p := range problems {
		if i, ok := index[p.Key]; ok {
			out[i].Detail += "; " + p.Detail
			continue
		}
		index[p.Key] = len(out)
		out = append(out, p)
	}
	return out
}

// blockingProblems reports a Definite or Temporary problem: the host is
// not known to be current.
func blockingProblems(problems []antispam.Problem) bool {
	return slices.ContainsFunc(problems, func(p antispam.Problem) bool { return p.Severity != antispam.Warning })
}

// leftoverMaps reports rspamd.com paths still loaded in enabled modules.
// Unreadable dumps say nothing: the next pass retries.
func leftoverMaps(f antispam.HostFacts) (antispam.Problem, bool) {
	if f.RspamdConfig.Err != nil || f.RspamdModules.Err != nil {
		return antispam.Problem{}, false
	}
	enabled, err := antispam.EnabledModules(f.RspamdModules.Stdout)
	if err != nil {
		return antispam.Problem{}, false
	}
	paths, err := antispam.RspamdComPaths([]byte(f.RspamdConfig.Stdout), enabled)
	if err != nil || len(paths) == 0 {
		return antispam.Problem{}, false
	}
	shown := paths[:min(len(paths), 10)]
	detail := "rspamd configuration still references rspamd.com at " + strings.Join(shown, ", ")
	if len(paths) > len(shown) {
		detail += fmt.Sprintf(" and %d more", len(paths)-len(shown))
	}
	detail += "; CSM points only the maps it knows at local copies. Enable the rspamd_maps feed to accept rspamd.com's terms, or redirect these maps yourself"
	return antispam.Problem{Code: antispam.CodeFeed, Severity: antispam.Warning, Key: antispam.FeedRspamdMaps, Detail: detail}, true
}

// probeFeeds asks every probed zone's test points through rspamd's first
// nameserver, concurrently, and reports what is wrong. No-answer counts
// carry across passes; three in a row raise a finding.
func (r Reconciler) probeFeeds(ctx context.Context, s antispam.Settings, f antispam.HostFacts, now time.Time) []alert.Finding {
	queries := antispam.ProbeQueries(s)
	if r.Probe == nil || len(queries) == 0 {
		r.Feeds.setProbeScope([32]byte{})
		return nil
	}
	servers, err := antispam.Nameservers([]byte(f.RspamdOptions.Stdout), f.ResolvConf)
	if err != nil {
		r.Feeds.setProbeScope([32]byte{})
		return nil // ResolveFeeds already turned DNS feeds off
	}
	answers := make([]antispam.ProbeAnswer, len(queries))
	var wg sync.WaitGroup
	for i, q := range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = r.Probe(ctx, servers[0], q.Name)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	var scope strings.Builder
	scope.WriteString(servers[0].String())
	for _, q := range queries {
		scope.WriteByte(0)
		scope.WriteString(q.Name)
	}
	r.Feeds.setProbeScope(sha256.Sum256([]byte(scope.String())))
	var out []alert.Finding
	seen := make(map[string]bool)
	for i, q := range queries {
		feed, _ := antispam.FeedByName(q.Feed)
		status, meaning := antispam.ClassifyProbe(feed, q, answers[i])
		// Both queries of a zone can fail alike; findings with one key
		// collapse, so keep the first.
		if finding, ok := r.Feeds.probeFinding(feed, q, status, meaning, answers[i], now); ok && !seen[finding.DedupKey] {
			seen[finding.DedupKey] = true
			out = append(out, finding)
		}
	}
	return out
}

// A changed resolver or query set starts a new sequence of observations.
func (st *FeedState) setProbeScope(scope [32]byte) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.scope != scope {
		clear(st.noAnswer)
		st.scope = scope
	}
}

// probeFinding turns one probe status into a finding. Messages name the
// feed and the answer addresses only, never the query name, which can hold
// the DQS key.
func (st *FeedState) probeFinding(feed antispam.Feed, q antispam.ProbeQuery, status antispam.ProbeStatus, meaning string, a antispam.ProbeAnswer, now time.Time) (alert.Finding, bool) {
	kind := "unlisted"
	if q.Listed {
		kind = "listed"
	}
	counter := feed.Name + ":" + q.Zone.Rule + ":" + kind
	f := alert.Finding{Severity: alert.Warning, Check: CheckFeed, Timestamp: now}
	switch status {
	case antispam.ProbeOK:
		st.count(counter, false)
		return alert.Finding{}, false
	case antispam.ProbeNoAnswer:
		if st.count(counter, true) < 3 {
			return alert.Finding{}, false
		}
		f.DedupKey = feed.Name + ":no_answer"
		f.Message = "Antispam feed " + feed.Name + " does not answer"
		f.Details = "Three checks in a row got no answer from the list through rspamd's resolver. The list adds no score meanwhile; check that rspamd's resolver recurses and can reach the list."
		if feed.NeedsKey {
			f.Details += " Spamhaus also answers nothing for a wrong or disabled DQS key; check the key."
		}
	case antispam.ProbeRefused:
		f.DedupKey = feed.Name + ":refused"
		f.Message = "Antispam feed " + feed.Name + " refuses CSM's queries"
		f.Details = clean(meaning) + ". The list adds no score while it refuses."
	case antispam.ProbeListsAll:
		f.Severity = alert.Critical
		f.DedupKey = feed.Name + ":lists_all"
		f.Message = "Antispam feed " + feed.Name + " answers for addresses it never lists"
		f.Details = "The list returned a listing for its never-listed test point. rspamd stops querying a list that does this once its own check sees it; turn the feed off if this persists."
		if feed.NeedsKey {
			f.Details = "The list returned a listing for its never-listed test point. DQS monitoring in rspamd is disabled to keep the key out of its monitor log; turn the feed off now. CSM's probe reports this condition but does not stop lookups."
		}
	default:
		f.DedupKey = feed.Name + ":unexpected"
		f.Message = "Antispam feed " + feed.Name + " gave an unexpected answer"
		addrs := slices.DeleteFunc(slices.Clone(a.Addrs), func(s string) bool { _, err := netip.ParseAddr(s); return err != nil })
		f.Details = "Answer: " + clean(strings.Join(addrs, ", ")) + ". CSM scores only the list's documented codes."
		if len(addrs) == 0 {
			f.Details = "The list answered with no address. CSM scores only the list's documented codes."
		}
	}
	if status != antispam.ProbeNoAnswer {
		st.count(counter, false)
	}
	return f, true
}

// count updates the consecutive no-answer count and returns it.
func (st *FeedState) count(key string, failed bool) int {
	if st == nil {
		return 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !failed {
		delete(st.noAnswer, key)
		return 0
	}
	st.noAnswer[key]++
	return st.noAnswer[key]
}
