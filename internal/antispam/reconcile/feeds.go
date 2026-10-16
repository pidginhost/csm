package reconcile

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/antispam"
)

// FeedState is what feed handling remembers between passes. Passes run one
// at a time; the mutex guards readers in tests and future callers.
type FeedState struct {
	mu sync.Mutex
	// held is the feed configuration whose apply failed the feeds check;
	// DNS feeds stay off while the configuration is unchanged.
	held string
	// noAnswer counts consecutive passes a probe got no answer, per
	// feed and query kind (Task 11).
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
				Detail: "feed " + name + " is off: rspamd loaded other blocklist rules than CSM wrote at the last apply; CSM keeps DNS feeds off until the feed configuration changes"})
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
	detail := "rspamd still fetches from rspamd.com at " + strings.Join(shown, ", ")
	if len(paths) > len(shown) {
		detail += fmt.Sprintf(" and %d more", len(paths)-len(shown))
	}
	detail += "; CSM points only the maps it knows at local copies. Enable the rspamd_maps feed to accept rspamd.com's terms, or redirect these maps yourself"
	return antispam.Problem{Code: antispam.CodeFeed, Severity: antispam.Warning, Key: antispam.FeedRspamdMaps, Detail: detail}, true
}
