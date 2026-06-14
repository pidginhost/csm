package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/atomicio"
)

// fetchedRanges is the runtime-updatable overlay of vendor-published IP ranges,
// keyed by bot identity. It augments the embedded snapshots in DefaultRanges so
// crawler allowlists refresh without a new release. Swapped wholesale; scan-path
// readers load the pointer lock-free.
var fetchedRanges atomic.Pointer[map[string][]*net.IPNet]

// PublishFetchedRanges installs the runtime range overlay. nil clears it.
func PublishFetchedRanges(m map[string][]*net.IPNet) {
	if len(m) == 0 {
		fetchedRanges.Store(nil)
		return
	}
	cp := make(map[string][]*net.IPNet, len(m))
	for k, v := range m {
		cp[k] = append([]*net.IPNet(nil), v...)
	}
	fetchedRanges.Store(&cp)
}

func fetchedRangesFor(bot string) []*net.IPNet {
	p := fetchedRanges.Load()
	if p == nil {
		return nil
	}
	return (*p)[bot]
}

func fetchedRangesSnapshot() map[string][]*net.IPNet {
	p := fetchedRanges.Load()
	if p == nil {
		return nil
	}
	return *p
}

// FetchedRangesSnapshot returns a shallow copy of the current overlay for
// inspection or merge by the updater.
func FetchedRangesSnapshot() map[string][]*net.IPNet {
	snap := fetchedRangesSnapshot()
	out := make(map[string][]*net.IPNet, len(snap))
	for k, v := range snap {
		out[k] = append([]*net.IPNet(nil), v...)
	}
	return out
}

// RefreshFetchedRanges fetches every source, publishes the merged overlay, and
// persists it to cachePath (skipped when empty). The first successful feed for a
// bot identity replaces that bot's previous overlay; later successful feeds for
// the same identity append. A bot whose every feed fails keeps its previous
// overlay, so a full vendor outage never narrows the allowlist. Returns the
// number of bot identities refreshed.
func RefreshFetchedRanges(ctx context.Context, client *http.Client, sources []RangeSource, cachePath string) (int, error) {
	merged := FetchedRangesSnapshot()
	updated := map[string]struct{}{}
	var lastErr error
	for _, src := range sources {
		nets, err := FetchRange(ctx, client, src.URL)
		if err != nil {
			lastErr = err
			continue
		}
		if _, ok := updated[src.Bot]; !ok {
			merged[src.Bot] = nil
			updated[src.Bot] = struct{}{}
		}
		merged[src.Bot] = append(merged[src.Bot], nets...)
	}
	if len(updated) == 0 {
		return 0, lastErr
	}
	PublishFetchedRanges(merged)
	if cachePath != "" {
		if err := SaveFetchedRanges(cachePath, merged); err != nil {
			return len(updated), err
		}
	}
	return len(updated), nil
}

// RangeSource is one vendor IP-range feed mapped to a bot identity. Multiple
// sources may share an identity (OpenAI publishes GPTBot, ChatGPT-User and
// OAI-SearchBot separately; all verify the "gptbot" identity).
type RangeSource struct {
	Bot string
	URL string
}

// DefaultRangeSources are the vendor feeds the auto-updater refreshes. URLs are
// stable, vendor-published JSON in the {prefixes:[{ipv4Prefix|ipv6Prefix}]}
// shape. Anthropic ClaudeBot is intentionally absent: it has no published
// machine-readable range feed and stays rDNS-verified (anthropic.com).
func DefaultRangeSources() []RangeSource {
	return []RangeSource{
		{Bot: "gptbot", URL: "https://openai.com/gptbot.json"},
		{Bot: "gptbot", URL: "https://openai.com/chatgpt-user.json"},
		{Bot: "gptbot", URL: "https://openai.com/searchbot.json"},
		{Bot: "perplexitybot", URL: "https://www.perplexity.ai/perplexitybot.json"},
	}
}

const (
	maxRangeBytes      = 4 << 20 // 4 MiB; vendor feeds are well under this
	maxPrefixesPerFeed = 100000  // sanity cap against a runaway feed
)

// ParseRangeJSON parses a vendor range feed and returns valid, public,
// suitably-narrow CIDRs. Unparseable, over-broad, or non-public entries are
// dropped (not errors) so one bad row cannot poison the feed, and the same
// guards as operator-configured ranges stop a compromised or mistaken feed from
// allowlisting the whole internet.
func ParseRangeJSON(data []byte) ([]*net.IPNet, error) {
	var f embedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("bot range feed: %w", err)
	}
	var out []*net.IPNet
	for _, p := range f.Prefixes {
		for _, cidr := range []string{p.IPv4, p.IPv6} {
			if cidr == "" {
				continue
			}
			_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			n = normalizeIPNet(n)
			if n == nil || !operatorBotIPRangeAllowed(n) {
				continue
			}
			out = append(out, n)
			if len(out) >= maxPrefixesPerFeed {
				return out, nil
			}
		}
	}
	return out, nil
}

// FetchRange downloads and parses one vendor range feed.
func FetchRange(ctx context.Context, client *http.Client, url string) ([]*net.IPNet, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bot range feed %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRangeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRangeBytes {
		return nil, fmt.Errorf("bot range feed %s: exceeds %d bytes", url, maxRangeBytes)
	}
	nets, err := ParseRangeJSON(data)
	if err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("bot range feed %s: no valid prefixes", url)
	}
	return nets, nil
}

// rangeCacheFile is the on-disk persistence shape for the fetched overlay.
type rangeCacheFile struct {
	Bots map[string][]string `json:"bots"`
}

// SaveFetchedRanges persists the overlay so a restart keeps the last-good feed
// until the next refresh completes.
func SaveFetchedRanges(path string, m map[string][]*net.IPNet) error {
	c := rangeCacheFile{Bots: map[string][]string{}}
	for bot, nets := range m {
		strs := make([]string, 0, len(nets))
		for _, n := range nets {
			strs = append(strs, n.String())
		}
		sort.Strings(strs)
		c.Bots[bot] = strs
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return atomicio.AtomicWrite(path, 0o600, data)
}

// LoadFetchedRanges reads a previously saved overlay and publishes it. A
// missing file is not an error (first run). Entries are re-validated on load.
func LoadFetchedRanges(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- daemon-owned state path
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var c rangeCacheFile
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	m := make(map[string][]*net.IPNet, len(c.Bots))
	for bot, strs := range c.Bots {
		for _, s := range strs {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			if n = normalizeIPNet(n); n != nil && operatorBotIPRangeAllowed(n) {
				m[bot] = append(m[bot], n)
			}
		}
	}
	PublishFetchedRanges(m)
	return nil
}
