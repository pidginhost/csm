package threatintel

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

type rangeTestResponse struct {
	status int
	body   string
	err    error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func rangeTestClient(routes map[string]rangeTestResponse) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		res, ok := routes[req.URL.String()]
		if !ok {
			res = rangeTestResponse{status: http.StatusNotFound}
		}
		if res.err != nil {
			return nil, res.err
		}
		status := res.status
		if status == 0 {
			status = http.StatusOK
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(res.body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
}

func TestParseRangeJSON_ValidatesAndNormalizes(t *testing.T) {
	data := []byte(`{"prefixes":[
		{"ipv4Prefix":"74.7.241.0/25"},
		{"ipv6Prefix":"2600:1901::/48"},
		{"ipv4Prefix":"8.0.0.0/8"},
		{"ipv4Prefix":"0.1.0.0/16"},
		{"ipv4Prefix":"100.64.0.0/16"},
		{"ipv4Prefix":"192.88.99.0/24"},
		{"ipv4Prefix":"198.18.0.0/16"},
		{"ipv4Prefix":"192.168.0.0/24"},
		{"ipv6Prefix":"2001:db8::/32"},
		{"ipv4Prefix":"garbage"},
		{"ipv4Prefix":"0.0.0.0/0"}
	]}`)
	nets, err := ParseRangeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	// Only the narrow, public /25 and /48 survive: /8 is over-broad, the
	// RFC1918 /24 is non-public, garbage is unparseable, /0 is the default route.
	if len(nets) != 2 {
		t.Fatalf("got %d nets, want 2: %v", len(nets), nets)
	}
	var v4, v6 bool
	for _, n := range nets {
		if n.Contains(net.ParseIP("74.7.241.37")) {
			v4 = true
		}
		if n.Contains(net.ParseIP("2600:1901::1")) {
			v6 = true
		}
	}
	if !v4 || !v6 {
		t.Errorf("expected the public v4 and v6 ranges to be kept: v4=%v v6=%v", v4, v6)
	}
}

func TestFetchRange(t *testing.T) {
	url := "https://ranges.test/gptbot.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		url: {body: `{"prefixes":[{"ipv4Prefix":"74.7.241.0/25"}]}`},
	})
	nets, err := FetchRange(context.Background(), client, url)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 || !nets[0].Contains(net.ParseIP("74.7.241.37")) {
		t.Fatalf("FetchRange = %v", nets)
	}
}

func TestFetchRangeRejectsEmptyValidPrefixSet(t *testing.T) {
	url := "https://ranges.test/empty.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		url: {body: `{"prefixes":[{"ipv4Prefix":"10.0.0.0/8"}]}`},
	})
	if _, err := FetchRange(context.Background(), client, url); err == nil {
		t.Fatal("FetchRange accepted a feed with no valid public prefixes")
	}
}

func TestFetchRangeRejectsOversizedFeed(t *testing.T) {
	url := "https://ranges.test/oversized.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		url: {body: strings.Repeat(" ", maxRangeBytes+1)},
	})
	if _, err := FetchRange(context.Background(), client, url); err == nil {
		t.Fatal("FetchRange accepted an oversized feed")
	}
}

func TestFetchedRangesOverlayInIPInBot(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	_, n, _ := net.ParseCIDR("203.0.113.0/24")
	PublishFetchedRanges(map[string][]*net.IPNet{"gptbot": {n}})

	r := DefaultRanges()
	if !r.IPInBot(net.ParseIP("203.0.113.50"), "gptbot") {
		t.Error("fetched-overlay IP must match IPInBot for its bot")
	}
	if r.IPInBot(net.ParseIP("203.0.113.50"), "bingbot") {
		t.Error("fetched-overlay IP must not match a different bot")
	}
	if !r.IPInAnyBot(net.ParseIP("203.0.113.50")) {
		t.Error("fetched-overlay IP must match IPInAnyBot")
	}
}

func TestAICrawlerRangePrefixCountsIncludesEmbeddedAndFetched(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	PublishFetchedRanges(nil)

	base := AICrawlerRangePrefixCounts()
	if base["gptbot"] == 0 {
		t.Fatal("gptbot embedded prefixes should be included")
	}
	if base["perplexitybot"] == 0 {
		t.Fatal("perplexitybot embedded prefixes should be included")
	}

	_, n, err := net.ParseCIDR("9.9.9.0/24")
	if err != nil {
		t.Fatal(err)
	}
	PublishFetchedRanges(map[string][]*net.IPNet{"perplexitybot": {n}})
	counts := AICrawlerRangePrefixCounts()
	if counts["perplexitybot"] != base["perplexitybot"]+1 {
		t.Fatalf("perplexitybot prefixes = %d, want embedded + fetched = %d", counts["perplexitybot"], base["perplexitybot"]+1)
	}
}

func TestRefreshFetchedRanges(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	gptURL := "https://ranges.test/gptbot.json"
	ppxURL := "https://ranges.test/perplexitybot.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		gptURL: {body: `{"prefixes":[{"ipv4Prefix":"74.7.241.0/25"}]}`},
		ppxURL: {body: `{"prefixes":[{"ipv4Prefix":"18.97.9.96/29"}]}`},
	})

	cache := filepath.Join(t.TempDir(), "botranges.json")
	sources := []RangeSource{{Bot: "gptbot", URL: gptURL}, {Bot: "perplexitybot", URL: ppxURL}}
	n, err := RefreshFetchedRanges(context.Background(), client, sources, cache)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("refreshed %d bots, want 2", n)
	}
	r := DefaultRanges()
	if !r.IPInBot(net.ParseIP("74.7.241.37"), "gptbot") || !r.IPInBot(net.ParseIP("18.97.9.100"), "perplexitybot") {
		t.Error("refreshed overlay not active in IPInBot")
	}

	// A transient failure for one bot keeps its prior overlay instead of dropping it.
	badURL := "https://ranges.test/bad.json"
	client = rangeTestClient(map[string]rangeTestResponse{
		badURL: {status: http.StatusInternalServerError},
		ppxURL: {body: `{"prefixes":[{"ipv4Prefix":"18.97.9.96/29"}]}`},
	})
	n, _ = RefreshFetchedRanges(context.Background(), client,
		[]RangeSource{{Bot: "gptbot", URL: badURL}, {Bot: "perplexitybot", URL: ppxURL}}, cache)
	if n != 1 {
		t.Fatalf("refreshed %d bots after one failure, want 1", n)
	}
	if !r.IPInBot(net.ParseIP("74.7.241.37"), "gptbot") {
		t.Error("gptbot overlay must survive a transient fetch failure")
	}
}

func TestRefreshFetchedRangesCacheWriteFailureKeepsPreviousOverlay(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil); setLastRefreshUnix(0) })
	_, oldNet, _ := net.ParseCIDR("8.8.4.0/24")
	PublishFetchedRanges(map[string][]*net.IPNet{"gptbot": {oldNet}})
	setLastRefreshUnix(123)

	gptURL := "https://ranges.test/gptbot.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		gptURL: {body: `{"prefixes":[{"ipv4Prefix":"9.9.9.0/24"}]}`},
	})
	n, err := RefreshFetchedRanges(context.Background(), client, []RangeSource{
		{Bot: "gptbot", URL: gptURL},
	}, filepath.Join(t.TempDir(), "missing", "botranges.json"))
	if err == nil {
		t.Fatal("refresh should fail when the cache cannot be written")
	}
	if n != 0 {
		t.Fatalf("refreshed %d bots after cache write failure, want 0", n)
	}
	snap := FetchedRangesSnapshot()
	if len(snap["gptbot"]) != 1 || snap["gptbot"][0].String() != oldNet.String() {
		t.Fatalf("overlay after failed write = %+v, want previous %s", snap["gptbot"], oldNet)
	}
	if got := LastFetchedRangesRefresh(); got.IsZero() || got.Unix() != 123 {
		t.Fatalf("last refresh after failed write = %v, want unix 123", got)
	}
}

func TestRefreshFetchedRangesPartialIdentitySuccessReplacesOverlay(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	_, oldGPT, _ := net.ParseCIDR("8.8.4.0/24")
	_, oldPPX, _ := net.ParseCIDR("1.1.1.0/24")
	PublishFetchedRanges(map[string][]*net.IPNet{
		"gptbot":        {oldGPT},
		"perplexitybot": {oldPPX},
	})

	gptOK := "https://ranges.test/openai-gptbot.json"
	gptBad := "https://ranges.test/openai-searchbot.json"
	ppxOK := "https://ranges.test/perplexitybot.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		gptOK:  {body: `{"prefixes":[{"ipv4Prefix":"9.9.9.0/24"}]}`},
		gptBad: {status: http.StatusInternalServerError},
		ppxOK:  {body: `{"prefixes":[{"ipv4Prefix":"4.2.2.0/24"}]}`},
	})

	n, err := RefreshFetchedRanges(context.Background(), client, []RangeSource{
		{Bot: "gptbot", URL: gptOK},
		{Bot: "gptbot", URL: gptBad},
		{Bot: "perplexitybot", URL: ppxOK},
	}, "")
	if err != nil {
		t.Fatalf("partial refresh with successful feeds returned error: %v", err)
	}
	if n != 2 {
		t.Fatalf("refreshed %d bots, want gptbot and perplexitybot", n)
	}
	r := DefaultRanges()
	if r.IPInBot(net.ParseIP("8.8.4.4"), "gptbot") {
		t.Error("gptbot's previous overlay must be replaced after a successful gptbot feed")
	}
	if !r.IPInBot(net.ParseIP("9.9.9.9"), "gptbot") {
		t.Error("gptbot must publish the successful same-identity feed")
	}
	if !r.IPInBot(net.ParseIP("4.2.2.2"), "perplexitybot") {
		t.Error("an unrelated bot with all feeds successful should still refresh")
	}
}

func TestRefreshFetchedRangesAllFailuresKeepOverlayAndReturnError(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	_, oldGPT, _ := net.ParseCIDR("8.8.4.0/24")
	PublishFetchedRanges(map[string][]*net.IPNet{"gptbot": {oldGPT}})

	badURL := "https://ranges.test/openai-gptbot.json"
	client := rangeTestClient(map[string]rangeTestResponse{
		badURL: {status: http.StatusInternalServerError},
	})

	n, err := RefreshFetchedRanges(context.Background(), client, []RangeSource{
		{Bot: "gptbot", URL: badURL},
	}, "")
	if err == nil {
		t.Fatal("all failed fetches should return the last error")
	}
	if n != 0 {
		t.Fatalf("refreshed %d bots, want 0", n)
	}
	if !DefaultRanges().IPInBot(net.ParseIP("8.8.4.4"), "gptbot") {
		t.Error("previous overlay must survive when every feed fails")
	}
}

func TestSaveLoadFetchedRanges(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	path := filepath.Join(t.TempDir(), "botranges.json")
	_, n, _ := net.ParseCIDR("18.97.1.228/30")
	if err := SaveFetchedRanges(path, map[string][]*net.IPNet{"perplexitybot": {n}}); err != nil {
		t.Fatal(err)
	}
	if err := LoadFetchedRanges(path); err != nil {
		t.Fatal(err)
	}
	if !DefaultRanges().IPInBot(net.ParseIP("18.97.1.229"), "perplexitybot") {
		t.Error("loaded-from-disk overlay must be active in IPInBot")
	}
}
