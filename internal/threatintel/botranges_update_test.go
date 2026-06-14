package threatintel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestParseRangeJSON_ValidatesAndNormalizes(t *testing.T) {
	data := []byte(`{"prefixes":[
		{"ipv4Prefix":"74.7.241.0/25"},
		{"ipv6Prefix":"2600:1901::/48"},
		{"ipv4Prefix":"8.0.0.0/8"},
		{"ipv4Prefix":"192.168.0.0/24"},
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"74.7.241.0/25"}]}`))
	}))
	defer srv.Close()
	nets, err := FetchRange(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 || !nets[0].Contains(net.ParseIP("74.7.241.37")) {
		t.Fatalf("FetchRange = %v", nets)
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

func TestRefreshFetchedRanges(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	gpt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"74.7.241.0/25"}]}`))
	}))
	defer gpt.Close()
	ppx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"18.97.9.96/29"}]}`))
	}))
	defer ppx.Close()

	cache := filepath.Join(t.TempDir(), "botranges.json")
	sources := []RangeSource{{Bot: "gptbot", URL: gpt.URL}, {Bot: "perplexitybot", URL: ppx.URL}}
	n, err := RefreshFetchedRanges(context.Background(), gpt.Client(), sources, cache)
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
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	n, _ = RefreshFetchedRanges(context.Background(), bad.Client(),
		[]RangeSource{{Bot: "gptbot", URL: bad.URL}, {Bot: "perplexitybot", URL: ppx.URL}}, cache)
	if n != 1 {
		t.Fatalf("refreshed %d bots after one failure, want 1", n)
	}
	if !r.IPInBot(net.ParseIP("74.7.241.37"), "gptbot") {
		t.Error("gptbot overlay must survive a transient fetch failure")
	}
}

func TestSaveLoadFetchedRanges(t *testing.T) {
	t.Cleanup(func() { PublishFetchedRanges(nil) })
	path := filepath.Join(t.TempDir(), "botranges.json")
	_, n, _ := net.ParseCIDR("198.51.100.0/24")
	if err := SaveFetchedRanges(path, map[string][]*net.IPNet{"perplexitybot": {n}}); err != nil {
		t.Fatal(err)
	}
	if err := LoadFetchedRanges(path); err != nil {
		t.Fatal(err)
	}
	if !DefaultRanges().IPInBot(net.ParseIP("198.51.100.9"), "perplexitybot") {
		t.Error("loaded-from-disk overlay must be active in IPInBot")
	}
}
