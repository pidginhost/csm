package antispam

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateSocketAccepts(t *testing.T) {
	for _, p := range []string{DefaultSocket, "/var/run/rspamd/normal.sock", "/run/a_b-c.d/x1.sock"} {
		if err := ValidateSocket(p); err != nil {
			t.Errorf("ValidateSocket(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateSocketRejects(t *testing.T) {
	for _, p := range []string{
		"", "/", "run/rspamd.sock", "/run//rspamd.sock", "/run/./rspamd.sock",
		"/run/../rspamd.sock", "/run/rspamd/", "/run/rspamd.sock\n", "/run/rspamd sock",
		"/run/$spool/x.sock", "/run/x.sock:/y", "/run/x;y", "/run/{x}", `/run/x\y`,
		"/run/caf\u00e9.sock", "/" + strings.Repeat("a", maxSocketPath),
	} {
		if err := ValidateSocket(p); err == nil {
			t.Errorf("ValidateSocket(%q) = nil, want error", p)
		}
	}
}

func TestValidateScores(t *testing.T) {
	for _, c := range [][2]int{{15, 6}, {2, 1}, {1000, 999}} {
		if err := ValidateScores(c[0], c[1]); err != nil {
			t.Errorf("ValidateScores(%d, %d) = %v, want nil", c[0], c[1], err)
		}
	}
	for _, c := range [][2]int{{0, 6}, {15, 0}, {-1, -5}, {6, 6}, {6, 15}, {1001, 6}, {15, 1001}} {
		if err := ValidateScores(c[0], c[1]); err == nil {
			t.Errorf("ValidateScores(%d, %d) = nil, want error", c[0], c[1])
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	s := Settings{Socket: DefaultSocket, RejectScore: DefaultRejectScore, TagScore: DefaultTagScore}
	if err := s.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	s.Socket = "relative.sock"
	if err := s.Validate(); err == nil {
		t.Fatal("relative socket accepted")
	}
}

func TestSettingsFeedHelpers(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedURIBL, FeedRspamdMaps, FeedPSBL}
	if !s.HasFeed(FeedPSBL) || s.HasFeed(FeedSEM) {
		t.Fatal("HasFeed")
	}
	var got []string
	for _, f := range s.DNSFeeds() {
		got = append(got, f.Name)
	}
	if want := []string{FeedPSBL, FeedURIBL}; !slices.Equal(got, want) {
		t.Fatalf("DNSFeeds = %v, want catalogue order %v", got, want)
	}
	if s.Redirects() {
		t.Fatal("rspamd_maps keeps rspamd.com maps")
	}
	if !defaults(false).Redirects() {
		t.Fatal("no feeds means local map copies")
	}
}

func TestSettingsValidateFeedsAndSkipMaps(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{"nope"}
	if err := s.Validate(); err == nil {
		t.Fatal("unknown feed accepted")
	}
	s = defaults(false)
	s.SkipMaps = []string{RedirectWhitelist, "nope"}
	if err := s.Validate(); err == nil {
		t.Fatal("unknown map redirect accepted")
	}
	s.SkipMaps = []string{RedirectWhitelist, RedirectWhitelist}
	if err := s.Validate(); err == nil {
		t.Fatal("duplicate map redirect accepted")
	}
}
