package webui

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

var allUIFeatures = []string{"cpanel", "mail", "mailQueue", "mailHeld", "mailForwarders", "mailDeferrals", "mailSuspensions", "emailAV", "cphulk"}

// Servers in this package's tests see a cPanel host unless a test calls
// setTestPlatform: every page, tab and setting is present, and no test asks
// the build host which mail server it runs.
func init() {
	hostPlatform = func() (platform.Info, platform.MTAKind) {
		return platform.Info{Panel: platform.PanelCPanel}, platform.MTAExim
	}
}

// setTestPlatform makes s see the given panel and mail server.
func setTestPlatform(s *Server, panel platform.Panel, mta platform.MTAKind) {
	s.detectPlatform = func() (platform.Info, platform.MTAKind) {
		return platform.Info{Panel: panel}, mta
	}
	s.featureMu.Lock()
	s.featureCache = featureSnapshot{}
	s.featureRefreshing = false
	s.featureMu.Unlock()
}

func TestUIFeaturesByPlatform(t *testing.T) {
	cases := []struct {
		name  string
		panel platform.Panel
		mta   platform.MTAKind
		on    []string
	}{
		{"cpanel", platform.PanelCPanel, platform.MTAExim, allUIFeatures},
		{"cpanel mta undetected", platform.PanelCPanel, platform.MTAUnknown, allUIFeatures},
		{"plesk postfix", platform.PanelPlesk, platform.MTAPostfix, []string{"mail"}},
		{"directadmin exim", platform.PanelDA, platform.MTAExim, []string{"mail"}},
		{"bare exim", platform.PanelNone, platform.MTAExim, []string{"mail"}},
		{"bare stalwart", platform.PanelNone, platform.MTAStalwart, []string{"mail"}},
		{"bare no mta", platform.PanelNone, platform.MTAUnknown, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := uiFeatures(platform.Info{Panel: c.panel}, c.mta)
			if len(got) != len(allUIFeatures) {
				t.Fatalf("got %d flags %v, want %d", len(got), got, len(allUIFeatures))
			}
			for _, k := range allUIFeatures {
				v, ok := got[k]
				if !ok {
					t.Errorf("flag %q missing", k)
				}
				if want := slices.Contains(c.on, k); v != want {
					t.Errorf("%s = %v, want %v", k, v, want)
				}
			}
		})
	}
}

func TestServerFeatureUnknownNameIsFalse(t *testing.T) {
	s := newTestServer(t, "tok")
	setTestPlatform(s, platform.PanelCPanel, platform.MTAExim)
	if s.feature("nope") {
		t.Fatal("unknown feature reported on")
	}
}

func TestServerFeaturesRefreshAfterTTL(t *testing.T) {
	s := newTestServer(t, "tok")
	calls := 0
	s.detectPlatform = func() (platform.Info, platform.MTAKind) {
		calls++
		if calls == 1 {
			return platform.Info{}, platform.MTAUnknown
		}
		return platform.Info{}, platform.MTAPostfix
	}
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.featureNow = func() time.Time { return now }

	if s.feature("mail") {
		t.Fatal("mail on before a mail server exists")
	}
	now = now.Add(4*time.Minute + 59*time.Second)
	if s.feature("mail") || calls != 1 {
		t.Fatalf("within TTL: mail=%v calls=%d, want false and 1", s.feature("mail"), calls)
	}
	now = now.Add(2 * time.Second)
	if !s.feature("mail") || calls != 2 {
		t.Fatalf("after TTL: mail=%v calls=%d, want true and 2", s.feature("mail"), calls)
	}
}

func TestServerFeaturesFollowPlatformOverride(t *testing.T) {
	for _, c := range []struct {
		panel platform.Panel
		want  bool
	}{{platform.PanelCPanel, true}, {platform.PanelNone, false}} {
		platform.ResetForTest()
		t.Cleanup(platform.ResetForTest)
		panel := c.panel
		if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
			t.Fatal("platform override rejected before Detect")
		}
		s := newTestServer(t, "tok")
		s.detectPlatform = func() (platform.Info, platform.MTAKind) {
			return platform.Detect(), platform.MTAUnknown
		}
		if got := s.feature("cphulk"); got != c.want {
			t.Errorf("panel %q: cphulk = %v, want %v", c.panel, got, c.want)
		}
	}
}

func TestCSMConfigCarriesFeatures(t *testing.T) {
	s := newTestServer(t, "tok")
	setTestPlatform(s, platform.PanelPlesk, platform.MTAPostfix)
	cfg := s.csmConfig()
	feats, ok := cfg["features"].(map[string]bool)
	if !ok {
		t.Fatalf("features is %T, want map[string]bool", cfg["features"])
	}
	if !feats["mail"] || feats["cpanel"] {
		t.Errorf("features = %v, want mail on and cpanel off", feats)
	}
	if cfg["panel"] != "plesk" || cfg["mta"] != "postfix" {
		t.Errorf("panel=%v mta=%v, want plesk and postfix", cfg["panel"], cfg["mta"])
	}
}

func TestCoreExposesFeatureHelper(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/csm-core.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "CSM.feature = function") {
		t.Error("csm-core.js does not define CSM.feature")
	}
}

// A slow detection (systemd answering late) must not hold up page renders:
// while one request re-detects, the others keep the previous answer.
func TestServerFeaturesServeStaleWhileRefreshing(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.featureNow = func() time.Time { return now }
	entered, release := make(chan struct{}), make(chan struct{})
	first := true
	s.detectPlatform = func() (platform.Info, platform.MTAKind) {
		if first {
			first = false
			return platform.Info{}, platform.MTAUnknown
		}
		close(entered)
		<-release
		return platform.Info{}, platform.MTAPostfix
	}
	if s.feature("mail") {
		t.Fatal("mail on before a mail server exists")
	}
	now = now.Add(featureTTL + time.Second)

	refreshed := make(chan bool)
	go func() { refreshed <- s.feature("mail") }()
	<-entered

	got := make(chan bool)
	go func() { got <- s.feature("mail") }()
	select {
	case v := <-got:
		if v {
			t.Error("stale read returned the value still being detected")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a second caller waited on the detection in progress")
	}
	close(release)
	if !<-refreshed {
		t.Error("the refreshing caller did not get the new value")
	}
	if !s.feature("mail") {
		t.Error("the new value was not cached")
	}
}
