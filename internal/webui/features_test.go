package webui

import (
	"maps"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

var cpanelUIFeatures = []string{"cpanel", "mail", "mailQueue", "mailHeld", "mailForwarders", "mailDeferrals", "mailSuspensions", "emailAV", "cphulk"}

var allUIFeatures = append(slices.Clone(cpanelUIFeatures), "stalwartFilter", "php", "phpShield")

// Servers in this package's tests see a cPanel host unless a test calls
// setTestPlatform: every page, tab and setting is present, and no test asks
// the build host which mail server it runs.
func init() {
	hostPlatform = func() (platform.Info, platform.MTAKind) {
		return platform.Info{Panel: platform.PanelCPanel}, platform.MTAExim
	}
	hostPHP = func() bool { return true }
}

// setTestPHP makes s see PHP installed or not.
func setTestPHP(s *Server, installed bool) {
	f := maps.Clone(s.features())
	f["php"], f["phpShield"] = installed, installed
	s.setFeatures(f)
}

func setTestPlatform(s *Server, panel platform.Panel, mta platform.MTAKind) {
	f := s.features()
	s.setFeatures(uiFeatures(platform.Info{Panel: panel}, mta, phpPresence{php: f["php"], shield: f["phpShield"]}))
}

func TestUIFeaturesByPlatform(t *testing.T) {
	cases := []struct {
		name  string
		panel platform.Panel
		mta   platform.MTAKind
		on    []string
	}{
		{"cpanel", platform.PanelCPanel, platform.MTAExim, cpanelUIFeatures},
		{"cpanel mta undetected", platform.PanelCPanel, platform.MTAUnknown, cpanelUIFeatures},
		{"plesk postfix", platform.PanelPlesk, platform.MTAPostfix, []string{"mail"}},
		{"directadmin exim", platform.PanelDA, platform.MTAExim, []string{"mail"}},
		{"bare exim", platform.PanelNone, platform.MTAExim, []string{"mail"}},
		{"bare stalwart", platform.PanelNone, platform.MTAStalwart, []string{"mail", "mailSuspensions", "stalwartFilter"}},
		{"bare no mta", platform.PanelNone, platform.MTAUnknown, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := uiFeatures(platform.Info{Panel: c.panel}, c.mta, phpPresence{})
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

func TestUIFeaturesPHPFollowsDetection(t *testing.T) {
	for _, panel := range []platform.Panel{platform.PanelCPanel, platform.PanelNone} {
		if !uiFeatures(platform.Info{Panel: panel}, platform.MTAUnknown, phpPresence{php: true})["php"] {
			t.Errorf("%q with PHP: php flag off", panel)
		}
		if uiFeatures(platform.Info{Panel: panel}, platform.MTAUnknown, phpPresence{})["php"] {
			t.Errorf("%q without PHP: php flag on", panel)
		}
	}
}

// CSM suspends Stalwart mailboxes through its API, on any panel but cPanel,
// which keeps its own backend.
func TestUIFeaturesStalwartSuspensions(t *testing.T) {
	for _, panel := range []platform.Panel{platform.PanelNone, platform.PanelPlesk, platform.PanelDA} {
		if !uiFeatures(platform.Info{Panel: panel}, platform.MTAStalwart, phpPresence{})["mailSuspensions"] {
			t.Errorf("%q with Stalwart: no Suspended tab", panel)
		}
	}
	for _, mta := range []platform.MTAKind{platform.MTAPostfix, platform.MTAExim, platform.MTAUnknown} {
		if uiFeatures(platform.Info{Panel: platform.PanelNone}, mta, phpPresence{})["mailSuspensions"] {
			t.Errorf("%q without cPanel: Suspended tab shown", mta)
		}
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
	synctest.Test(t, func(t *testing.T) {
		s := &Server{pruneDone: make(chan struct{})}
		s.setFeatures(uiFeatures(platform.Info{}, platform.MTAUnknown, phpPresence{php: true}))
		var calls atomic.Int32
		s.detectPlatform = func() (platform.Info, platform.MTAKind) {
			calls.Add(1)
			return platform.Info{}, platform.MTAPostfix
		}
		go s.watchFeatures()
		defer close(s.pruneDone)
		synctest.Wait()
		time.Sleep(featureTTL - time.Second)
		if s.feature("mail") || calls.Load() != 0 {
			t.Fatalf("within TTL: mail=%v calls=%d", s.feature("mail"), calls.Load())
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if !s.feature("mail") || calls.Load() != 1 {
			t.Fatalf("after TTL: mail=%v calls=%d", s.feature("mail"), calls.Load())
		}
	})
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
		s.setFeatures(s.hostFeatures())
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

// A blocked detector must never hold up a reader, even on the first scan.
func TestPHPRefreshDoesNotBlockFirstRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{pruneDone: make(chan struct{})}
		s.setFeatures(uiFeatures(platform.Info{}, platform.MTAUnknown, phpPresence{}))
		entered, release := make(chan struct{}), make(chan struct{})
		s.detectContainerPHP = func() (bool, bool) {
			close(entered)
			<-release
			return true, false
		}
		platformEntered, platformRelease := make(chan struct{}), make(chan struct{})
		s.detectPlatform = func() (platform.Info, platform.MTAKind) {
			close(platformEntered)
			<-platformRelease
			return platform.Info{}, platform.MTAPostfix
		}
		go s.watchFeatures()
		defer close(s.pruneDone)
		<-entered
		if s.feature("php") {
			t.Fatal("PHP reported before detection completed")
		}
		close(release)
		synctest.Wait()
		if !s.feature("php") || s.feature("phpShield") {
			t.Fatal("container PHP snapshot was not published")
		}

		time.Sleep(featureTTL)
		<-platformEntered
		if s.feature("mail") || !s.feature("php") {
			t.Fatal("page lost the previous snapshot during refresh")
		}
		close(platformRelease)
		synctest.Wait()
		if !s.feature("mail") || !s.feature("phpShield") {
			t.Fatal("host snapshot was not refreshed")
		}
	})
}
