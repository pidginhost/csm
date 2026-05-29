package threatintel

import (
	"net"
	"testing"
)

func TestIPInAnyBot(t *testing.T) {
	r := DefaultRanges()
	if !r.IPInAnyBot(net.ParseIP("66.249.66.1")) {
		t.Error("66.249.66.1 (googlebot) should match IPInAnyBot")
	}
	if !r.IPInAnyBot(net.ParseIP("157.55.39.1")) {
		t.Error("157.55.39.1 (bingbot) should match IPInAnyBot")
	}
	if r.IPInAnyBot(net.ParseIP("203.0.113.7")) {
		t.Error("203.0.113.7 must not match any crawler range")
	}
	if r.IPInAnyBot(nil) {
		t.Error("nil IP must not match")
	}
}

func TestDefaultRanges_Googlebot(t *testing.T) {
	r := DefaultRanges()
	if !r.IPInBot(net.ParseIP("66.249.66.1"), "googlebot") {
		t.Error("66.249.66.1 should be inside googlebot range")
	}
	if r.IPInBot(net.ParseIP("203.0.113.5"), "googlebot") {
		t.Error("203.0.113.5 must not be inside googlebot range")
	}
}

func TestClaimedBotFromUA(t *testing.T) {
	cases := map[string]string{
		"Googlebot/2.1": "googlebot",
		"bingbot/2.0":   "bingbot",
		"Mozilla/5.0":   "",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit...)": "facebookbot",
		"meta-externalagent/1.1": "facebookbot",
	}
	for ua, want := range cases {
		if got := ClaimedBotFromUA(ua); got != want {
			t.Errorf("ClaimedBotFromUA(%q)=%q want %q", ua, got, want)
		}
	}
}
