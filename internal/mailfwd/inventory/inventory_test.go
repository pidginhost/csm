package inventory

import (
	"testing"
)

func TestClassifyProvider(t *testing.T) {
	local := map[string]bool{"example.test": true, "hosted.test": true}
	cases := []struct {
		addr string
		want ProviderClass
	}{
		{"user@example.test", ProviderLocal},
		{"user@hosted.test", ProviderLocal},
		{"a@gmail.com", ProviderGmail},
		{"a@googlemail.com", ProviderGmail},
		{"a@yahoo.com", ProviderYahoo},
		{"a@yahoo.co.uk", ProviderYahoo},
		{"a@ymail.com", ProviderYahoo},
		{"a@outlook.com", ProviderOutlook},
		{"a@hotmail.com", ProviderOutlook},
		{"a@live.ro", ProviderOutlook},
		{"a@somecorp.example", ProviderExternal},
		{"A@GMAIL.COM", ProviderGmail}, // case-insensitive
	}
	for _, c := range cases {
		if got := classifyProvider(c.addr, local); got != c.want {
			t.Errorf("classifyProvider(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestParseForwarderLine(t *testing.T) {
	local := map[string]bool{"psihologa.test": true}

	t.Run("forward-only to free provider", func(t *testing.T) {
		fwd, ok := parseForwarderLine("psihologa.test", "contact: psi@yahoo.com", local)
		if !ok {
			t.Fatal("expected a forwarder")
		}
		if fwd.Source != "contact@psihologa.test" {
			t.Errorf("source = %q", fwd.Source)
		}
		if len(fwd.Destinations) != 1 || fwd.Destinations[0].Provider != ProviderYahoo {
			t.Errorf("destinations = %+v", fwd.Destinations)
		}
		if !fwd.ForwardOnly || fwd.KeepLocal {
			t.Errorf("want forward-only, got ForwardOnly=%v KeepLocal=%v", fwd.ForwardOnly, fwd.KeepLocal)
		}
	})

	t.Run("keep-local copy plus external forward", func(t *testing.T) {
		fwd, ok := parseForwarderLine("psihologa.test", "owner: owner@psihologa.test, ext@gmail.com", local)
		if !ok {
			t.Fatal("expected a forwarder")
		}
		if !fwd.KeepLocal || fwd.ForwardOnly {
			t.Errorf("want keep-local, got KeepLocal=%v ForwardOnly=%v", fwd.KeepLocal, fwd.ForwardOnly)
		}
		if len(fwd.Destinations) != 2 {
			t.Fatalf("want 2 destinations, got %d", len(fwd.Destinations))
		}
	})

	t.Run("pipe, blackhole, fail, comment, blank are not forwarders", func(t *testing.T) {
		for _, line := range []string{
			"app: |/usr/local/bin/script",
			"void: :blackhole:",
			"nouser: :fail: No Such User Here",
			"sink: /dev/null",
			"# a comment",
			"   ",
			"malformed-no-colon",
		} {
			if _, ok := parseForwarderLine("psihologa.test", line, local); ok {
				t.Errorf("line %q should not be a forwarder", line)
			}
		}
	})

	t.Run("local-only alias is not an external-relevant forwarder", func(t *testing.T) {
		fwd, ok := parseForwarderLine("psihologa.test", "team: a@psihologa.test, b@psihologa.test", local)
		if !ok {
			t.Fatal("expected a forwarder record")
		}
		if fwd.ForwardOnly {
			t.Error("local-only alias must not be forward-only")
		}
		if fwd.HasExternal() {
			t.Error("local-only alias must report no external destinations")
		}
	})
}

func TestForwarderHasExternal(t *testing.T) {
	f := Forwarder{Destinations: []Destination{
		{Provider: ProviderLocal},
		{Provider: ProviderGmail},
	}}
	if !f.HasExternal() {
		t.Error("forwarder with a gmail dest must report external")
	}
	if !f.HasFreeProvider() {
		t.Error("gmail dest must count as a free provider")
	}
}
