package main

import (
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/stalwartsetup"
)

func TestStalwartAddressListProbeGates(t *testing.T) {
	for _, mode := range []string{"enforce", "observe", "foreign rule", "filter off", "filter unknown"} {
		t.Run(mode, func(t *testing.T) {
			h := newSetupHarness(t)
			h.api.rule = &stalwartapi.SpamRule{Type: "Any", Enabled: true, Arms: stalwartsetup.AddressListArms(), Else: "false"}
			h.api.probe.Tags = []string{"CSM_IP_CANARY"}
			wantProbes := 1
			switch mode {
			case "observe":
				h.cfg.Mode = config.ModeObserve
			case "foreign rule":
				h.api.rule.Type = "Connection"
			case "filter off":
				h.api.spam.Enabled = false
				wantProbes = 0
			case "filter unknown":
				h.api.spamErr = errors.New("unavailable")
				wantProbes = 0
			}
			h.doctorIn = stalwartInputs(h.cfg, nil, nil, nil)
			checks := h.doctorChecks()
			if len(h.api.probes) != wantProbes || len(h.api.writes) != 0 {
				t.Fatalf("probes = %d, writes = %q; want %d probes and no writes", len(h.api.probes), h.api.writes, wantProbes)
			}
			for _, name := range []string{"stalwart blocklists", "stalwart address list match"} {
				want := wantProbes == 1
				if name == "stalwart address list match" {
					want = mode == "enforce"
				}
				found := slices.ContainsFunc(checks, func(c DoctorCheck) bool { return c.Name == name })
				if found != want {
					t.Fatalf("%s present = %v, want %v", name, found, want)
				}
				if want && stalwartCheckNamed(t, checks, name).Status != "ok" {
					t.Fatalf("%s did not use the successful shared probe", name)
				}
			}
		})
	}
}

func TestStalwartSharedProbeErrorOutputSafety(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.api.rule = &stalwartapi.SpamRule{Type: "Any", Enabled: true, Arms: stalwartsetup.AddressListArms(), Else: "false"}
	password := setupTestPassword + "/?\n\x1b"
	h.env["STALWART_PASSWORD"] = password
	secrets := []string{
		password, url.QueryEscape(password), url.PathEscape(password),
		base64.StdEncoding.EncodeToString([]byte("admin:" + password)),
		doctorTestKey, base64.StdEncoding.EncodeToString([]byte(":" + doctorTestKey)),
	}
	h.api.probeErr = errors.New(strings.Join(secrets, " ") + "\x1b[2J\r\n\u202e" + strings.Repeat("x", 1024))
	checks := h.doctorChecks()
	if len(h.api.probes) != 1 || len(h.api.writes) != 0 {
		t.Fatal("expected one shared probe and no writes")
	}
	for _, name := range []string{"stalwart blocklists", "stalwart address list match"} {
		c := stalwartCheckNamed(t, checks, name)
		if c.Status != "warn" || !strings.HasPrefix(c.Message, "Could not test ") || c.Fix != "" {
			t.Fatalf("%s must report an inconclusive probe without a fix", name)
		}
		text := c.Name + c.Message + c.Fix
		for _, secret := range append(secrets, setupTestPassword) {
			if strings.Contains(text, secret) {
				t.Fatalf("%s exposed a credential", name)
			}
		}
		if strings.Count(c.Message, "[redacted]") != len(secrets) {
			t.Fatalf("%s did not redact all credential forms before formatting", name)
		}
		if len(c.Message) > 640 || !strings.HasSuffix(c.Message, "...") {
			t.Fatalf("%s did not bound the server error", name)
		}
		for _, r := range text {
			if r < 32 || r > 126 {
				t.Fatalf("%s contains a terminal control or non-ASCII character", name)
			}
		}
	}
}

func TestStalwartSetupObserveStillApplies(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.cfg.Mode = config.ModeObserve
	if !stalwartSetupInputs(h.cfg, h.deps).Observe {
		t.Fatal("setup did not receive observe mode")
	}
	code, out := h.run()
	if code != 0 {
		t.Fatalf("setup exit = %d, output = %q", code, out)
	}
	if !slices.Equal(h.api.writes, settingsSetupWrites()) {
		t.Fatalf("observe setup writes = %q, want %q", h.api.writes, settingsSetupWrites())
	}
	if h.api.rule == nil || len(h.api.tags) == 0 || len(h.api.probes) != 0 {
		t.Fatal("observe setup must create the address list rule and tags without a spam probe")
	}
}
