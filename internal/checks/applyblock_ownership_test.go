package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/platform"
)

// A derived block admission takes or refuses ends in ApplyBlock before the
// engine: no kernel call, no tracker row, and a sentinel the callers treat
// as an expected outcome. A root the web server may have rewritten still
// gets the legacy block.
func TestApplyBlockLeavesTakenBlocksToAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		executes bool
		rootErr  error
		legacy   bool
	}{
		{"taken", true, nil, false},
		{"previewing", false, nil, true},
		{"unobserved root", true, attributionRefusal(admission.CauseNoObservation), false},
		{"rewritten root", true, attributionRefusal(admission.CauseRewrittenLog), true},
		{"proxied client", true, attributionRefusal(admission.CauseUnreachable), false},
		{"proxy edge", true, attributionRefusal(admission.CauseProxyPeer), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = tc.executes
			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.97", EngineReason: "CSM challenge-timeout: wp brute", Reason: "challenge timeout after wp brute",
				TTL: time.Hour, Source: BlockSourceChallenge, Entry: admission.EntryChallengeTimeout,
				Check: "wp_login_bruteforce", RootFinding: alert.Finding{Check: "wp_login_bruteforce"}, RootErr: tc.rootErr,
			})
			if tc.legacy {
				if err != nil || len(blocker.calls) != 1 {
					t.Fatalf("ApplyBlock = %v, engine calls %+v; want the legacy block", err, blocker.calls)
				}
				return
			}
			if !errors.Is(err, ErrBlockTakenByAdmission) || res.Outcome != firewall.BlockOutcomeNoop || len(blocker.calls) != 0 || len(loadBlockState(cfg.StatePath).IPs) != 0 {
				t.Fatalf("ApplyBlock = %+v, %v, engine calls %+v; want the block left to admission", res, err, blocker.calls)
			}
		})
	}
}

// A long-lived derived block stays outside admission even when its local
// evidence was refused. The legacy engine must receive the full lifetime.
func TestLongDerivedBlockKeepsLegacyLifetimeAfterRefusal(t *testing.T) {
	for _, cause := range []admission.Cause{admission.CauseNoObservation, admission.CauseRewrittenLog, admission.CauseKindNotAllowed} {
		t.Run(cause.String(), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.BlockExpiry = "1h"
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = true
			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.97", TTL: 24 * time.Hour, Source: BlockSourceCentral, Entry: admission.EntryCentral,
				RootFinding: alert.Finding{Check: "wp_login_bruteforce"}, RootErr: attributionRefusal(cause),
			})
			if err != nil || res.Outcome != firewall.BlockOutcomeLive || len(blocker.calls) != 1 || blocker.calls[0].timeout != 24*time.Hour {
				t.Fatalf("long derived block: result %+v, err %v, calls %+v", res, err, blocker.calls)
			}
			if len(a.responses()) != 0 || len(a.refused) != 0 {
				t.Fatalf("legacy-only block reached admission: responses %+v, refusals %v", a.responses(), a.refused)
			}
		})
	}
}

// A long-lived derived block of an address LiteSpeed rewrote is refused for
// good: any local user can choose that address. Elsewhere the rewritten
// root keeps its legacy lifetime.
func TestLongDerivedBlockOfALiteSpeedRewriteIsRefused(t *testing.T) {
	for _, tc := range []struct {
		server platform.WebServer
		legacy bool
	}{
		{platform.WSLiteSpeed, false},
		{platform.WSApache, true},
	} {
		t.Run(string(tc.server), func(t *testing.T) {
			withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: tc.server})
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.BlockExpiry = "1h"
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = true
			_, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.97", TTL: 7 * 24 * time.Hour, Source: BlockSourceIncident, Entry: admission.EntryIncident,
				RootFinding: alert.Finding{Check: "wp_login_bruteforce"}, RootErr: attributionRefusal(admission.CauseRewrittenLog),
			})
			if tc.legacy {
				if err != nil || len(blocker.calls) != 1 || len(a.refused) != 0 {
					t.Fatalf("err %v, calls %+v, refusals %v; want the legacy block", err, blocker.calls, a.refused)
				}
				return
			}
			if !errors.Is(err, ErrBlockTakenByAdmission) || len(blocker.calls) != 0 || len(a.refused) != 1 {
				t.Fatalf("err %v, calls %+v, refusals %v; want one counted refusal and no block", err, blocker.calls, a.refused)
			}
		})
	}
}

// Incident retries eventually request a permanent block. Its lifetime
// must not turn a refused LiteSpeed address into a firewall target.
func TestPermanentDerivedBlockKeepsLiteSpeedRefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rewrite HTTPRewrite
		refuse  bool
	}{
		{"litespeed active", HTTPRewrite{State: RewriteActive, Server: platform.WSLiteSpeed}, true},
		{"litespeed unknown", HTTPRewrite{State: RewriteUnknown, Server: platform.WSLiteSpeed}, true},
		{"apache", HTTPRewrite{State: RewriteActive, Server: platform.WSApache}, false},
		{"nginx", HTTPRewrite{State: RewriteActive, Server: platform.WSNginx}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHTTPRewrite(t, tc.rewrite)
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = true
			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.97", TTL: 0, Source: BlockSourceIncident, Entry: admission.EntryIncident,
				RootFinding: alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.97"},
				RootErr:     attributionRefusal(admission.CauseRewrittenLog),
			})
			if tc.refuse {
				if !errors.Is(err, ErrBlockTakenByAdmission) || res.Outcome != firewall.BlockOutcomeNoop || len(blocker.calls) != 0 || len(res.Findings) != 0 || len(loadBlockState(cfg.StatePath).IPs) != 0 {
					t.Fatalf("refused permanent block: result %+v, err %v, calls %+v", res, err, blocker.calls)
				}
				if len(a.refused) != 1 || len(a.responses()) != 0 {
					t.Fatalf("refusals = %v, responses = %+v, want one preserved refusal", a.refused, a.responses())
				}
				return
			}
			if err != nil || res.Outcome != firewall.BlockOutcomeLive || len(blocker.calls) != 1 || blocker.calls[0].timeout != 0 || len(a.refused) != 0 {
				t.Fatalf("legacy permanent block: result %+v, err %v, calls %+v, refusals %v", res, err, blocker.calls, a.refused)
			}
		})
	}
}

// A preserved forgery refusal stays final even if an incident escalates
// its block lifetime or the web server's rewrite configuration changes.
func TestForgedClientRefusalSurvivesBlockLifetime(t *testing.T) {
	for _, rw := range []HTTPRewrite{
		{State: RewriteActive, Server: platform.WSApache},
		{State: RewriteActive, Server: platform.WSLiteSpeed},
		{State: RewriteActive, Server: platform.WSNginx},
		{State: RewriteNone},
	} {
		for _, ttl := range []time.Duration{0, time.Hour, 7 * 24 * time.Hour} {
			t.Run(string(rw.Server)+"/"+ttl.String(), func(t *testing.T) {
				withHTTPRewrite(t, rw)
				cfg := pendingTestConfig(t)
				cfg.AutoResponse.BlockExpiry = "1h"
				blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
				applyBlockTestSetup(t, blocker)
				a := withAdmission(t)
				a.executes = true
				res, err := ApplyBlock(cfg, ApplyBlockRequest{
					IP: "203.0.113.97", TTL: ttl, Source: BlockSourceIncident, Entry: admission.EntryIncident,
					RootFinding: alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.97"},
					RootErr:     attributionRefusal(admission.CauseForgedClient),
				})
				if !errors.Is(err, ErrBlockTakenByAdmission) || res.Outcome != firewall.BlockOutcomeNoop ||
					len(blocker.calls) != 0 || len(res.Findings) != 0 || len(loadBlockState(cfg.StatePath).IPs) != 0 {
					t.Fatalf("forged block: result %+v, err %v, calls %+v; want no block or tracker state", res, err, blocker.calls)
				}
				if len(a.refused) != 1 || len(a.responses()) != 0 {
					t.Fatalf("refusals = %v, responses = %+v; want one preserved refusal", a.refused, a.responses())
				}
			})
		}
	}
}
