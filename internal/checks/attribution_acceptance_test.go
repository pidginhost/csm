package checks

import (
	"context"
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestAttributionAcceptanceRow runs the Attribution acceptance row, one
// subtest per case: only a verified peer, client or destination becomes a
// target, a victim is never taken from request text, and a client behind a
// trusted proxy is never treated as contained by a firewall block.
func TestAttributionAcceptanceRow(t *testing.T) {
	const victim = "198.51.100.66"
	wpLines := func(peer, request, ua, forwarded string) []string {
		var lines []string
		for i := 0; i < 20; i++ {
			line := fmt.Sprintf(`%s - - [09/Nov/2026:12:01:%02d +0000] "%s" 200 100 "-" "%s"`, peer, i, request, ua)
			if forwarded != "" {
				line += ` "` + forwarded + `"`
			}
			lines = append(lines, line)
		}
		return lines
	}
	scanWP := func(t *testing.T, cfg *config.Config, lines []string, ip string, kind admission.Attribution) alert.Finding {
		t.Helper()
		path, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if f.SourceIP != ip || f.Attribution != kind {
			t.Fatalf("finding names %s as %s, want %s as %s", f.SourceIP, f.Attribution, ip, kind)
		}
		// Refusal can precede cursor validation, so it cannot prove the
		// scanner attached the record that actually counted.
		wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, len(lines)-1), domlogTestTime(19))
		for _, other := range findings {
			if other.SourceIP != "" && other.SourceIP != ip {
				t.Fatalf("%s names unexpected address %s", other.Check, other.SourceIP)
			}
		}
		return f
	}
	wantTarget := func(t *testing.T, f alert.Finding, ip string, producer admission.ProducerID) {
		t.Helper()
		e, target, err := mintScanFinding(t, f)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if addr, ok := target.Addr(); !ok || addr.String() != ip || e.Target() != target {
			t.Fatalf("mint input target %v, evidence target %v; want %s", target, e.Target(), ip)
		}
		if e.Producer() != producer || e.Observation().Stream != f.Observation.Stream || e.Observation().Cursor != f.Observation.Cursor || !e.ObservedAt().Equal(f.Observation.ObservedAt) {
			t.Fatalf("minted evidence %+v lost the scanner's observation %+v", e, f.Observation)
		}
	}
	proxied := &config.Config{}
	proxied.WebServer.TrustedProxies = []string{"192.0.2.10", "192.0.2.11"}

	t.Run("untrusted_xff", func(t *testing.T) {
		f := scanWP(t, proxied, wpLines("203.0.113.70", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", victim), "203.0.113.70", admission.AttributionHTTPPeer)
		wantTarget(t, f, "203.0.113.70", ProducerDomlogScan)
	})

	t.Run("trusted_multi_hop_chain", func(t *testing.T) {
		f := scanWP(t, proxied, wpLines("192.0.2.10", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", victim+", 203.0.113.71, 192.0.2.11"), "203.0.113.71", admission.AttributionTrustedHTTPChain)
		wantChainRefused(t, f)
		mock := &mockIPList{ips: make(map[string]bool)}
		old := challengeIPList
		SetChallengeIPList(mock)
		defer SetChallengeIPList(old)
		routed := *proxied
		routed.Challenge.Enabled = true
		ChallengeRouteIPs(&routed, []alert.Finding{f})
		if len(mock.ips) != 1 || len(mock.nonEscalating) != 1 || !mock.ips["203.0.113.71"] || !mock.nonEscalating["203.0.113.71"] {
			t.Fatalf("challenge list %v, non-escalating %v: a proxied client's timeout must never block it", mock.ips, mock.nonEscalating)
		}
	})

	// A chain the scan cannot trust counts against nobody, never the proxy;
	// a valid chain in the same log still reaches admission.
	nobody := func(t *testing.T, forwarded string) {
		lines := wpLines("192.0.2.10", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", forwarded)
		lines = append(lines, wpLines("192.0.2.10", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", "203.0.113.75")...)
		f := scanWP(t, proxied, lines, "203.0.113.75", admission.AttributionTrustedHTTPChain)
		wantChainRefused(t, f)
	}
	t.Run("malformed_chain", func(t *testing.T) { nobody(t, "203.0.113.72, not-an-address") })
	t.Run("all_trusted_chain", func(t *testing.T) { nobody(t, "192.0.2.11") })

	t.Run("rewritten_remote_address", func(t *testing.T) {
		withHTTPRewrite(t, activeRewrite)
		f := scanWP(t, &config.Config{}, wpLines("203.0.113.74", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", ""), "203.0.113.74", admission.AttributionHTTPPeer)
		if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseRewrittenLog {
			t.Fatalf("mint: %v, want the rewritten_log cause", err)
		}
	})

	t.Run("injected_victim_in_text", func(t *testing.T) {
		f := scanWP(t, &config.Config{}, wpLines("203.0.113.73", "POST /wp-login.php?redirect_to=http://"+victim+"/ HTTP/1.1", "Mozilla/5.0 (from "+victim+")", ""), "203.0.113.73", admission.AttributionHTTPPeer)
		wantTarget(t, f, "203.0.113.73", ProducerDomlogScan)
	})

	t.Run("outbound_destination", func(t *testing.T) {
		outboundOS(t, tcpLine("0", hexAddr(192, 0, 2, 100, 54321), hexAddr(203, 0, 113, 9, 443), "01"), testBootID)
		var c2 []alert.Finding
		for _, f := range CheckOutboundConnections(context.Background(), &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{}}, nil) {
			if f.Check == "c2_connection" {
				c2 = append(c2, f)
			}
		}
		if len(c2) != 1 || c2[0].Attribution != admission.AttributionSocketDestination {
			t.Fatalf("c2 findings %+v, want one socket destination", c2)
		}
		if c2[0].Observation.Stream != alert.SocketStream(testBootID) || c2[0].Observation.Cursor != "12345" {
			t.Fatalf("socket observation %+v, want the scanned boot and inode", c2[0].Observation)
		}
		wantTarget(t, c2[0], "203.0.113.9", ProducerConnectionScan)
		// Central intel and incidents never take a destination as an attacker.
		if AddressEvidence("c2_connection", alert.Critical) {
			t.Fatal("a destination is address evidence")
		}
	})
}
