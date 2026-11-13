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
	proxied := &config.Config{}
	proxied.WebServer.TrustedProxies = []string{"192.0.2.10", "192.0.2.11"}

	t.Run("untrusted_xff", func(t *testing.T) {
		_, findings := scanDomlogFile(t, &config.Config{}, nopBotClassifier{}, wpLines("203.0.113.70", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", victim))
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if f.SourceIP != "203.0.113.70" {
			t.Fatalf("finding names %s, want the untrusted peer", f.SourceIP)
		}
		wantPeerMints(t, f)
	})

	t.Run("trusted_multi_hop_chain", func(t *testing.T) {
		_, findings := scanDomlogFile(t, proxied, nopBotClassifier{}, wpLines("192.0.2.10", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", victim+", 203.0.113.71, 192.0.2.11"))
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if f.SourceIP != "203.0.113.71" {
			t.Fatalf("finding names %s, want the first untrusted hop from the right", f.SourceIP)
		}
		wantChainRefused(t, f)
		mock := &mockIPList{ips: make(map[string]bool)}
		old := challengeIPList
		SetChallengeIPList(mock)
		defer SetChallengeIPList(old)
		routed := *proxied
		routed.Challenge.Enabled = true
		ChallengeRouteIPs(&routed, []alert.Finding{f})
		if !mock.ips[f.SourceIP] || !mock.nonEscalating[f.SourceIP] {
			t.Fatalf("challenge list %v, non-escalating %v: a proxied client's timeout must never block it", mock.ips, mock.nonEscalating)
		}
	})

	// A chain the scan cannot trust counts against nobody, never the proxy;
	// a valid chain in the same log still reaches admission.
	nobody := func(t *testing.T, forwarded string) {
		lines := wpLines("192.0.2.10", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", forwarded)
		lines = append(lines, wpLines("192.0.2.10", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", "203.0.113.75")...)
		_, findings := scanDomlogFile(t, proxied, nopBotClassifier{}, lines)
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if f.SourceIP != "203.0.113.75" {
			t.Fatalf("finding names %s, want only the valid chain's client", f.SourceIP)
		}
		wantChainRefused(t, f)
	}
	t.Run("malformed_chain", func(t *testing.T) { nobody(t, "203.0.113.72, not-an-address") })
	t.Run("all_trusted_chain", func(t *testing.T) { nobody(t, "192.0.2.11") })

	t.Run("rewritten_remote_address", func(t *testing.T) {
		withHTTPRewrite(t, activeRewrite)
		_, findings := scanDomlogFile(t, &config.Config{}, nopBotClassifier{}, wpLines("203.0.113.74", "POST /wp-login.php HTTP/1.1", "Mozilla/5.0", ""))
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseRewrittenLog {
			t.Fatalf("mint: %v, want the rewritten_log cause", err)
		}
	})

	t.Run("injected_victim_in_text", func(t *testing.T) {
		_, findings := scanDomlogFile(t, &config.Config{}, nopBotClassifier{}, wpLines("203.0.113.73", "POST /wp-login.php?redirect_to=http://"+victim+"/ HTTP/1.1", "Mozilla/5.0 (from "+victim+")", ""))
		for _, f := range findings {
			if f.SourceIP == victim {
				t.Fatalf("%s names the address in the request text", f.Check)
			}
		}
		f := oneScanFinding(t, findings, "wp_login_bruteforce")
		_, target, err := mintScanFinding(t, f)
		if addr, _ := target.Addr(); err != nil || addr.String() != "203.0.113.73" {
			t.Fatalf("mint target %v, %v; want the peer", addr, err)
		}
	})

	t.Run("outbound_destination", func(t *testing.T) {
		data := procTCPHeader + tcpLine("0", hexAddr(192, 0, 2, 100, 54321), hexAddr(203, 0, 113, 9, 443), "01")
		withMockOS(t, &mockOS{readFile: func(path string) ([]byte, error) {
			if path == "/proc/sys/kernel/random/boot_id" {
				return []byte("4b5f6e0c-1d2e-4f3a-9b8c-7d6e5f4a3b2c\n"), nil
			}
			return []byte(data), nil
		}})
		var c2 []alert.Finding
		for _, f := range CheckOutboundConnections(context.Background(), &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{}}, nil) {
			if f.Check == "c2_connection" {
				c2 = append(c2, f)
			}
		}
		if len(c2) != 1 || c2[0].Attribution != admission.AttributionSocketDestination {
			t.Fatalf("c2 findings %+v, want one socket destination", c2)
		}
		_, in, err := AdmissionEvidence(c2[0])
		if addr, _ := in.Target.Addr(); err != nil || addr.String() != "203.0.113.9" {
			t.Fatalf("AdmissionEvidence target %v, %v; want the destination", addr, err)
		}
		// Central intel and incidents never take a destination as an attacker.
		if AddressEvidence("c2_connection", alert.Critical) {
			t.Fatal("a destination is address evidence")
		}
	})
}
