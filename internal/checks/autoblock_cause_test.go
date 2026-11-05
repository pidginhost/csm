package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func noticeWith(actions []alert.Finding, prefix string) *alert.Finding {
	for i := range actions {
		if actions[i].Check == "auto_block" && strings.HasPrefix(actions[i].Message, prefix) {
			return &actions[i]
		}
	}
	return nil
}

func wantCause(t *testing.T, actions []alert.Finding, prefix string, want alert.Cause) {
	t.Helper()
	n := noticeWith(actions, prefix)
	if n == nil {
		t.Fatalf("no %q notice in %+v", prefix, actions)
	}
	if n.Cause == nil || *n.Cause != want {
		t.Fatalf("%s cause = %+v, want %+v", n.Message, n.Cause, want)
	}
}

// Every block notice names the finding that caused it, so the known-customer
// alert can say which check blocked the address.
func TestAutoBlockFindingCarriesCause(t *testing.T) {
	t.Run("address block and permanent promotion", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		cfg.AutoResponse.PermBlock = true
		cfg.AutoResponse.PermBlockCount = config.MinBlockEscalationCount
		applyBlockTestSetup(t, &recordingIPBlocker{})
		first := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: "192.0.2.20", Message: "SMTP brute force from 192.0.2.20"}
		wantCause(t, AutoBlockIPs(cfg, []alert.Finding{first}), "AUTO-BLOCK: ", alert.CauseOf(first))
		second := alert.Finding{Check: "mail_bruteforce", Severity: alert.Critical, SourceIP: "192.0.2.20", Message: "Mail auth brute force from 192.0.2.20"}
		actions := AutoBlockIPs(cfg, []alert.Finding{second})
		wantCause(t, actions, "AUTO-BLOCK: ", alert.CauseOf(second))
		wantCause(t, actions, "AUTO-PERMBLOCK: ", alert.CauseOf(second))
	})
	t.Run("dry-run address verdict", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		applyBlockTestSetup(t, &outcomeStubBlocker{outcome: firewall.BlockOutcomeDryRun})
		f := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: "192.0.2.21", Message: "SMTP brute force from 192.0.2.21"}
		wantCause(t, AutoBlockIPs(cfg, []alert.Finding{f}), "AUTO-BLOCK [dry-run]: ", alert.CauseOf(f))
	})
	t.Run("mail subnet", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		applyBlockTestSetup(t, &recordingIPBlocker{})
		f := alert.Finding{Check: "mail_subnet_spray", Severity: alert.Critical, Message: "mail auth spray from 203.0.113.0/24"}
		wantCause(t, AutoBlockIPs(cfg, []alert.Finding{f}), "AUTO-BLOCK-SUBNET: ", alert.CauseOf(f))
	})
	t.Run("asn crawl subnet", func(t *testing.T) {
		cfg := pendingTestConfig(t)
		applyBlockTestSetup(t, &recordingIPBlocker{})
		f := alert.Finding{Check: "http_asn_crawl", Severity: alert.Critical, Message: "crawl", CIDRs: []string{"198.51.100.0/24"}}
		wantCause(t, AutoBlockIPs(cfg, []alert.Finding{f}), "AUTO-BLOCK-SUBNET: ", alert.CauseOf(f))
	})
	t.Run("dry-run subnet verdict", func(t *testing.T) {
		cfg := dryRunSubnetConfig(t)
		applyBlockTestSetup(t, &subnetRecorder{})
		f := alert.Finding{Check: "mail_subnet_spray", Severity: alert.Critical, Message: "mail auth spray from 203.0.113.0/24"}
		wantCause(t, AutoBlockIPs(cfg, []alert.Finding{f}), "AUTO-BLOCK-SUBNET [dry-run]: ", alert.CauseOf(f))
	})
	t.Run("netblock", func(t *testing.T) {
		cfg := netblockWindowConfig(t)
		blocker := newNetblockBlocker()
		swapBlocker(t, blocker)
		var actions []alert.Finding
		var last alert.Finding
		for _, ip := range []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"} {
			last = bruteForceFrom(ip)[0]
			actions = AutoBlockIPs(cfg, []alert.Finding{last})
			delete(blocker.live, ip)
		}
		// The netblock answers the blocks that counted; the newest one
		// names it.
		wantCause(t, actions, "AUTO-NETBLOCK: ", alert.Cause{FindingID: alert.FindingID(last)})
	})
}
