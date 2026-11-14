package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// A block admission takes for an address ends every legacy block of that
// address in the same scan: a queued retry, a finding admission could not
// take, and a mail spray finding. The address then has one enforcer.
// Another address keeps its legacy work.
func TestScanYieldsAnAddressAdmissionTakes(t *testing.T) {
	const ip, other = "203.0.113.98", "203.0.113.99"
	taken := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "WordPress brute force from " + ip}
	kept := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "SMTP brute force from " + ip}
	spray := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "SMTP password spray from " + ip, BlockTTL: 720 * time.Hour}
	for _, tc := range []struct {
		name     string
		pending  []pendingIP
		findings []alert.Finding
	}{
		{"kept finding first", nil, []alert.Finding{kept, taken}},
		{"taken finding first", nil, []alert.Finding{taken, kept}},
		{"spray finding", nil, []alert.Finding{spray, taken}},
		{"queued retry", []pendingIP{{IP: ip, Check: "smtp_bruteforce", Severity: alert.Critical, Reason: "queued"}}, []alert.Finding{taken}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			pending := append([]pendingIP{{IP: other, Check: "smtp_bruteforce", Severity: alert.Critical, Reason: "queued", QueuedAt: time.Now()}}, tc.pending...)
			for i := range pending {
				pending[i].QueuedAt = time.Now()
			}
			saveBlockState(cfg.StatePath, &blockState{Pending: pending})
			a := withAdmission(t)
			a.executes = true
			a.mintErrs = map[string]error{"smtp_bruteforce": attributionRefusal(admission.CauseNoObservation)}
			findings := make([]alert.Finding, len(tc.findings))
			for i, f := range tc.findings {
				f.Timestamp = time.Now()
				findings[i] = f
			}
			lost := func() (n uint64) {
				for _, q := range []string{"pending", "candidates"} {
					n += AutoBlockQueueStatuses(time.Now())[q].DroppedTotal
				}
				return n
			}
			before := lost()
			AutoBlockIPs(cfg, findings)
			if dropped := lost() - before; dropped != 0 {
				t.Errorf("the scan counted %d lost retries for an address admission took", dropped)
			}
			state := loadBlockState(cfg.StatePath)
			if len(blocker.calls) != 1 || blocker.calls[0].ip != other {
				t.Fatalf("engine calls = %+v, want only the legacy block of %s", blocker.calls, other)
			}
			if len(state.IPs) != 1 || state.IPs[0].IP != other || len(state.Pending) != 0 || state.BlocksThisHour != 1 || state.LoginSprayBlocksThisHour != 0 {
				t.Fatalf("legacy state = %+v, want only %s tracked and charged", state, other)
			}
		})
	}
}

// A finding admission refuses as a CDN edge or a proxied client is not
// enforced by admission, so the address keeps the legacy block another
// finding asks for.
func TestScanKeepsLegacyBlocksBesideAnUncontainedRefusal(t *testing.T) {
	const ip = "203.0.113.94"
	for _, cause := range []admission.Cause{admission.CauseProxyPeer, admission.CauseUnreachable} {
		t.Run(cause.String(), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = true
			a.mintErrs = map[string]error{
				"wp_login_bruteforce": attributionRefusal(cause),
				"smtp_bruteforce":     attributionRefusal(admission.CauseNoObservation),
			}
			AutoBlockIPs(cfg, []alert.Finding{
				{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "WordPress brute force from " + ip, Timestamp: time.Now()},
				{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "SMTP brute force from " + ip, Timestamp: time.Now()},
			})
			if len(blocker.calls) != 1 || blocker.calls[0].ip != ip {
				t.Fatalf("engine calls = %+v, want the legacy block of %s", blocker.calls, ip)
			}
		})
	}
}

// A synchronous ingress refusal cannot cancel a retry or another finding
// for the address, including an IPv6 address admission cannot contain.
func TestScanKeepsLegacyAfterSynchronousRefusal(t *testing.T) {
	for _, reason := range []admission.Reason{
		admission.ReasonQueueOverflow, admission.ReasonEngineUnavailable,
		admission.ReasonStale, admission.ReasonInvalid,
		admission.ReasonUnsupportedContainment,
	} {
		t.Run(reason.String(), func(t *testing.T) {
			ip := "203.0.113.95"
			if reason == admission.ReasonUnsupportedContainment {
				ip = "2001:db8::95"
			}
			for _, retry := range []bool{false, true} {
				cfg := pendingTestConfig(t)
				blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
				applyBlockTestSetup(t, blocker)
				a := withAdmission(t)
				a.executes = true
				a.respondErr = &admission.Error{Reason: reason}
				a.mintErrs = map[string]error{"smtp_bruteforce": attributionRefusal(admission.CauseNoObservation)}
				kept := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: ip, Timestamp: time.Now()}
				refused := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Timestamp: time.Now()}
				findings := []alert.Finding{kept, refused, kept}
				if retry {
					saveBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{IP: ip, Check: kept.Check, Severity: kept.Severity, QueuedAt: time.Now()}}})
					findings = []alert.Finding{refused}
				}
				AutoBlockIPs(cfg, findings)
				if len(blocker.calls) != 1 || blocker.calls[0].ip != ip {
					t.Fatalf("refusal %s, retry %v: calls %+v, want one legacy block of %s", reason, retry, blocker.calls, ip)
				}
			}
		})
	}
}
