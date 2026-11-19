package admissionowner

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
)

func blockMetric(t *testing.T, name string) float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if value, ok := strings.CutPrefix(line, name+" "); ok {
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	return 0
}

// Live execution bypasses the legacy chokepoint, but must keep its block
// aliveness counters and the challenge panel's escalation count current.
func TestLiveBlocksKeepOutcomeMetrics(t *testing.T) {
	for _, tc := range []struct {
		entry  admission.Entry
		source string
	}{
		{admission.EntryScan, "scan"},
		{admission.EntryChallengeTimeout, "challenge"},
		{admission.EntryIncident, "incident"},
		{admission.EntryIncidentSpray, "incident"},
		{admission.EntryCentral, "central_intel"},
	} {
		t.Run(tc.entry.String(), func(t *testing.T) {
			p := blockMetricsRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			consumer := &appliedSink{}
			consumer.set(errors.New("consumer unavailable"))
			opts := executeOptions(f, blocks)
			opts.Applied = consumer.consume
			o := f.start(opts)
			heldMono(t, o)
			const ip = "192.0.2.10"
			target, err := admission.CanonicalAddress(ip, admission.Caps{IPv6: true})
			if err != nil {
				t.Fatal(err)
			}
			id, _ := queuedThrough(t, o, p, f.host, admission.SeverityCritical, ip, admission.KindBlockIP, target, tc.entry)
			names := []string{fmt.Sprintf(`csm_firewall_block_outcome_total{outcome="live",source=%q}`, tc.source), `csm_auto_response_actions_total{action="block"}`}
			if tc.entry == admission.EntryChallengeTimeout {
				names = append(names, `csm_challenge_escalated_total{outcome="live"}`)
			}
			before := make([]float64, len(names))
			for i, name := range names {
				before[i] = blockMetric(t, name)
			}
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateVerified {
				t.Fatalf("block = %+v", c)
			}
			// Delivery retries and idle turns must not count the apply again.
			if err := o.do(o.deliverAudit); err == nil {
				t.Fatal("failed consumer reported delivery")
			}
			consumer.set(nil)
			for range 2 {
				if err := o.do(o.deliverAudit); err != nil {
					t.Fatal(err)
				}
				turn(t, o)
			}
			for i, name := range names {
				if got := blockMetric(t, name) - before[i]; got != 1 {
					t.Errorf("%s delta = %v, want 1", name, got)
				}
			}
		})
	}
}

func TestLiveBlockFailuresKeepOutcomeMetrics(t *testing.T) {
	for _, mode := range []string{"batch error", "member error", "unknown", "short reply"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			switch mode {
			case "batch error":
				blocks.applyErr = errors.New("apply unavailable")
			case "member error":
				blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Err: errors.New("rejected")}
			case "unknown":
				blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockUnknown}
			case "short reply":
				blocks.shortResults = true
			}
			o := f.start(executeOptions(f, blocks))
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			const failures = `csm_firewall_block_outcome_total{outcome="error",source="scan"}`
			const live = `csm_firewall_block_outcome_total{outcome="live",source="scan"}`
			before, liveBefore := blockMetric(t, failures), blockMetric(t, live)
			turn(t, o)
			if _, applied := blocks.calls(); len(applied) != 1 {
				t.Fatalf("applies = %d", len(applied))
			}
			if got := blockMetric(t, failures) - before; got != 1 {
				t.Errorf("error delta = %v, want 1", got)
			}
			if got := blockMetric(t, live); got != liveBefore {
				t.Errorf("failed block counted as live")
			}
		})
	}
}

// These entries all answer the same local root; only the response source
// differs, so the test can check the source labels independently of parsers.
func blockMetricsRegistry(t *testing.T) *admission.Producer {
	t.Helper()
	reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
		return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal, Attribution: admission.Attributions(admission.AttributionPeer)}, check == "ssh_brute"
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"}, Attribution: admission.Attributions(admission.AttributionPeer)})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []admission.Entry{admission.EntryChallengeTimeout, admission.EntryIncident, admission.EntryIncidentSpray, admission.EntryCentral} {
		if _, err := reg.Register(admission.ProducerSpec{ID: admission.ProducerID(entry.String()), Entry: entry, Observation: admission.ObservationEventSeq, Checks: []string{"ssh_brute"}}); err != nil {
			t.Fatal(err)
		}
	}
	reg.Seal()
	prev := buildRegistry
	buildRegistry = func() (*admission.Registry, map[admission.ProducerID]*admission.Producer, error) {
		return reg, map[admission.ProducerID]*admission.Producer{p.ID(): p}, nil
	}
	t.Cleanup(func() { buildRegistry = prev })
	return p
}

// Refusals that end live work keep the legacy outcome labels. Deferrals
// and forecasts have not attempted a live block and leave them alone.
func TestLiveBlockRefusalMetrics(t *testing.T) {
	for _, tc := range []struct {
		refusal firewall.BlockRefusal
		outcome string
		want    float64
	}{
		{firewall.BlockRefusedProtected, "protected", 1},
		{firewall.BlockRefusedAllowed, "allowlisted", 1},
		{firewall.BlockRefusedExisting, "noop", 1},
		{firewall.BlockRefusedPending, "noop", 0},
	} {
		t.Run(string(tc.refusal), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.refuse["192.0.2.10"] = tc.refusal
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			name := fmt.Sprintf(`csm_firewall_block_outcome_total{outcome=%q,source="scan"}`, tc.outcome)
			before := blockMetric(t, name)
			turn(t, o)
			mono.advance(batchEvery)
			turn(t, o)
			if _, applies := blocks.calls(); len(applies) != 0 {
				t.Fatal("refusal reached apply")
			}
			if got := blockMetric(t, name) - before; got != tc.want {
				t.Errorf("delta = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPanelAllowMetricsExcludeForecasts(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(fmt.Sprint(dry), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			panel := newFakePanel("allow")
			policy := verdictPolicy(1, panel)
			policy.DryRun = dry
			blocks := newFakeBlocks()
			o, _, _ := policyOwner(t, f, blocks, policy)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			const name = `csm_firewall_block_outcome_total{outcome="allowed",source="scan"}`
			before := blockMetric(t, name)
			turn(t, o)
			readyAnswers(t, o, 1)
			turn(t, o)
			if c := candidate(t, o, id); c.Reason != admission.ReasonVerdictAllow {
				t.Fatalf("candidate = %+v", c)
			}
			want := float64(1)
			if dry {
				want = 0
			}
			if got := blockMetric(t, name) - before; got != want {
				t.Errorf("delta = %v, want %v", got, want)
			}
		})
	}
}
