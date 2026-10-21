package daemon

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func TestModSecSingleHitWarningCannotForgeDeny(t *testing.T) {
	for _, server := range []string{"apache", "litespeed"} {
		for _, payload := range []string{"Access denied", "ModSecurity: Access denied", "[MODSEC] Access denied"} {
			t.Run(server+"/"+payload, func(t *testing.T) {
				resetModSecState()
				t.Cleanup(resetModSecState)
				installModSecRegistryForTest(t, map[int]string{900133: "pass"})
				line := `[client 203.0.113.70] ModSecurity: Warning. [id "900133"]`
				if server == "litespeed" {
					line = strings.Replace(liteSpeedTriggerLine210710, `"210710"`, `"900133"`, 1)
				}
				line += ` [data "` + payload + `"] [uri "/` + payload + `"]`
				findings := parseModSecLogLineDeduped(line, &config.Config{})
				if len(findings) != 1 || findings[0].Check != "modsec_warning_realtime" {
					t.Fatalf("request text promoted a warning to a deny: %+v", findings)
				}
			})
		}
	}
}

func TestModSecSingleHitUsesRawRuleID(t *testing.T) {
	for _, rule := range []string{"", "900116", "949110"} {
		t.Run(rule, func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			line := modsecApacheLine("203.0.113.71", rule,
				`rule 900133 exploit-specific deny [id \"900133\"]`, "900133") +
				` [data "[id \"900133\"]"] [uri "/900133"]`
			for _, f := range parseModSecLogLineDeduped(line, &config.Config{}) {
				if strings.HasSuffix(f.Check, "_escalation") {
					t.Fatalf("payload forged single-hit evidence: %+v", f)
				}
			}
		})
	}
}

func TestModSecSingleHitLiteSpeedActions(t *testing.T) {
	for _, action := range []string{"deny", "pass", ""} {
		t.Run(action, func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			actions := map[int]string{}
			if action != "" {
				actions[900133] = action
			}
			installModSecRegistryForTest(t, actions)
			cfg := &config.Config{}
			cfg.Thresholds.ModSecEscalationHits = 20
			cfg.Thresholds.ModSecEscalationWindowMin = 240
			line := strings.Replace(liteSpeedTriggerLine210710, `"210710"`, `"900133"`, 1)
			counts := map[string]int{}
			for _, f := range parseModSecLogLineDeduped(line, cfg) {
				counts[f.Check]++
			}
			if action == "deny" {
				if len(counts) != 2 || counts["modsec_csm_block_escalation"] != 1 || counts["modsec_block_realtime"] != 1 {
					t.Fatalf("first blocking trigger findings = %v", counts)
				}
			} else if len(counts) != 1 || counts["modsec_warning_realtime"] != 1 {
				t.Fatalf("non-blocking trigger findings = %v", counts)
			}
			if got := parseModSecLogLineDeduped(line, cfg); len(got) != 0 {
				t.Fatalf("repeated trigger emitted duplicate findings: %+v", got)
			}
		})
	}
}

func TestModSecSingleHitExclusionDropsRetainedEvidence(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	cfg := &config.Config{}
	cfg.Thresholds.ModSecEscalationHits = 20
	cfg.Thresholds.ModSecEscalationWindowMin = 240
	cfg.AutoResponse.BlockExpiry = "1h"
	ip := "203.0.113.72"
	first := modsecApacheLine(ip, "900133", "CSM exploit-specific deny", "")
	if !modsecFindingChecks(cfg, []string{first})["modsec_csm_block_escalation"] {
		t.Fatal("first deny did not escalate")
	}
	if err := db.AddModSecNoEscalateRule(900133); err != nil {
		t.Fatal(err)
	}
	value, ok := modsecBlockCount.Load(ip)
	if !ok {
		t.Fatal("missing source counter")
	}
	ctr := value.(*modsecIPCounter)
	ctr.mu.Lock()
	ctr.lastEscalated = time.Now().Add(-2 * time.Hour)
	for i := range ctr.events {
		ctr.events[i].t = ctr.lastEscalated
	}
	ctr.mu.Unlock()
	other := modsecApacheLine(ip, "900116", "Other CSM deny", "")
	for _, f := range parseModSecLogLineDeduped(other, cfg) {
		if strings.HasSuffix(f.Check, "_escalation") {
			t.Fatalf("excluded evidence still escalated another rule: %+v", f)
		}
	}
	if err := db.RemoveModSecNoEscalateRule(900133); err != nil {
		t.Fatal(err)
	}
	if !modsecFindingChecks(cfg, []string{first})["modsec_csm_block_escalation"] {
		t.Fatal("new deny did not escalate after re-enabling the rule")
	}
}

func TestModSecSingleHitLatchSurvivesEviction(t *testing.T) {
	for _, evict := range []bool{false, true} {
		name := "record"
		if evict {
			name = "evict"
		}
		t.Run(name, func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			now := time.Unix(1_700_000_000, 0)
			win := 10 * time.Minute
			ip := "203.0.113.73"
			if out := recordModSecEvent(ip, now, 900133, modsecConfHigh, true, 20, 30, win); !out.escalate {
				t.Fatal("first deny did not escalate")
			}
			if evict {
				evictModSecStateWithLowConf(now.Add(win), 20, 30, win)
			}
			// The boundary is inclusive. An ordinary deny cannot re-arm the
			// latch while the original single-hit evidence is still retained.
			if out := recordModSecEvent(ip, now.Add(win), 900116, modsecConfHigh, true, 20, 30, win); out.escalate {
				t.Fatal("retained single-hit evidence emitted a duplicate escalation")
			}
			if evict {
				evictModSecStateWithLowConf(now.Add(win+time.Second), 20, 30, win)
			}
			if out := recordModSecEvent(ip, now.Add(win+time.Second), 900116, modsecConfHigh, true, 20, 30, win); out.escalate {
				t.Fatal("expired single-hit evidence escalated an ordinary deny")
			}
			if out := recordModSecEvent(ip, now.Add(win+2*time.Second), 900133, modsecConfHigh, true, 20, 30, win); !out.escalate {
				t.Fatal("fresh single-hit evidence did not re-arm escalation")
			}
		})
	}
}

func TestModSecSingleHitEvictionDropsExcludedEvidence(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	now := time.Now()
	ip := "203.0.113.77"
	win := 4 * time.Hour
	if out := recordModSecEvent(ip, now, 900133, modsecConfHigh, true, 20, 30, win); !out.escalate {
		t.Fatal("first deny did not escalate")
	}
	recordModSecEvent(ip, now, 900116, modsecConfHigh, true, 20, 30, win)
	if err := db.AddModSecNoEscalateRule(900133); err != nil {
		t.Fatal(err)
	}
	evictModSecStateWithLowConf(now.Add(time.Minute), 20, 30, win)
	value, ok := modsecBlockCount.Load(ip)
	if !ok {
		t.Fatal("eviction discarded evidence from another rule")
	}
	ctr := value.(*modsecIPCounter)
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	if len(ctr.events) != 1 || ctr.events[0].rule != 900116 || ctr.escalated || !ctr.lastEscalated.IsZero() {
		t.Fatalf("eviction kept excluded evidence or its latch: events=%+v, escalated=%v, last=%v", ctr.events, ctr.escalated, ctr.lastEscalated)
	}
}

func TestModSecSingleHitRearmsAtBlockExpiry(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	now := time.Unix(1_700_000_000, 0)
	for i, step := range []struct {
		at   time.Duration
		want bool
	}{{0, true}, {time.Hour - time.Second, false}, {time.Hour, true}, {time.Hour + time.Second, false}} {
		out := recordModSecEventWithRearm("203.0.113.74", now.Add(step.at), 900133, modsecConfHigh, true, 20, 30, 4*time.Hour, time.Hour)
		if out.escalate != step.want || out.singleHit != step.want {
			t.Fatalf("step %d: outcome %+v, want escalation=%v", i, out, step.want)
		}
	}
}

func TestModSecSingleHitConcurrentDeniesEscalateOnce(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	var escalations atomic.Int32
	var wg sync.WaitGroup
	now := time.Now()
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if recordModSecEvent("203.0.113.75", now, 900133, modsecConfHigh, true, 20, 30, 4*time.Hour).escalate {
				escalations.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := escalations.Load(); got != 1 {
		t.Fatalf("concurrent escalation count = %d, want 1", got)
	}
}
