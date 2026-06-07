package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
)

// CheckLocalThreatScore's loop body exercises three distinct branches
// per record: skip-when-already-blocked, skip-when-below-threshold,
// emit-when-at-or-above-threshold. A single seeded attackdb + a
// blocked_ips.json side-file lets one test hit all three in one pass.
func TestCheckLocalThreatScoreEmitsForHighUnblocked(t *testing.T) {
	now := time.Now()

	// IP A: high score, NOT blocked → emits a finding.
	// IP B: below 70, NOT blocked → skipped (below threshold).
	// IP C: high score, blocked → skipped (alreadyBlocked wins).
	db := attackdb.NewForTest(map[string]*attackdb.IPRecord{
		"203.0.113.10": {
			IP:                    "203.0.113.10",
			ThreatScore:           85,
			EventCount:            50,
			FirstSeen:             now.Add(-20 * time.Minute),
			LastSeen:              now,
			BruteForceWindowStart: now.Add(-20 * time.Minute),
			BruteForceWindowCount: 50,
			BruteForceSustainedAt: now,
			AttackCounts: map[attackdb.AttackType]int{
				attackdb.AttackBruteForce: 50,
			},
			Accounts: map[string]int{"alice": 5, "bob": 7},
		},
		"203.0.113.20": {
			IP:          "203.0.113.20",
			ThreatScore: 40,
			EventCount:  3,
			FirstSeen:   now.Add(-10 * time.Minute),
			LastSeen:    now,
		},
		"203.0.113.30": {
			IP:                    "203.0.113.30",
			ThreatScore:           95,
			EventCount:            50,
			FirstSeen:             now.Add(-20 * time.Minute),
			LastSeen:              now,
			BruteForceWindowStart: now.Add(-20 * time.Minute),
			BruteForceWindowCount: 50,
			BruteForceSustainedAt: now,
			AttackCounts: map[attackdb.AttackType]int{
				attackdb.AttackBruteForce: 50,
			},
		},
	})
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })

	// blocked_ips.json makes loadAllBlockedIPs return {203.0.113.30: true}.
	statePath := t.TempDir()
	blocked := map[string]any{
		"ips": []map[string]any{
			{"ip": "203.0.113.30", "expires_at": now.Add(24 * time.Hour)},
		},
	}
	data, err := json.Marshal(blocked)
	if err != nil {
		t.Fatalf("marshal blocked: %v", err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "blocked_ips.json"), data, 0600); err != nil {
		t.Fatalf("write blocked_ips.json: %v", err)
	}

	cfg := &config.Config{StatePath: statePath}
	findings := CheckLocalThreatScore(context.Background(), cfg, nil)

	if len(findings) != 1 {
		t.Fatalf("findings: got %d, want 1. findings=%+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != alert.Critical {
		t.Errorf("severity: got %v, want Critical", f.Severity)
	}
	if f.Check != "local_threat_score" {
		t.Errorf("check: got %q, want local_threat_score", f.Check)
	}
	// The message must reference the high-score unblocked IP, not the
	// blocked 95-score one and not the 40-score one.
	want := "203.0.113.10"
	if !strings.Contains(f.Message, want) {
		t.Errorf("message must mention %s; got %q", want, f.Message)
	}
	if f.SourceIP != want {
		t.Errorf("SourceIP = %q, want %q", f.SourceIP, want)
	}
}

func TestCheckLocalThreatScoreBlockedTopAttackersDoNotStarveUnblocked(t *testing.T) {
	now := time.Now()
	records := map[string]*attackdb.IPRecord{
		"203.0.113.200": {
			IP:                    "203.0.113.200",
			ThreatScore:           75,
			EventCount:            50,
			FirstSeen:             now.Add(-20 * time.Minute),
			LastSeen:              now,
			BruteForceWindowStart: now.Add(-20 * time.Minute),
			BruteForceWindowCount: 50,
			BruteForceSustainedAt: now,
			AttackCounts: map[attackdb.AttackType]int{
				attackdb.AttackBruteForce: 50,
			},
			Accounts: map[string]int{"alice": 50},
		},
	}
	for i := 0; i < 60; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		records[ip] = &attackdb.IPRecord{
			IP:          ip,
			ThreatScore: 100,
			EventCount:  100,
			FirstSeen:   now.Add(-1 * time.Hour),
			LastSeen:    now,
			AttackCounts: map[attackdb.AttackType]int{
				attackdb.AttackC2:       1,
				attackdb.AttackWebshell: 1,
			},
			Accounts: map[string]int{},
		}
	}

	db := attackdb.NewForTest(records)
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })

	statePath := t.TempDir()
	var blocked []map[string]any
	for i := 0; i < 60; i++ {
		blocked = append(blocked, map[string]any{
			"ip":         fmt.Sprintf("203.0.113.%d", i+1),
			"expires_at": now.Add(24 * time.Hour),
		})
	}
	data, err := json.Marshal(map[string]any{"ips": blocked})
	if err != nil {
		t.Fatalf("marshal blocked: %v", err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "blocked_ips.json"), data, 0600); err != nil {
		t.Fatalf("write blocked_ips.json: %v", err)
	}

	findings := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: statePath}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings: got %d, want 1. findings=%+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "203.0.113.200") {
		t.Fatalf("finding message = %q, want unblocked attacker", findings[0].Message)
	}
}
