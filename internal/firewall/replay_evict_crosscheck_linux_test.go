//go:build linux

package firewall

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/responsereplay"
)

// The replay model's eviction rule is checked against the engine's here: the
// pure victim choice on arbitrary state, and victim choice after the normal
// expiry pass, through the model's own step.

var evictNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func toReplayEntries(entries []BlockedEntry) []responsereplay.TempEntry {
	out := make([]responsereplay.TempEntry, len(entries))
	for i, e := range entries {
		out[i] = responsereplay.TempEntry{IP: e.IP, BlockedAt: e.BlockedAt, ExpiresAt: e.ExpiresAt}
	}
	return out
}

func entry(ip string, expiresIn time.Duration) BlockedEntry {
	return BlockedEntry{IP: ip, BlockedAt: evictNow.Add(-time.Hour), ExpiresAt: evictNow.Add(expiresIn)}
}

func permanentEntry(ip string) BlockedEntry {
	return BlockedEntry{IP: ip, BlockedAt: evictNow.Add(-time.Hour)}
}

func TestReplayEviction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []BlockedEntry
		exclude string
		want    string
	}{
		{"empty", nil, "203.0.113.1", ""},
		{"permanent only", []BlockedEntry{permanentEntry("198.51.100.1")}, "", ""},
		{"distinct expiry", []BlockedEntry{entry("198.51.100.1", 3*time.Minute), entry("198.51.100.2", time.Minute), entry("198.51.100.3", 2*time.Minute)}, "", "198.51.100.2"},
		{"ties keep insertion order", []BlockedEntry{entry("198.51.100.1", time.Minute), entry("198.51.100.2", time.Minute)}, "", "198.51.100.1"},
		{"expired entries still count", []BlockedEntry{entry("198.51.100.1", time.Minute), entry("198.51.100.2", -5*time.Minute)}, "", "198.51.100.2"},
		{"excluded first victim", []BlockedEntry{entry("198.51.100.1", time.Minute), entry("198.51.100.2", 2*time.Minute)}, "198.51.100.1", "198.51.100.2"},
		{"duplicate excluded rows", []BlockedEntry{entry("198.51.100.1", time.Minute), entry("198.51.100.1", time.Minute), entry("198.51.100.2", 3*time.Minute)}, "198.51.100.1", "198.51.100.2"},
		{"mapped exclusion", []BlockedEntry{entry("203.0.113.1", time.Minute), entry("198.51.100.2", 2*time.Minute)}, "::ffff:203.0.113.1", "198.51.100.2"},
		{"mapped entry", []BlockedEntry{entry("::ffff:203.0.113.1", time.Minute), entry("198.51.100.2", 2*time.Minute)}, "203.0.113.1", "198.51.100.2"},
		{"ipv6 spellings", []BlockedEntry{entry("2001:db8::1", time.Minute), entry("2001:db8::2", 2*time.Minute)}, "2001:DB8:0::1", "2001:db8::2"},
		{"only the excluded", []BlockedEntry{entry("198.51.100.1", time.Minute)}, "198.51.100.1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			real, realOK := soonestExpiringTempIP(FirewallState{Blocked: tc.entries}, tc.exclude)
			model, modelOK := responsereplay.EvictionVictim(toReplayEntries(tc.entries), tc.exclude)
			if real != tc.want || realOK != (tc.want != "") {
				t.Fatalf("fixture expectation wrong: engine chose %q %v", real, realOK)
			}
			if model != real || modelOK != realOK {
				t.Fatalf("engine %q %v, model %q %v", real, realOK, model, modelOK)
			}
		})
	}

	// Random states over a small address pool, so ties, aliases, permanent,
	// expired and excluded entries all recur. Deterministic cases above are
	// the boundary proof; this checks the rules compose the same way.
	pool := []string{"203.0.113.1", "::ffff:203.0.113.1", "203.0.113.2", "2001:db8::1", "2001:DB8:0::1", "2001:db8::2", "198.51.100.9"}
	rng := rand.New(rand.NewSource(0x519)) // #nosec G404 -- reproducible test corpus
	hits := map[string]int{}
	for i := range 500 {
		var entries []BlockedEntry
		for range rng.Intn(21) {
			ip := pool[rng.Intn(len(pool))]
			if rng.Intn(5) == 0 {
				entries = append(entries, permanentEntry(ip))
				hits["permanent"]++
				continue
			}
			minutes := rng.Intn(10) - 5
			entries = append(entries, entry(ip, time.Duration(minutes)*time.Minute))
			if minutes < 0 {
				hits["expired"]++
			}
		}
		exclude := ""
		if rng.Intn(4) != 0 {
			exclude = pool[rng.Intn(len(pool))]
		}
		real, realOK := soonestExpiringTempIP(FirewallState{Blocked: entries}, exclude)
		model, modelOK := responsereplay.EvictionVictim(toReplayEntries(entries), exclude)
		if model != real || modelOK != realOK {
			t.Fatalf("state %d: engine %q %v, model %q %v (entries %+v, exclude %q)", i, real, realOK, model, modelOK, entries, exclude)
		}
		switch {
		case len(entries) == 0:
			hits["empty"]++
		case !realOK:
			hits["no victim"]++
		}
		earliest := map[string]bool{}
		var soonest time.Time
		for _, e := range entries {
			if exclude != "" && e.IP != exclude && sameIPString(e.IP, exclude) {
				hits["alias excluded"]++
			}
			if e.ExpiresAt.IsZero() || sameIPString(e.IP, exclude) {
				continue
			}
			switch {
			case len(earliest) == 0 || e.ExpiresAt.Before(soonest):
				soonest, earliest = e.ExpiresAt, map[string]bool{e.IP: true}
			case e.ExpiresAt.Equal(soonest):
				earliest[e.IP] = true
			}
		}
		// Only distinct addresses sharing the earliest expiry make insertion
		// order decide the victim.
		if len(earliest) > 1 {
			hits["tie"]++
		}
	}
	for _, category := range []string{"empty", "permanent", "expired", "no victim", "alias excluded", "tie"} {
		if hits[category] == 0 {
			t.Errorf("random corpus never produced %q", category)
		}
	}
}

// Admission normally sees state after the expiry pass. The model runs its
// own expiry and then the exported rule, so a full temporary limit evicts
// the same victim the engine would.
func TestReplayEvictionAfterExpiry(t *testing.T) {
	const candidate = "203.0.113.200"
	for _, tc := range []struct {
		name    string
		entries []BlockedEntry
		changed bool
	}{
		{"expires exactly now", []BlockedEntry{entry("198.51.100.1", 0), entry("198.51.100.2", time.Minute), entry("198.51.100.3", 2*time.Minute)}, true},
		{"all expired", []BlockedEntry{entry("198.51.100.1", -time.Minute), entry("198.51.100.2", -2*time.Minute)}, true},
		{"full limit with ties", []BlockedEntry{permanentEntry("198.51.100.9"), entry("198.51.100.1", time.Minute), entry("198.51.100.2", time.Minute), entry("198.51.100.3", time.Minute)}, false},
		{"expired soonest", []BlockedEntry{entry("198.51.100.1", -time.Minute), entry("198.51.100.2", 3*time.Minute), entry("198.51.100.3", time.Minute)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := toReplayEntries(tc.entries)
			pruned, changed := pruneBlocked(tc.entries, evictNow)
			if changed != tc.changed {
				t.Fatalf("prune changed = %v", changed)
			}
			temporary := 0
			for _, e := range pruned {
				if !e.ExpiresAt.IsZero() {
					temporary++
				}
			}
			want, wantOK := soonestExpiringTempIP(FirewallState{Blocked: pruned}, candidate)
			model, err := responsereplay.NewLegacy(responsereplay.LegacyConfig{
				MaxPerHour: 100, DenyTempLimit: max(temporary, 1), BlockTTL: time.Hour, PendingBound: 10,
				PendingMaxAge: 2 * time.Hour, HourLocation: time.UTC, Seed: 1,
			}, responsereplay.Classifier{
				Blockable:      func(f responsereplay.Finding) bool { return f.Check == "hard" },
				ChallengeFirst: func(responsereplay.Finding) bool { return false },
				SourceIP: func(f responsereplay.Finding) string {
					_, ip, _ := strings.Cut(f.Message, " from ")
					return ip
				},
				ExemptBlock: func(responsereplay.Finding) (responsereplay.ObservedBlock, bool) {
					return responsereplay.ObservedBlock{}, false
				},
			}, responsereplay.LegacyState{Entries: original})
			if err != nil {
				t.Fatal(err)
			}
			out, err := model.Step(responsereplay.Batch{At: evictNow, Findings: []responsereplay.Finding{{Check: "hard", Message: "attack from " + candidate}}})
			if err != nil {
				t.Fatal(err)
			}
			if out.Blocked != 1 {
				t.Fatalf("candidate not blocked: %+v", out)
			}
			// The limit is full only when a temporary entry survived expiry.
			if temporary == 0 {
				if wantOK || out.Evicted != 0 {
					t.Fatalf("nothing live to evict, yet engine %q %v, model %v", want, wantOK, out.EvictedIPs)
				}
				return
			}
			if !wantOK || fmt.Sprint(out.EvictedIPs) != fmt.Sprint([]string{want}) {
				t.Fatalf("engine evicts %q, model %v", want, out.EvictedIPs)
			}
		})
	}
}
