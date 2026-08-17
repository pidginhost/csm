package daemon

import "testing"

// A Forge release that simply carries fewer rules than the installed one is a
// routine upstream change, not a conflict. Comparing the post-reload total
// against the pre-reload total treats it as one, and the recovery action
// deletes the whole Forge file -- trading thousands of working rules for a
// handful. The counts here are the ones observed when this happened: an
// installed set of 5227 (146 local rules plus 5081 from Forge) replaced by an
// upstream release of 5032, totalling 5178.
func TestForgeRollbackNotNeededWhenUpstreamShipsFewerRules(t *testing.T) {
	if forgeRollbackNeeded(5178, 5032) {
		t.Error("rollback triggered by a smaller upstream release; it would delete 5032 working rules to avoid losing 49")
	}
}

// The condition the guard exists for: the archive did not compile in, so the
// scanner is left with only the local rules and the install must be undone.
func TestForgeRollbackNeededWhenNewRulesDidNotLoad(t *testing.T) {
	if !forgeRollbackNeeded(146, 5032) {
		t.Error("rollback not triggered when the new Forge rules failed to load")
	}
}

func TestForgeRollbackBoundaries(t *testing.T) {
	tests := []struct {
		name                   string
		newCount, forgeRuleCnt int
		want                   bool
	}{
		{"exactly the forge rules loaded, no local rules", 5032, 5032, false},
		{"one rule short of the archive", 5031, 5032, true},
		{"first install onto an empty scanner", 5032, 5032, false},
		{"growth", 6000, 5900, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := forgeRollbackNeeded(tc.newCount, tc.forgeRuleCnt); got != tc.want {
				t.Errorf("forgeRollbackNeeded(%d, %d) = %v, want %v",
					tc.newCount, tc.forgeRuleCnt, got, tc.want)
			}
		})
	}
}
