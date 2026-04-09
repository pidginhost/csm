package webui

import (
	"testing"

	"github.com/pidginhost/csm/internal/modsec"
)

func TestValidateModSecDisabledRulesRejectsCounterRule(t *testing.T) {
	rules := []modsec.Rule{
		{ID: 900006, IsCounter: true},
		{ID: 900007},
	}

	err := validateModSecDisabledRules(rules, []int{900006})
	if err == nil {
		t.Fatal("expected bookkeeping rule to be rejected")
	}
}

func TestValidateModSecDisabledRulesAllowsVisibleRule(t *testing.T) {
	rules := []modsec.Rule{
		{ID: 900006, IsCounter: true},
		{ID: 900007},
	}

	if err := validateModSecDisabledRules(rules, []int{900007}); err != nil {
		t.Fatalf("expected visible rule to be accepted, got %v", err)
	}
}
