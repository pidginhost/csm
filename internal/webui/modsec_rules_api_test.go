package webui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/modsec"
)

func TestModSecFailedRollbackIsNotAuditedAsRestored(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	rules, overrides := filepath.Join(dir, "rules.conf"), filepath.Join(dir, "overrides.conf")
	if err := os.WriteFile(rules, []byte(`SecRule REQUEST_URI "x" "id:900007,phase:1,deny"`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overrides, []byte("# original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.ModSec.RulesFile, s.cfg.ModSec.OverridesFile = rules, overrides
	// The failed reload leaves an unwritable rollback destination.
	s.cfg.ModSec.ReloadCommand = "mkdir '" + strings.ReplaceAll(overrides+".tmp", "'", "'\\''") + "'; exit 1"
	w := httptest.NewRecorder()
	s.apiModSecRulesApply(w, jsonPost("/api/v1/modsec/rules/apply", `{"disabled":[900007]}`))
	var result struct {
		RolledBack bool   `json:"rolled_back"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.RolledBack || !strings.Contains(result.Error, "rollback failed") {
		t.Fatalf("rollback failure was concealed: %s", w.Body.String())
	}
	e := requireAudit(t, s, "modsec_rules_apply_failed", "overrides")
	if !strings.Contains(e.Details, "rollback failed") || strings.Contains(e.Details, "overrides restored") {
		t.Fatalf("inaccurate audit outcome: %s", e.Details)
	}
}

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
