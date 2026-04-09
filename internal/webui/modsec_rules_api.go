package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/store"
)

func validateModSecDisabledRules(allRules []modsec.Rule, disabled []int) error {
	knownIDs := make(map[int]bool)
	counterIDs := make(map[int]bool)
	for _, rule := range allRules {
		knownIDs[rule.ID] = true
		if rule.IsCounter {
			counterIDs[rule.ID] = true
		}
	}
	for _, id := range disabled {
		if !knownIDs[id] {
			return fmt.Errorf("rule ID %d is not a known CSM rule", id)
		}
		if counterIDs[id] {
			return fmt.Errorf("rule ID %d is a protected bookkeeping rule", id)
		}
	}
	return nil
}

func (s *Server) handleModSecRules(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "modsec-rules.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// GET /api/v1/modsec/rules - list all CSM rules with status
func (s *Server) apiModSecRules(w http.ResponseWriter, _ *http.Request) {
	cfg := s.cfg.ModSec

	// Check all three config fields
	var missing []string
	if cfg.RulesFile == "" {
		missing = append(missing, "rules_file")
	}
	if cfg.OverridesFile == "" {
		missing = append(missing, "overrides_file")
	}
	if cfg.ReloadCommand == "" {
		missing = append(missing, "reload_command")
	}
	if len(missing) > 0 {
		writeJSON(w, map[string]interface{}{
			"configured": false,
			"missing":    missing,
		})
		return
	}

	// Parse rules from config file
	allRules, err := modsec.ParseRulesFile(cfg.RulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "modsec: parse rules failed: %v\n", err)
		writeJSONError(w, "Failed to parse rules file", http.StatusInternalServerError)
		return
	}

	// Read disabled IDs from overrides file
	disabledIDs, _ := modsec.ReadOverrides(cfg.OverridesFile)
	disabledSet := make(map[int]bool)
	for _, id := range disabledIDs {
		disabledSet[id] = true
	}

	// Read escalation exclusions and hit counts from store
	var noEscalate map[int]bool
	var hits map[int]store.RuleHitStats
	if db := store.Global(); db != nil {
		noEscalate = db.GetModSecNoEscalateRules()
		hits = db.GetModSecRuleHits()
	}

	// Build response - filter out counter rules
	type ruleView struct {
		ID          int    `json:"id"`
		Description string `json:"description"`
		Action      string `json:"action"`
		StatusCode  int    `json:"status_code"`
		Phase       int    `json:"phase"`
		Enabled     bool   `json:"enabled"`
		Escalate    bool   `json:"escalate"`
		Hits24h     int    `json:"hits_24h"`
		LastHit     string `json:"last_hit,omitempty"`
	}

	var rules []ruleView
	for _, r := range allRules {
		if r.IsCounter {
			continue // hide bookkeeping rules
		}
		rv := ruleView{
			ID:          r.ID,
			Description: r.Description,
			Action:      r.Action,
			StatusCode:  r.StatusCode,
			Phase:       r.Phase,
			Enabled:     !disabledSet[r.ID],
			Escalate:    !noEscalate[r.ID],
		}
		if h, ok := hits[r.ID]; ok {
			rv.Hits24h = h.Hits
			if !h.LastHit.IsZero() {
				rv.LastHit = h.LastHit.Format("2006-01-02T15:04:05Z07:00")
			}
		}
		rules = append(rules, rv)
	}

	active := 0
	for _, r := range rules {
		if r.Enabled {
			active++
		}
	}

	writeJSON(w, map[string]interface{}{
		"rules":      rules,
		"total":      len(rules),
		"active":     active,
		"disabled":   disabledIDs,
		"configured": true,
	})
}

// POST /api/v1/modsec/rules/apply - write overrides and reload
func (s *Server) apiModSecRulesApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Serialize apply operations - the write+reload+rollback sequence
	// must not interleave with concurrent applies.
	s.modSecApplyMu.Lock()
	defer s.modSecApplyMu.Unlock()

	cfg := s.cfg.ModSec
	if cfg.RulesFile == "" || cfg.OverridesFile == "" || cfg.ReloadCommand == "" {
		writeJSONError(w, "ModSecurity not configured", http.StatusBadRequest)
		return
	}

	var req struct {
		Disabled []int `json:"disabled"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate: only allow disabling known CSM rule IDs from the parsed rules file
	allRules, err := modsec.ParseRulesFile(cfg.RulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "modsec: parse rules failed: %v\n", err)
		writeJSONError(w, "Failed to parse rules file", http.StatusInternalServerError)
		return
	}
	if err := validateModSecDisabledRules(allRules, req.Disabled); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save previous state for rollback
	previousContent := modsec.ReadOverridesRaw(cfg.OverridesFile)

	// Write new overrides
	if writeErr := modsec.WriteOverrides(cfg.OverridesFile, req.Disabled); writeErr != nil {
		fmt.Fprintf(os.Stderr, "modsec: write overrides failed: %v\n", writeErr)
		writeJSONError(w, "Failed to write overrides", http.StatusInternalServerError)
		return
	}

	// Reload web server
	output, reloadErr := modsec.Reload(cfg.ReloadCommand)
	if reloadErr != nil {
		// Rollback on failure
		_ = modsec.RestoreOverrides(cfg.OverridesFile, previousContent)
		fmt.Fprintf(os.Stderr, "modsec: reload failed (rolled back): %v\noutput: %s\n", reloadErr, output)
		// Truncate output for client - may contain sensitive system paths
		clientOutput := output
		if len(clientOutput) > 500 {
			clientOutput = clientOutput[:500] + "... (truncated)"
		}
		writeJSON(w, map[string]interface{}{
			"ok":            false,
			"error":         "Web server reload failed, changes rolled back",
			"reload_output": clientOutput,
			"rolled_back":   true,
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"ok":             true,
		"disabled_count": len(req.Disabled),
	})
}

// POST /api/v1/modsec/rules/escalation - toggle escalation for a single rule
func (s *Server) apiModSecRulesEscalation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	db := store.Global()
	if db == nil {
		writeJSONError(w, "Store not available", http.StatusInternalServerError)
		return
	}

	var req struct {
		RuleID   int  `json:"rule_id"`
		Escalate bool `json:"escalate"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024) // 4KB - single rule ID
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate: only accept known CSM rule IDs (900000-900999)
	if req.RuleID < 900000 || req.RuleID > 900999 {
		writeJSONError(w, "Rule ID must be a CSM custom rule (900000-900999)", http.StatusBadRequest)
		return
	}

	var err error
	if req.Escalate {
		err = db.RemoveModSecNoEscalateRule(req.RuleID)
	} else {
		err = db.AddModSecNoEscalateRule(req.RuleID)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "modsec: escalation update failed: %v\n", err)
		writeJSONError(w, "Failed to update escalation setting", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{"ok": true})
}
