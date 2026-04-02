package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/signatures"
	"github.com/pidginhost/cpanel-security-monitor/internal/store"
	"github.com/pidginhost/cpanel-security-monitor/internal/yara"
)

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "rules.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// GET /api/v1/rules/status
func (s *Server) apiRulesStatus(w http.ResponseWriter, _ *http.Request) {
	yamlCount := 0
	yamlVersion := 0
	if scanner := signatures.Global(); scanner != nil {
		yamlCount = scanner.RuleCount()
		yamlVersion = scanner.Version()
	}

	yaraCount := 0
	if yaraScanner := yara.Global(); yaraScanner != nil {
		yaraCount = yaraScanner.RuleCount()
	}

	result := map[string]interface{}{
		"yaml_rules":      yamlCount,
		"yara_rules":      yaraCount,
		"yara_available":  yara.Available(),
		"yaml_version":    yamlVersion,
		"rules_dir":       s.cfg.Signatures.RulesDir,
		"auto_update":     s.cfg.Signatures.UpdateURL != "",
		"update_url":      s.cfg.Signatures.UpdateURL,
		"update_interval": s.cfg.Signatures.UpdateInterval,
	}
	writeJSON(w, result)
}

// GET /api/v1/rules/list
func (s *Server) apiRulesList(w http.ResponseWriter, _ *http.Request) {
	rulesDir := s.cfg.Signatures.RulesDir

	type ruleFileInfo struct {
		Name string `json:"name"`
		Type string `json:"type"` // "yaml" or "yara"
		Size int64  `json:"size"`
	}

	var files []ruleFileInfo

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, files)
			return
		}
		writeJSONError(w, fmt.Sprintf("reading rules directory: %v", err), http.StatusInternalServerError)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))

		var fileType string
		switch ext {
		case ".yml", ".yaml":
			fileType = "yaml"
		case ".yar", ".yara":
			fileType = "yara"
		default:
			continue // skip non-rule files
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		files = append(files, ruleFileInfo{
			Name: name,
			Type: fileType,
			Size: info.Size(),
		})
	}

	writeJSON(w, files)
}

// POST /api/v1/rules/reload
func (s *Server) apiRulesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var yamlErr, yaraErr error
	yamlCount := 0
	yaraCount := 0

	if scanner := signatures.Global(); scanner != nil {
		yamlErr = scanner.Reload()
		yamlCount = scanner.RuleCount()
		// Update the cached sig count shown in dashboard/status
		s.SetSigCount(yamlCount)
	}

	if yaraScanner := yara.Global(); yaraScanner != nil {
		yaraErr = yaraScanner.Reload()
		yaraCount = yaraScanner.RuleCount()
	}

	var errors []string
	if yamlErr != nil {
		errors = append(errors, fmt.Sprintf("YAML reload: %v", yamlErr))
	}
	if yaraErr != nil {
		errors = append(errors, fmt.Sprintf("YARA reload: %v", yaraErr))
	}

	result := map[string]interface{}{
		"ok":         len(errors) == 0,
		"yaml_rules": yamlCount,
		"yara_rules": yaraCount,
	}
	if len(errors) > 0 {
		result["errors"] = errors
	}

	writeJSON(w, result)
}

// GET/POST /api/v1/rules/modsec-escalation — manage rules excluded from auto-block
func (s *Server) apiModSecEscalation(w http.ResponseWriter, r *http.Request) {
	db := store.Global()

	if r.Method == http.MethodPost {
		if db == nil {
			writeJSONError(w, "Store not available", http.StatusInternalServerError)
			return
		}
		var req struct {
			Rules []int `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rules := make(map[int]bool)
		for _, id := range req.Rules {
			rules[id] = true
		}
		if err := db.SetModSecNoEscalateRules(rules); err != nil {
			writeJSONError(w, fmt.Sprintf("Save failed: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "count": len(rules)})
		return
	}

	// GET
	var ids []int
	if db != nil {
		for id := range db.GetModSecNoEscalateRules() {
			ids = append(ids, id)
		}
	}
	if ids == nil {
		ids = []int{}
	}
	writeJSON(w, map[string]interface{}{"rules": ids})
}
