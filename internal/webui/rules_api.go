package webui

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "rules.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// GET /api/v1/rules/status
func (s *Server) apiRulesStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := s.liveCfg()
	yamlCount := 0
	yamlVersion := 0
	if scanner := signatures.Global(); scanner != nil {
		yamlCount = scanner.RuleCount()
		yamlVersion = scanner.Version()
	}

	yaraCount := 0
	if b := yara.Active(); b != nil {
		yaraCount = b.RuleCount()
	}

	result := map[string]interface{}{
		"yaml_rules":      yamlCount,
		"yara_rules":      yaraCount,
		"yara_available":  yara.Available(),
		"yaml_version":    yamlVersion,
		"rules_dir":       cfg.Signatures.RulesDir,
		"auto_update":     cfg.Signatures.UpdateURL != "",
		"update_url":      cfg.Signatures.UpdateURL,
		"update_interval": cfg.Signatures.UpdateInterval,
	}
	writeJSON(w, result)
}

// GET /api/v1/rules/list
func (s *Server) apiRulesList(w http.ResponseWriter, _ *http.Request) {
	rulesDir := s.liveCfg().Signatures.RulesDir

	type ruleFileInfo struct {
		Name string `json:"name"`
		Type string `json:"type"` // "yaml" or "yara"
		Size int64  `json:"size"`
	}

	var files []ruleFileInfo

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeAll(w, files)
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

	writeAll(w, files)
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

	if b := yara.Active(); b != nil {
		yaraErr = b.Reload()
		yaraCount = b.RuleCount()
	}

	var errors []string
	if yamlErr != nil {
		errors = append(errors, fmt.Sprintf("YAML reload: %v", yamlErr))
	}
	if yaraErr != nil {
		errors = append(errors, fmt.Sprintf("YARA reload: %v", yaraErr))
	}

	s.auditLog(r, "rules_reload", "signatures", fmt.Sprintf("errors: %d", len(errors)))
	result := map[string]interface{}{
		"yaml_rules": yamlCount,
		"yara_rules": yaraCount,
	}
	if len(errors) > 0 {
		result["error"] = strings.Join(errors, "; ")
		result["errors"] = errors
		writeJSONStatus(w, http.StatusInternalServerError, result)
		return
	}
	writeOK(w, result)
}
