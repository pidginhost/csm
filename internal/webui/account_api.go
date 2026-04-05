package webui

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "account.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) apiAccountDetail(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if err := validateAccountName(name); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	homePrefix := "/home/" + name + "/"

	// Current findings for this account
	type findingView struct {
		Severity int    `json:"severity"`
		Check    string `json:"check"`
		Message  string `json:"message"`
		HasFix   bool   `json:"has_fix"`
	}
	var accountFindings []findingView
	latest := s.store.LatestFindings()
	for _, f := range latest {
		if f.Check == "auto_response" || f.Check == "auto_block" || f.Check == "check_timeout" || f.Check == "health" {
			continue
		}
		if strings.Contains(f.Message, homePrefix) || strings.Contains(f.Details, homePrefix) || strings.Contains(f.FilePath, homePrefix) {
			accountFindings = append(accountFindings, findingView{
				Severity: int(f.Severity),
				Check:    f.Check,
				Message:  f.Message,
				HasFix:   checks.HasFix(f.Check),
			})
		}
	}

	// Quarantined files for this account
	type qEntry struct {
		ID           string `json:"id"`
		OriginalPath string `json:"original_path"`
		Size         int64  `json:"size"`
		Reason       string `json:"reason"`
	}
	var quarantined []qEntry
	rootMetas := listMetaFiles("/opt/csm/quarantine")
	preCleanMetas := listMetaFiles(filepath.Join("/opt/csm/quarantine", "pre_clean"))
	metas := rootMetas
	metas = append(metas, preCleanMetas...)
	for _, metaPath := range metas {
		meta, err := readQuarantineMeta(metaPath)
		if err != nil {
			continue
		}
		if strings.HasPrefix(meta.OriginalPath, homePrefix) {
			id := strings.TrimSuffix(filepath.Base(metaPath), ".meta")
			quarantined = append(quarantined, qEntry{
				ID: id, OriginalPath: meta.OriginalPath, Size: meta.Size, Reason: meta.Reason,
			})
		}
	}

	// Recent history for this account (last 100 matching entries)
	allHistory, _ := s.store.ReadHistory(2000, 0)
	type histEntry struct {
		Severity  int    `json:"severity"`
		Check     string `json:"check"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	}
	var history []histEntry
	for _, f := range allHistory {
		if len(history) >= 100 {
			break
		}
		if strings.Contains(f.Message, homePrefix) || strings.Contains(f.Details, homePrefix) {
			history = append(history, histEntry{
				Severity: int(f.Severity), Check: f.Check, Message: f.Message,
				Timestamp: f.Timestamp.Format(time.RFC3339),
			})
		}
	}

	writeJSON(w, map[string]interface{}{
		"account":     name,
		"findings":    accountFindings,
		"quarantined": quarantined,
		"history":     history,
		"whm_url":     "https://" + s.cfg.Hostname + ":2087/scripts/domainsdata?user=" + name,
	})
}
