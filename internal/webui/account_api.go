package webui

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if err := validateAccountName(name); err != nil {
		http.Redirect(w, r, "/findings", http.StatusFound)
		return
	}
	s.renderTemplate(w, "account.html", map[string]string{
		"Hostname":    s.cfg.Hostname,
		"AccountName": name,
		"HomeDir":     checks.AccountHomeDirIn(s.accountRoots(), name),
	})
}

// accountPathPrefixes returns "<root>/<name>/" for every account root, the
// prefixes a path inside the account's home starts with.
func (s *Server) accountPathPrefixes(name string) []string {
	roots := s.accountRoots()
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		out = append(out, filepath.Join(root, name)+"/")
		// Findings and quarantine metadata can carry the resolved path even
		// after the file has been moved away. Resolve the root, not the file.
		if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != filepath.Clean(root) {
			out = append(out, filepath.Join(resolved, name)+"/")
		}
	}
	return out
}

func pathHasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func accountFindingMatches(f alert.Finding, name string, prefixes []string) bool {
	for _, owner := range []string{f.TenantID, f.CPUser} {
		if owner = strings.TrimSpace(owner); owner != "" {
			return owner == name
		}
	}
	return containsAny(f.Message, prefixes) || containsAny(f.Details, prefixes) || pathHasAnyPrefix(f.FilePath, prefixes)
}

func (s *Server) apiAccountDetail(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if err := validateAccountName(name); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	homePrefixes := s.accountPathPrefixes(name)

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
		if accountFindingMatches(f, name, homePrefixes) {
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
	rootMetas := listMetaFiles(quarantineDir)
	preCleanMetas := listMetaFiles(filepath.Join(quarantineDir, "pre_clean"))
	metas := rootMetas
	metas = append(metas, preCleanMetas...)
	for _, metaPath := range metas {
		meta, err := readQuarantineMeta(metaPath)
		if err != nil {
			continue
		}
		if pathHasAnyPrefix(meta.OriginalPath, homePrefixes) {
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
		if accountFindingMatches(f, name, homePrefixes) {
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
