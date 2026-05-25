package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

var errNoStore = errors.New("store unavailable")

func nowUnix() int64 { return time.Now().UTC().Unix() }

// operatorKey returns a SHA-256 hex of the auth credential carried by r. It
// is used as the per-operator partition key for the preferences store. The
// store never sees the raw token; only its hash.
//
// Returns "" when no credential is present (handlers below run after
// requireAuth, so this only happens in unit tests that bypass middleware).
func (s *Server) operatorKey(r *http.Request) string {
	if c, err := r.Cookie("csm_auth"); err == nil && c.Value != "" {
		return hashOperatorToken(c.Value)
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		bearer := strings.TrimPrefix(auth, "Bearer ")
		if bearer != "" {
			return hashOperatorToken(bearer)
		}
	}
	return ""
}

func hashOperatorToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

const (
	prefsNamespaceUser  = "user"
	prefsNamespaceViews = "views"
)

// userPrefsBlob is the JSON document the client posts to /api/v1/prefs/user.
// Fields are validated and clipped to a small enum where appropriate so an
// attacker cannot smuggle arbitrary template data into the layout.
type userPrefsBlob struct {
	Density      string              `json:"density"`
	Timezone     string              `json:"timezone"`
	AutoRefresh  string              `json:"auto_refresh"`
	TableColumns map[string][]string `json:"table_columns,omitempty"`
}

func sanitizeUserPrefs(in userPrefsBlob) userPrefsBlob {
	out := userPrefsBlob{}
	switch in.Density {
	case "compact", "comfortable":
		out.Density = in.Density
	}
	switch in.Timezone {
	case "server", "local":
		out.Timezone = in.Timezone
	default:
		// Allow IANA-shaped strings (e.g. "Europe/Bucharest"). Reject anything
		// containing whitespace or control characters; the value gets reflected
		// in JS where Intl.DateTimeFormat will reject malformed zones anyway.
		if isIANAish(in.Timezone) {
			out.Timezone = in.Timezone
		}
	}
	switch in.AutoRefresh {
	case "on", "off":
		out.AutoRefresh = in.AutoRefresh
	}
	if len(in.TableColumns) > 0 {
		cleaned := make(map[string][]string, len(in.TableColumns))
		for k, vals := range in.TableColumns {
			if !isSimpleIdent(k) || len(vals) > 64 {
				continue
			}
			var v []string
			for _, name := range vals {
				if isSimpleIdent(name) {
					v = append(v, name)
				}
			}
			cleaned[k] = v
		}
		if len(cleaned) > 0 {
			out.TableColumns = cleaned
		}
	}
	return out
}

func isIANAish(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '+' || r == '-' || r == '/':
		default:
			return false
		}
	}
	return true
}

func isSimpleIdent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

// apiPrefsUser handles GET and PUT for the operator's user-pref blob.
func (s *Server) apiPrefsUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetUserPrefs(w, r)
	case http.MethodPut:
		s.handlePutUserPrefs(w, r)
	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetUserPrefs(w http.ResponseWriter, r *http.Request) {
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	sdb := store.Global()
	if sdb == nil {
		writeJSON(w, userPrefsBlob{})
		return
	}
	raw, err := sdb.GetOperatorPref(opkey, prefsNamespaceUser)
	if err != nil {
		writeJSONError(w, "Store error", http.StatusInternalServerError)
		return
	}
	if raw == nil {
		writeJSON(w, userPrefsBlob{})
		return
	}
	var blob userPrefsBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		writeJSON(w, userPrefsBlob{})
		return
	}
	writeJSON(w, sanitizeUserPrefs(blob))
}

func (s *Server) handlePutUserPrefs(w http.ResponseWriter, r *http.Request) {
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	var blob userPrefsBlob
	if err := decodeJSONBodyLimited(w, r, store.MaxPrefBlobSize, &blob); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	clean := sanitizeUserPrefs(blob)
	raw, err := json.Marshal(clean)
	if err != nil {
		writeJSONError(w, "Encoding failed", http.StatusInternalServerError)
		return
	}
	sdb := store.Global()
	if sdb == nil {
		writeJSONError(w, "Store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := sdb.PutOperatorPref(opkey, prefsNamespaceUser, raw); err != nil {
		writeJSONError(w, "Store error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, clean)
}

// savedView represents one user-named filter combination for a page.
type savedView struct {
	Name    string            `json:"name"`
	Page    string            `json:"page"`
	Params  map[string]string `json:"params"`
	Updated int64             `json:"updated"`
}

const maxSavedViewsPerOperator = 200

// apiPrefsViews handles list (GET), upsert (PUT), and delete (DELETE) of
// saved filter views.
func (s *Server) apiPrefsViews(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListSavedViews(w, r)
	case http.MethodPut:
		s.handlePutSavedView(w, r)
	case http.MethodDelete:
		s.handleDeleteSavedView(w, r)
	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) loadSavedViews(opkey string) []savedView {
	sdb := store.Global()
	if sdb == nil {
		return nil
	}
	raw, err := sdb.GetOperatorPref(opkey, prefsNamespaceViews)
	if err != nil || raw == nil {
		return nil
	}
	var views []savedView
	if err := json.Unmarshal(raw, &views); err != nil {
		return nil
	}
	return views
}

func (s *Server) saveSavedViews(opkey string, views []savedView) error {
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Page != views[j].Page {
			return views[i].Page < views[j].Page
		}
		return views[i].Name < views[j].Name
	})
	raw, err := json.Marshal(views)
	if err != nil {
		return err
	}
	sdb := store.Global()
	if sdb == nil {
		return errNoStore
	}
	return sdb.PutOperatorPref(opkey, prefsNamespaceViews, raw)
}

func (s *Server) handleListSavedViews(w http.ResponseWriter, r *http.Request) {
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	page := strings.TrimSpace(r.URL.Query().Get("page"))
	views := s.loadSavedViews(opkey)
	out := make([]savedView, 0, len(views))
	for _, v := range views {
		if page != "" && v.Page != page {
			continue
		}
		out = append(out, v)
	}
	writeJSON(w, out)
}

func (s *Server) handlePutSavedView(w http.ResponseWriter, r *http.Request) {
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		Name   string            `json:"name"`
		Page   string            `json:"page"`
		Params map[string]string `json:"params"`
	}
	if err := decodeJSONBodyLimited(w, r, store.MaxPrefBlobSize, &body); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Page = strings.TrimSpace(body.Page)
	if !isSimpleIdent(body.Page) {
		writeJSONError(w, "Invalid page", http.StatusBadRequest)
		return
	}
	if body.Name == "" || len(body.Name) > 80 {
		writeJSONError(w, "Name must be 1-80 characters", http.StatusBadRequest)
		return
	}
	if !isPrintableLabel(body.Name) {
		writeJSONError(w, "Name contains invalid characters", http.StatusBadRequest)
		return
	}
	if len(body.Params) > 32 {
		writeJSONError(w, "Too many params", http.StatusBadRequest)
		return
	}
	cleanParams := make(map[string]string, len(body.Params))
	for k, v := range body.Params {
		if !isSimpleIdent(k) || len(v) > 256 {
			writeJSONError(w, "Invalid param", http.StatusBadRequest)
			return
		}
		cleanParams[k] = v
	}

	views := s.loadSavedViews(opkey)
	now := nowUnix()
	updated := false
	for i := range views {
		if views[i].Page == body.Page && views[i].Name == body.Name {
			views[i].Params = cleanParams
			views[i].Updated = now
			updated = true
			break
		}
	}
	if !updated {
		if len(views) >= maxSavedViewsPerOperator {
			writeJSONError(w, "Saved view limit reached", http.StatusBadRequest)
			return
		}
		views = append(views, savedView{
			Name:    body.Name,
			Page:    body.Page,
			Params:  cleanParams,
			Updated: now,
		})
	}
	if err := s.saveSavedViews(opkey, views); err != nil {
		writeJSONError(w, "Store error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteSavedView(w http.ResponseWriter, r *http.Request) {
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		Name string `json:"name"`
		Page string `json:"page"`
	}
	if err := decodeJSONBodyLimited(w, r, 8*1024, &body); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	views := s.loadSavedViews(opkey)
	out := views[:0]
	removed := false
	for _, v := range views {
		if v.Page == body.Page && v.Name == body.Name {
			removed = true
			continue
		}
		out = append(out, v)
	}
	if !removed {
		writeJSONError(w, "View not found", http.StatusNotFound)
		return
	}
	if err := s.saveSavedViews(opkey, out); err != nil {
		writeJSONError(w, "Store error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func isPrintableLabel(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
