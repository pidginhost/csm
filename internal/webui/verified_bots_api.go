package webui

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/threatintel"
)

// SetVerifiedBotsReloader registers the callback the Daemon uses to push a
// saved verified_bots list into the live registry + rDNS verifier, so edits
// take effect without a restart. nil-safe: tests leave it unset.
func (s *Server) SetVerifiedBotsReloader(fn func() error) {
	s.verifiedBotsReloader = fn
}

func (s *Server) handleVerifiedBots(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "verified-bots.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// apiVerifiedBots (GET /api/v1/verified-bots) returns the configured list plus
// the config etag for optimistic locking on save.
func (s *Server) apiVerifiedBots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	diskBytes, err := os.ReadFile(s.cfg.ConfigFile) // #nosec G304 -- operator-supplied config path
	if err != nil {
		writeJSONError(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk, err := config.LoadBytes(diskBytes)
	if err != nil {
		writeJSONError(w, "parse config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	bots := disk.Reputation.VerifiedBots
	if bots == nil {
		bots = []config.VerifiedBot{}
	}
	writeJSON(w, map[string]interface{}{
		"bots":       bots,
		"etag":       disk.Integrity.ConfigHash,
		"bot_ranges": botRangesSummary(disk),
	})
}

// botRangesSummary is the read-only view of the built-in AI-crawler ranges the
// Verified Bots page shows: the configured auto-update posture plus the live
// per-bot prefix counts and last-refresh time from the active overlay.
func botRangesSummary(disk *config.Config) map[string]interface{} {
	lastRefresh := ""
	if ts := threatintel.LastFetchedRangesRefresh(); !ts.IsZero() {
		lastRefresh = ts.UTC().Format(time.RFC3339)
	}
	return map[string]interface{}{
		"auto_update":     disk.BotRangesAutoUpdate(),
		"update_interval": disk.Reputation.BotRanges.UpdateInterval,
		"last_refresh":    lastRefresh,
		"prefixes":        threatintel.AICrawlerRangePrefixCounts(),
	}
}

// apiVerifiedBotsApply (POST /api/v1/verified-bots/apply) validates and
// persists the whole verified_bots list to csm.yaml, then applies it live.
// The list is validated exactly as a config load would, so the same
// shared-hosting/over-broad-range guards apply here as on disk.
func (s *Server) apiVerifiedBotsApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Serialize read-validate-write-reload so concurrent saves cannot race.
	s.verifiedBotsMu.Lock()
	defer s.verifiedBotsMu.Unlock()

	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		writeJSONError(w, "If-Match header required", http.StatusBadRequest)
		return
	}
	var body struct {
		Bots *[]config.VerifiedBot `json:"bots"`
	}
	if err := decodeJSONBodyLimited(w, r, 256*1024, &body); err != nil {
		writeJSONError(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Bots == nil {
		writeJSONError(w, "bots is required", http.StatusBadRequest)
		return
	}
	bots := normalizeVerifiedBotsForSave(*body.Bots)

	diskBytes, err := os.ReadFile(s.cfg.ConfigFile) // #nosec G304 -- operator-supplied config path
	if err != nil {
		writeJSONError(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk, err := config.LoadBytes(diskBytes)
	if err != nil {
		writeJSONError(w, "parse config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk.ConfigFile = s.cfg.ConfigFile
	disk.ConfigDir = s.cfg.ConfigDir
	if disk.Integrity.ConfigHash != ifMatch {
		writeJSONError(w, "config changed on disk, reload", http.StatusPreconditionFailed)
		return
	}
	if rejectIfConfDirChanged(w, s.cfg.ConfigDir, disk.Integrity.ConfdHash) {
		return
	}

	clone := cloneConfigForSettingsApply(disk)
	clone.Reputation.VerifiedBots = bots

	var verr []fieldError
	for _, v := range config.Validate(&clone) {
		if v.Level == "error" && strings.HasPrefix(v.Field, "reputation.verified_bots") {
			verr = append(verr, fieldError{Field: v.Field, Message: v.Message})
		}
	}
	if len(verr) > 0 {
		writeValidationErrors(w, verr)
		return
	}

	// YAMLEdit block-renders []interface{} via yaml.Marshal; a typed
	// []config.VerifiedBot is not recognized, so wrap each entry.
	botsVal := make([]interface{}, len(bots))
	for i, b := range bots {
		botsVal[i] = b
	}
	edited, err := config.YAMLEdit(diskBytes, []config.YAMLChange{
		{Path: []string{"reputation", "verified_bots"}, Value: botsVal},
	})
	if err != nil {
		writeJSONError(w, "yaml edit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := integrity.SignAndSavePreserving(s.cfg.ConfigFile, s.cfg.ConfigDir, edited, &clone, disk.Integrity.BinaryHash); err != nil {
		writeJSONError(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newIntegrity := clone.Integrity
	// reputation is a hot-reload-safe section: apply to the live config now.
	if live := config.Active(); live != nil {
		liveClone := *live
		liveClone.Reputation.VerifiedBots = bots
		liveClone.Integrity = newIntegrity
		config.SetActive(&liveClone)
	} else {
		config.SetActive(&clone)
	}
	// Push the new list into the running registry + verifier (no restart).
	if s.verifiedBotsReloader != nil {
		_ = s.verifiedBotsReloader()
	}

	writeJSON(w, map[string]interface{}{
		"ok":       true,
		"count":    len(bots),
		"new_etag": newIntegrity.ConfigHash,
	})
}

func normalizeVerifiedBotsForSave(in []config.VerifiedBot) []config.VerifiedBot {
	out := make([]config.VerifiedBot, len(in))
	copy(out, in)
	for i := range out {
		out[i].UASubstrings = nilIfEmptyStrings(out[i].UASubstrings)
		out[i].RDNSSuffixes = nilIfEmptyStrings(out[i].RDNSSuffixes)
		out[i].IPRanges = nilIfEmptyStrings(out[i].IPRanges)
	}
	return out
}

func nilIfEmptyStrings(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	return v
}
