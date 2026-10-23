package webui

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/mailfwd/inventory"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// forwarderDestination is one resolved target of a forwarder, as served to the
// UI. Provider is the inventory class string (local/yahoo/gmail/outlook/external)
// the table renders as a badge.
type forwarderDestination struct {
	Address  string `json:"address"`
	Domain   string `json:"domain"`
	Provider string `json:"provider"`
}

// forwarderEntry is a single source address and everything it relays to.
type forwarderEntry struct {
	Source          string                 `json:"source"`
	Domain          string                 `json:"domain"`
	Owner           string                 `json:"owner"`
	Destinations    []forwarderDestination `json:"destinations"`
	Providers       []string               `json:"providers"` // distinct destination classes, sorted
	KeepLocal       bool                   `json:"keep_local"`
	ForwardOnly     bool                   `json:"forward_only"`
	HasExternal     bool                   `json:"has_external"`
	HasFreeProvider bool                   `json:"has_free_provider"`
}

// forwardersSummary is the page-header rollup: how many forwarders exist and
// how many carry reputation risk (leave the server / target a free provider).
type forwardersSummary struct {
	Total        int `json:"total"`
	External     int `json:"external"`
	FreeProvider int `json:"free_provider"`
}

type forwardersResponse struct {
	Forwarders []forwarderEntry  `json:"items"`
	Total      int               `json:"total"`
	Summary    forwardersSummary `json:"summary"`
}

// selectForwarderSource picks the inventory source for the host. Only cPanel
// enumeration is wired; other platforms get the empty source until their
// adapters land (Phase 3).
func selectForwarderSource() inventory.Source {
	if platform.Detect().IsCPanel() {
		return inventory.NewCPanelSource()
	}
	return inventory.EmptySource{}
}

// selectForwarderRemover picks how forwarders are deleted. Only cPanel is
// wired; elsewhere the delete route answers as unavailable. eximLookPath and
// eximRun run any command, not only exim.
func selectForwarderRemover() *inventory.CPanelRemover {
	if platform.Detect().IsCPanel() {
		return inventory.NewCPanelRemover(eximLookPath, eximRun)
	}
	return nil
}

// apiEmailForwarders handles GET /api/v1/email/forwarders and returns the host's
// forwarder inventory: each source, its destinations with provider class, owner,
// and whether it keeps a local copy or forwards only.
func (s *Server) apiEmailForwarders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := forwardersResponse{Forwarders: []forwarderEntry{}}
	if s.forwarderSource == nil {
		writeJSON(w, resp)
		return
	}

	fwds, err := s.forwarderSource.Forwarders()
	if err != nil {
		writeJSONError(w, "Failed to enumerate forwarders", http.StatusInternalServerError)
		return
	}

	for _, f := range fwds {
		resp.Forwarders = append(resp.Forwarders, toForwarderEntry(f))
		resp.Summary.Total++
		resp.Total++
		if f.HasExternal() {
			resp.Summary.External++
		}
		if f.HasFreeProvider() {
			resp.Summary.FreeProvider++
		}
	}

	writeJSON(w, resp)
}

func toForwarderEntry(f inventory.Forwarder) forwarderEntry {
	dests := make([]forwarderDestination, 0, len(f.Destinations))
	seen := make(map[string]bool, len(f.Destinations))
	providers := make([]string, 0, len(f.Destinations))
	for _, d := range f.Destinations {
		dests = append(dests, forwarderDestination{
			Address:  d.Address,
			Domain:   d.Domain,
			Provider: string(d.Provider),
		})
		if p := string(d.Provider); !seen[p] {
			seen[p] = true
			providers = append(providers, p)
		}
	}
	sort.Strings(providers)

	return forwarderEntry{
		Source:          f.Source,
		Domain:          f.Domain,
		Owner:           f.Owner,
		Destinations:    dests,
		Providers:       providers,
		KeepLocal:       f.KeepLocal,
		ForwardOnly:     f.ForwardOnly,
		HasExternal:     f.HasExternal(),
		HasFreeProvider: f.HasFreeProvider(),
	}
}

// apiEmailForwarderDelete handles POST /api/v1/email/forwarders/delete: it
// removes one destination of one forwarder. The pair must be in the current
// inventory, which also names the account uapi runs as, so a request can
// never pick the account or reach an address the list does not show. Every
// attempt that reaches cPanel is audit-logged with its outcome.
func (s *Server) apiEmailForwarderDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	if err := decodeJSONBodyLimited(w, r, 4096, &req); err != nil || req.Source == "" || req.Destination == "" {
		writeJSONError(w, "Body must name a source and a destination", http.StatusBadRequest)
		return
	}
	if s.forwarderRemover == nil || s.forwarderSource == nil {
		writeJSONError(w, "Forwarders cannot be changed on this host", http.StatusServiceUnavailable)
		return
	}
	fwds, err := s.forwarderSource.Forwarders()
	if err != nil {
		writeJSONError(w, "Failed to enumerate forwarders", http.StatusInternalServerError)
		return
	}
	f, ok := findForwarderDestination(fwds, req.Source, req.Destination)
	switch {
	case !ok:
		writeJSONError(w, "No such forwarder; reload the list", http.StatusNotFound)
		return
	case strings.HasPrefix(f.Source, "*@"):
		writeJSONError(w, "The default address is changed in cPanel", http.StatusBadRequest)
		return
	case f.Owner == "":
		writeJSONError(w, "No cPanel account owns "+f.Domain, http.StatusConflict)
		return
	}

	err = s.forwarderRemover.Remove(f, req.Destination)
	details := "destination: " + req.Destination + "; owner: " + f.Owner
	if err != nil {
		details += "; error: " + err.Error()
	}
	s.auditLog(r, "email_forwarder_delete", f.Source, details)

	switch {
	case err == nil:
		writeOK(w, nil)
	case errors.Is(err, systemdrun.ErrUnavailable):
		writeJSONError(w, "Deleting forwarders needs systemd-run: "+err.Error(), http.StatusServiceUnavailable)
	default:
		writeJSONError(w, "Forwarder delete failed: "+err.Error(), http.StatusInternalServerError)
	}
}

// findForwarderDestination returns the forwarder whose source and one of whose
// destinations match exactly.
func findForwarderDestination(fwds []inventory.Forwarder, source, dest string) (inventory.Forwarder, bool) {
	for _, f := range fwds {
		if f.Source != source {
			continue
		}
		for _, d := range f.Destinations {
			if d.Address == dest {
				return f, true
			}
		}
	}
	return inventory.Forwarder{}, false
}
