package webui

import (
	"net/http"
	"sort"

	"github.com/pidginhost/csm/internal/mailfwd/inventory"
	"github.com/pidginhost/csm/internal/platform"
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
	Forwarders []forwarderEntry  `json:"forwarders"`
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
