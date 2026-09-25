package admission

import (
	"maps"
	"sort"
)

const inventoryVersion = 1
const reportLinksVersion = 1

// MaxReportLinks bounds the later findings kept for one evidence record.
// Further reports are only counted.
const MaxReportLinks = 8

type inventoryRecord struct {
	V        uint8             `json:"v"`
	Accounts map[string]uint64 `json:"accounts"`
	Domains  map[string]string `json:"domains"`
}

// MarshalBinary encodes the inventory so the ledger can keep the last good
// snapshot when a later read fails.
func (inv *Inventory) MarshalBinary() ([]byte, error) {
	if inv == nil || inv.accounts == nil || inv.domains == nil {
		return nil, refuse(ReasonInvalid, "inventory is not initialized")
	}
	return sealRecord(inventoryRecord{V: inventoryVersion, Accounts: inv.accounts, Domains: inv.domains})
}

// UnmarshalInventory decodes a stored inventory and rebuilds it through
// NewInventory, so a stored snapshot obeys the same rules as a fresh one.
func UnmarshalInventory(data []byte) (*Inventory, error) {
	var rec inventoryRecord
	if err := openRecord(data, &rec); err != nil {
		return nil, err
	}
	if rec.V != inventoryVersion || rec.Accounts == nil || rec.Domains == nil {
		return nil, ErrCorruptRecord
	}
	inv, err := NewInventory(rec.Accounts, rec.Domains)
	if err != nil {
		return nil, ErrCorruptRecord
	}
	return inv, nil
}

// MatchesGenerations checks the persisted snapshot against its allocation
// tracker before either can be used to refresh account identities.
func (inv *Inventory) MatchesGenerations(g *Generations) bool {
	return inv != nil && inv.accounts != nil && inv.domains != nil &&
		g != nil && g.next != 0 && maps.Equal(inv.accounts, g.live)
}

// ReportLinks are the later findings that reported one evidence record. They
// are metadata: adding one never changes the evidence, its queue age or its
// freshness.
type ReportLinks struct {
	// Links are finding IDs, sorted and unique.
	Links []string
	// Dropped counts reports beyond MaxReportLinks. It saturates.
	Dropped uint32
}

type reportLinksRecord struct {
	V       uint8    `json:"v"`
	Links   []string `json:"links"`
	Dropped uint32   `json:"dropped,omitempty"`
}

// Add returns the links with findingID recorded, and whether they changed.
func (r ReportLinks) Add(findingID string) (ReportLinks, bool, error) {
	if !r.valid() {
		return r, false, refuse(ReasonInvalid, "report links are inconsistent")
	}
	if !lowerHex(findingID, 16) {
		return r, false, refuse(ReasonInvalid, "finding ID is not 16 lowercase hex digits")
	}
	i := sort.SearchStrings(r.Links, findingID)
	if i < len(r.Links) && r.Links[i] == findingID {
		return r, false, nil
	}
	if len(r.Links) >= MaxReportLinks {
		if r.Dropped == ^uint32(0) {
			return r, false, nil
		}
		r.Dropped++
		return r, true, nil
	}
	links := make([]string, 0, len(r.Links)+1)
	links = append(links, r.Links[:i]...)
	links = append(links, findingID)
	r.Links = append(links, r.Links[i:]...)
	return r, true, nil
}

func (r ReportLinks) valid() bool {
	if len(r.Links) > MaxReportLinks || (r.Dropped > 0 && len(r.Links) < MaxReportLinks) {
		return false
	}
	for i, id := range r.Links {
		if !lowerHex(id, 16) || (i > 0 && r.Links[i-1] >= id) {
			return false
		}
	}
	return true
}

func (r ReportLinks) MarshalBinary() ([]byte, error) {
	if !r.valid() {
		return nil, refuse(ReasonInvalid, "report links are inconsistent")
	}
	links := r.Links
	if links == nil {
		links = []string{}
	}
	return sealRecord(reportLinksRecord{V: reportLinksVersion, Links: links, Dropped: r.Dropped})
}

// UnmarshalReportLinks decodes stored links and checks their invariants.
func UnmarshalReportLinks(data []byte) (ReportLinks, error) {
	var rec reportLinksRecord
	if err := openRecord(data, &rec); err != nil {
		return ReportLinks{}, err
	}
	r := ReportLinks{Links: rec.Links, Dropped: rec.Dropped}
	if rec.V != reportLinksVersion || rec.Links == nil || !r.valid() {
		return ReportLinks{}, ErrCorruptRecord
	}
	return r, nil
}
