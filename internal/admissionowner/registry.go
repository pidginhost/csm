package admissionowner

import (
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
)

// Registry registers every producer of the producer table against the
// check registry's admission policy and seals it.
func Registry() (*admission.Registry, error) {
	reg, err := admission.NewRegistry(checks.AdmissionPolicy)
	if err != nil {
		return nil, err
	}
	for _, p := range checks.ProducerTable() {
		if _, err = reg.Register(p.Spec); err != nil {
			return nil, err
		}
	}
	reg.Seal()
	return reg, nil
}

// Inventory is one complete read of the hosting inventory as the ledger
// observes it.
func Inventory() (admission.InventoryObservation, error) {
	s, err := checks.HostingInventory()
	if err != nil {
		return admission.InventoryObservation{}, err
	}
	return admission.InventoryObservation{Accounts: s.Accounts, Domains: s.Domains, AmbiguousDomains: s.AmbiguousDomains, Incarnations: s.Incarnations}, nil
}
