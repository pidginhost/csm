package admissionowner

import (
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/checks"
)

// Registry registers every producer of the producer table against the
// check registry's admission policy and seals it. The producer handles are
// the owner's: only it mints evidence.
func Registry() (*admission.Registry, map[admission.ProducerID]*admission.Producer, error) {
	reg, err := admission.NewRegistry(checks.AdmissionPolicy)
	if err != nil {
		return nil, nil, err
	}
	producers := map[admission.ProducerID]*admission.Producer{}
	for _, p := range checks.ProducerTable() {
		handle, err := reg.Register(p.Spec)
		if err != nil {
			return nil, nil, err
		}
		producers[handle.ID()] = handle
	}
	reg.Seal()
	return reg, producers, nil
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
