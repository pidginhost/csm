package daemon

import (
	"fmt"
	"slices"

	"github.com/pidginhost/csm/internal/antispam/dovecot"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/checks"
)

// liveMailboxSource reads cPanel's own files. It holds no lock: the resolver
// serialises its calls.
type liveMailboxSource struct {
	source    learnwatch.Source
	inventory func() (checks.HostingSnapshot, error)
	// accounts and domains are the last Inventory's. Only these homes are
	// opened and only these domains are read.
	accounts map[string]learnwatch.Account
	domains  map[string]string
}

func newLiveMailboxSource(accounts learnwatch.Source) cpanelMailboxSource {
	return &liveMailboxSource{source: accounts, inventory: checks.HostingInventory}
}

func (s *liveMailboxSource) Inventory() (checks.HostingSnapshot, error) {
	accounts, _, err := learnwatch.Accounts(s.source)
	if err != nil {
		return checks.HostingSnapshot{}, err
	}
	s.accounts = make(map[string]learnwatch.Account, len(accounts))
	for _, a := range accounts {
		s.accounts[a.Name] = a
	}
	snapshot, err := s.inventory()
	s.domains = snapshot.Domains
	return snapshot, err
}

func (s *liveMailboxSource) Mailboxes(account string) (map[string][]string, bool, error) {
	a, ok := s.accounts[account]
	if !ok {
		return nil, false, fmt.Errorf("account %q is not in the account list", account)
	}
	home, err := learnwatch.OpenHome(a)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = home.Close() }()
	boxes, skips, err := home.DomainMailboxes(s.hostedDomains(account))
	if err != nil {
		return nil, false, err
	}
	lists := map[string][]string{}
	for _, b := range boxes {
		domain := normalizeSprayMailbox(b.Domain)
		lists[domain] = append(lists[domain], normalizeSprayMailbox(b.Box))
	}
	// Folding can reorder a list and merge entries.
	for domain, list := range lists {
		slices.Sort(list)
		lists[domain] = slices.Compact(list)
	}
	return lists, len(skips) == 0, nil
}

// hostedDomains lists the valid domains the last Inventory gave account, in
// its lower-case spelling. ~/etc is not listed.
//
// ponytail: a directory spelled differently from its domain is not seen, so its
// mailboxes answer Missing; list ~/etc for case variants if a host ever has one.
func (s *liveMailboxSource) hostedDomains(account string) []string {
	var domains []string
	for domain, owner := range s.domains {
		if owner == account && dovecot.ValidDomain(domain) {
			domains = append(domains, domain)
		}
	}
	slices.Sort(domains)
	return domains
}
