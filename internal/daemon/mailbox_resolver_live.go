package daemon

import (
	"fmt"

	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/checks"
)

// liveMailboxSource reads cPanel's own files. It holds no lock: the resolver
// serialises its calls.
type liveMailboxSource struct {
	source    learnwatch.Source
	inventory func() (checks.HostingSnapshot, error)
	// accounts is the account list of the last Inventory. Only their homes
	// are opened.
	accounts map[string]learnwatch.Account
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
	return s.inventory()
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
	boxes, skips, err := home.Mailboxes()
	if err != nil {
		return nil, false, err
	}
	lists := map[string][]string{}
	for _, b := range boxes {
		// The main mailbox has no address to list.
		if b.Domain != "" {
			lists[b.Domain] = append(lists[b.Domain], b.Box)
		}
	}
	return lists, len(skips) == 0, nil
}
