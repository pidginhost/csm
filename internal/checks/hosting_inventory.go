package checks

import (
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/platform"
)

// HostingSnapshot contains all required inventory sources read without error.
// It does not establish an atomic read or an account incarnation identity.
type HostingSnapshot struct {
	// Accounts is sorted and contains no duplicates.
	Accounts []string
	// Domains maps canonical domains to listed accounts. Ambiguous and
	// malformed rows are excluded.
	Domains map[string]string
	// AmbiguousDomains counts domains listed for more than one owner. They
	// are left out of Domains, so evidence about them stays host-scoped.
	AmbiguousDomains int
}

// HostingInventory reads the hosting accounts and the domains they own. On
// cPanel the account registry is the account list; homes may sit on any
// home partition, so they are not consulted. Elsewhere every account root
// must be readable and its directories are the accounts. A missing or
// unreadable required source fails the whole read: a partial snapshot would
// retire accounts and hand them new generations when they reappear. Off
// cPanel, mount state is not checked: a readable empty root contributes no
// accounts even if its expected filesystem is unmounted. Other readable
// roots still contribute their accounts.
func HostingInventory() (HostingSnapshot, error) {
	if !platform.Detect().IsCPanel() {
		return homeRootInventory()
	}
	registry, err := osFS.ReadDir("/var/cpanel/users")
	if err != nil {
		return HostingSnapshot{}, err
	}
	snap := HostingSnapshot{Accounts: []string{}, Domains: map[string]string{}}
	known := map[string]bool{}
	for _, e := range registry {
		name := e.Name()
		if e.IsDir() || !admission.ValidAccountName(name) || known[name] {
			continue
		}
		known[name] = true
		snap.Accounts = append(snap.Accounts, name)
	}
	sort.Strings(snap.Accounts)
	data, err := osFS.ReadFile("/etc/userdomains")
	if err != nil {
		return HostingSnapshot{}, err
	}
	// Check every row before collapsing duplicates or filtering owners; the
	// legacy lookup keeps the last row and would hide a conflict.
	owners := map[string]string{}
	ambiguous := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		domain, owner := parseUserDomain(line)
		domain = strings.TrimSuffix(domain, ".")
		// More than one trailing dot cannot produce a stable inventory key.
		if domain == "" || strings.HasSuffix(domain, ".") {
			continue
		}
		if old, exists := owners[domain]; exists && old != owner {
			ambiguous[domain] = true
		}
		owners[domain] = owner
	}
	for domain, owner := range owners {
		if !ambiguous[domain] && known[owner] {
			snap.Domains[domain] = owner
		}
	}
	snap.AmbiguousDomains = len(ambiguous)
	return snap, nil
}

// homeRootInventory lists the account directories under every account root.
func homeRootInventory() (HostingSnapshot, error) {
	snap := HostingSnapshot{Accounts: []string{}, Domains: map[string]string{}}
	seen := map[string]bool{}
	for _, root := range accountHomeRoots() {
		entries, err := osFS.ReadDir(root)
		if err != nil {
			return HostingSnapshot{}, err
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() && admission.ValidAccountName(name) && !seen[name] {
				seen[name] = true
				snap.Accounts = append(snap.Accounts, name)
			}
		}
	}
	sort.Strings(snap.Accounts)
	return snap, nil
}
