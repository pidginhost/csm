package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/platform"
)

// HostingSnapshot contains all required inventory sources read without error.
// It does not establish an atomic read.
type HostingSnapshot struct {
	// Accounts is sorted and contains no duplicates.
	Accounts []string
	// Domains maps canonical domains to listed accounts. Ambiguous and
	// malformed rows are excluded.
	Domains map[string]string
	// AmbiguousDomains counts domains listed for more than one owner. They
	// are left out of Domains, so evidence about them stays host-scoped.
	AmbiguousDomains int
	// Incarnations maps every account to a server-owned token that changes
	// when the account is deleted and created again.
	Incarnations map[string]string
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
	snap := HostingSnapshot{Accounts: []string{}, Domains: map[string]string{}, Incarnations: map[string]string{}}
	known := map[string]bool{}
	for _, e := range registry {
		name := e.Name()
		if e.IsDir() || !admission.ValidAccountName(name) || known[name] {
			continue
		}
		known[name] = true
		snap.Accounts = append(snap.Accounts, name)
		if snap.Incarnations[name], err = cpanelIncarnation(name); err != nil {
			return HostingSnapshot{}, err
		}
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
// An account listed under several roots is the one in the first.
func homeRootInventory() (HostingSnapshot, error) {
	snap := HostingSnapshot{Accounts: []string{}, Domains: map[string]string{}, Incarnations: map[string]string{}}
	for _, root := range accountHomeRoots() {
		entries, err := osFS.ReadDir(root)
		if err != nil {
			return HostingSnapshot{}, err
		}
		for _, e := range entries {
			name := e.Name()
			if _, seen := snap.Incarnations[name]; !admission.ValidAccountName(name) || seen {
				continue
			}
			if e.Type()&os.ModeSymlink != 0 {
				return HostingSnapshot{}, fmt.Errorf("account home for %s is a symlink", name)
			}
			if !e.IsDir() {
				continue
			}
			snap.Accounts = append(snap.Accounts, name)
			if snap.Incarnations[name], err = accountIncarnation(filepath.Join(root, name)); err != nil {
				return HostingSnapshot{}, err
			}
		}
	}
	sort.Strings(snap.Accounts)
	return snap, nil
}

// cpanelIncarnation is the creation time cPanel records in an account's
// user file. A recreated account has a new one; edits keep it. cPanel's own
// system entries record zero, which is stable and therefore valid.
func cpanelIncarnation(name string) (string, error) {
	data, err := osFS.ReadFile(filepath.Join("/var/cpanel/users", name))
	if err != nil {
		return "", err
	}
	var token string
	for _, line := range strings.Split(string(data), "\n") {
		v, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "STARTDATE=")
		if !ok {
			continue
		}
		_, parseErr := strconv.ParseInt(v, 10, 64)
		if token != "" || len(v) > 19 || parseErr != nil || strings.Trim(v, "0123456789") != "" {
			return "", fmt.Errorf("cPanel user file for %s has an invalid creation date", name)
		}
		token = "startdate:" + v
	}
	if token != "" {
		return token, nil
	}
	return "", fmt.Errorf("cPanel user file for %s names no creation date", name)
}

// accountIncarnation names one incarnation of the account home at path.
var accountIncarnation = accountDirIncarnation
