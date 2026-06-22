package checks

import (
	"errors"
	"os"
	"sort"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
)

// EnumerateScanAccounts returns the sorted list of cPanel account usernames
// eligible for a server-wide scan. Source of truth: the cPanel user registry
// (/var/cpanel/users) intersected with present home directories (/home/<user>).
// All filesystem access goes through the package osFS hook so it is fakeable.
//
// Fallback: when /var/cpanel/users is absent (non-cPanel platform), the
// function falls back to enumerating /home subdirectories whose names pass
// name validation. This makes the function usable on generic Linux hosts.
//
// A hard FS error reading the registry (not os.ErrNotExist) is propagated as
// an error. An empty registry returns ([]string{}, nil).
func EnumerateScanAccounts(_ *config.Config) ([]string, error) {
	registryEntries, err := osFS.ReadDir("/var/cpanel/users")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if errors.Is(err, os.ErrNotExist) {
		// Non-cPanel platform: fall back to /home subdirectories.
		return enumerateFromHome()
	}

	// Build a set of names present under /home for the intersection step.
	homeEntries, _ := osFS.ReadDir("/home")
	homeSet := make(map[string]struct{}, len(homeEntries))
	for _, e := range homeEntries {
		homeSet[e.Name()] = struct{}{}
	}

	seen := make(map[string]struct{}, len(registryEntries))
	var accounts []string
	for _, e := range registryEntries {
		name := e.Name()
		if !control.ValidScanAccountTarget(name) {
			continue
		}
		if _, inHome := homeSet[name]; !inHome {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		accounts = append(accounts, name)
	}

	sort.Strings(accounts)
	if accounts == nil {
		accounts = []string{}
	}
	return accounts, nil
}

// enumerateFromHome lists /home subdirectory names that pass name validation.
// Used when the cPanel registry is absent.
func enumerateFromHome() ([]string, error) {
	homeEntries, _ := osFS.ReadDir("/home")

	seen := make(map[string]struct{}, len(homeEntries))
	var accounts []string
	for _, e := range homeEntries {
		name := e.Name()
		if !control.ValidScanAccountTarget(name) {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		accounts = append(accounts, name)
	}

	sort.Strings(accounts)
	if accounts == nil {
		accounts = []string{}
	}
	return accounts, nil
}
