package checks

import (
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/platform"
)

// accountOwnerForDomain is the production mapping: cPanel's /etc/userdomains
// file, which misses on every other panel. Tests in other packages inject a
// table through SetAccountOwnerLookupForTest.
var accountOwnerForDomain = func(domain string) (string, bool) {
	if !platform.Detect().IsCPanel() {
		return "", false
	}
	owner := domainAccountOwner(domain)
	return owner, owner != ""
}

// AccountOwnerForDomain resolves the hosting account that owns a mail
// domain, for producers that know a verified local mailbox or domain.
// Correlation never calls it; owners are resolved where the mailbox is known.
func AccountOwnerForDomain(domain string) (string, bool) {
	return accountOwnerForDomain(domain)
}

// SetAccountOwnerLookupForTest replaces the domain-to-owner mapping and
// returns a function that restores it. Test-only seam for packages that
// cannot reach this package's filesystem fakes.
func SetAccountOwnerLookupForTest(fn func(domain string) (string, bool)) func() {
	prev := accountOwnerForDomain
	accountOwnerForDomain = fn
	return func() { accountOwnerForDomain = prev }
}

// MailOwner returns the hosting account for a mailbox or bare domain, or ""
// when the mapping is unavailable. It never returns the mailbox or domain
// itself as an owner.
func MailOwner(mailboxOrDomain string) string {
	domain := strings.TrimSpace(mailboxOrDomain)
	if at := strings.LastIndexByte(domain, '@'); at >= 0 {
		domain = domain[at+1:]
	}
	if domain == "" {
		return ""
	}
	owner, _ := AccountOwnerForDomain(domain)
	return owner
}

// hostingAccountForUser is the production mapping from a system user name
// to a hosting account. Tests in other packages inject a table through
// SetHostingAccountLookupForTest.
var hostingAccountForUser = func(name string) string {
	if name == "" || name == "root" || name == "unknown" || strings.ContainsAny(name, "/\\") {
		return ""
	}
	home := defaultUIDCache.HomeDir(name)
	if !filepath.IsAbs(home) {
		return ""
	}
	if _, account, ok := accountRootOf(filepath.Join(home, "probe")); ok && account == name {
		return name
	}
	return ""
}

// HostingAccountForUser returns name when it is a hosting account: its
// passwd home directory sits directly under a configured account root.
// Root, system and service users, unknown names and the lookup sentinel
// resolve to "". The passwd cache is the same one process findings use for
// uid resolution, so tests point both at one fixture file.
func HostingAccountForUser(name string) string {
	return hostingAccountForUser(name)
}

// SetHostingAccountLookupForTest replaces the user-to-account mapping and
// returns a function that restores it. Test-only seam for packages that
// cannot reach this package's passwd and account-root fakes.
func SetHostingAccountLookupForTest(fn func(name string) string) func() {
	prev := hostingAccountForUser
	hostingAccountForUser = fn
	return func() { hostingAccountForUser = prev }
}

// ftpAccountOwner resolves an FTP login name: a virtual account is
// user@domain and belongs to the domain's owner; anything else is a system
// account name that must itself be a hosting account.
func ftpAccountOwner(account string) string {
	if strings.Contains(account, "@") {
		return MailOwner(account)
	}
	return HostingAccountForUser(account)
}

// accountHomeExists reports whether a configured account root contains a
// directory named user. It distinguishes a hosting account's cron spool from
// a system or service user's.
func accountHomeExists(user string) bool {
	if user == "" || user == "root" || strings.ContainsAny(user, "/\\") {
		return false
	}
	for _, root := range accountHomeRoots() {
		if info, err := osFS.Stat(filepath.Join(root, user)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// installOwner resolves the hosting account that owns a CMS install from
// its configuration path. ok is false outside every account root; callers
// keep their display label but must not stamp a tenant.
func installOwner(configPath string) (string, bool) {
	_, account, ok := accountRootOf(configPath)
	return account, ok
}
