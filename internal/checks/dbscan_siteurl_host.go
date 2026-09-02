package checks

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
	"golang.org/x/net/publicsuffix"
)

// A WordPress address pointing off the account.
//
// siteURLPoisonReason deliberately tests the shape of siteurl and not its
// host, because hosting a site under a domain that is not served locally is
// ordinary: sites move, staging lives elsewhere, a theme demo keeps its vendor
// address. Testing the host alone would report all of them.
//
// What is not ordinary is a document root the panel is serving right now,
// under domains the account owns, whose WordPress address points at an
// unrelated domain. A site that moved is no longer served here; a site that is
// served here should address itself by a name the account holds. That
// combination is either a hijack or a migration left half-finished, and both
// want an operator.
//
// It matters because the shape check only caught the live case by luck: the
// poisoned value carried a query string. A hijack to a plausible-looking
// address passes every shape test there is.

// foreignSiteURLFinding reports a served install addressed at a domain the
// account does not own, or nil when the value is fine, unreadable, or the
// question cannot be answered.
func foreignSiteURLFinding(user string, creds wpDBCreds, prefix, option, value string) *alert.Finding {
	// Only a served root rules out the migration explanation.
	if creds.docrootServed != servedByPanel || !creds.panelDomains.hasAccount(user) {
		return nil
	}
	// A value whose shape is wrong is siteURLPoisonReason's finding, not this
	// one; reporting it twice says nothing new.
	if _, bad := siteURLPoisonReason(value); bad {
		return nil
	}
	parsed, err := url.Parse(strings.TrimSpace(mysqlclient.BatchUnescape(value)))
	if err != nil {
		return nil
	}
	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return nil
	}
	if panelHostOwnedByAccount(creds.panelDomains, user, host) {
		return nil
	}

	return &alert.Finding{
		Severity: alert.High,
		Check:    "db_siteurl_foreign_host",
		DedupKey: foreignSiteURLDedupKey(user, creds, prefix),
		Message: fmt.Sprintf("WordPress %s addresses a domain this account does not own (account: %s): %s",
			option, user, host),
		Details: dbContentFindingDetails(creds, prefix,
			fmt.Sprintf("%s = %s", option, truncateDB(value, 200)),
			"WordPress builds every asset URL from this value, so the address it "+
				"names is loaded on every page of a site the panel is serving right now.",
			"This is reported only for a served document root. A site that moved "+
				"away is no longer served here, which is why an unowned address on a "+
				"dormant root is left alone."),
	}
}

func foreignSiteURLDedupKey(user string, creds wpDBCreds, prefix string) string {
	identity := strings.Join([]string{user, creds.dbHost, creds.dbName, prefix}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("wp-site:%x", digest[:12])
}

// panelDomainOwnership indexes the complete panel map in both directions.
type panelDomainOwnership struct {
	owners    map[string]string
	wildcards map[string]string
	accounts  map[string]struct{}
}

func newPanelDomainOwnership(panelDomains map[string][]string) *panelDomainOwnership {
	if len(panelDomains) == 0 {
		return nil
	}
	ownership := &panelDomainOwnership{
		owners:    make(map[string]string),
		wildcards: make(map[string]string),
		accounts:  make(map[string]struct{}, len(panelDomains)),
	}
	for account, domains := range panelDomains {
		for _, rawDomain := range domains {
			wildcard := strings.HasPrefix(rawDomain, "*.")
			domain := normalizeHost(strings.TrimPrefix(rawDomain, "*."))
			if domain == "" {
				return nil
			}
			owners := ownership.owners
			if wildcard {
				owners = ownership.wildcards
			}
			if owner, exists := owners[domain]; exists && owner != account {
				return nil
			}
			owners[domain] = account
			ownership.accounts[account] = struct{}{}
		}
	}
	if len(ownership.owners) == 0 && len(ownership.wildcards) == 0 {
		return nil
	}
	return ownership
}

func (ownership *panelDomainOwnership) hasAccount(account string) bool {
	if ownership == nil {
		return false
	}
	_, ok := ownership.accounts[account]
	return ok
}

// panelHostOwnedByAccount resolves ownership using the most-specific panel
// domain that covers host. This preserves delegated subdomains: when alice
// owns example.com but bob owns shop.example.com, bob owns both
// shop.example.com and www.shop.example.com.
func panelHostOwnedByAccount(ownership *panelDomainOwnership, account, host string) bool {
	host = normalizeHost(host)
	if ownership == nil || host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		owner, exists := ownership.owners[host]
		return exists && owner == account
	}
	for domain, exact := host, true; ; exact = false {
		// A wildcard delegation is more specific than an exact mapping of its
		// parent, but it never owns the parent name itself. Like an exact
		// ancestor, its base must be an ownable domain: a malformed wildcard
		// such as *.com must not claim every registrable name below it.
		if !exact {
			if owner, exists := ownership.wildcards[domain]; exists {
				if panelDomainOwnsDescendants(domain) {
					return owner == account
				}
			}
		}
		if owner, exists := ownership.owners[domain]; exists {
			// Exact names remain authoritative. An ancestor must itself be an
			// ownable domain; a malformed "com" row cannot claim google.com.
			if exact {
				return owner == account
			}
			if panelDomainOwnsDescendants(domain) {
				return owner == account
			}
		}
		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			break
		}
		domain = domain[dot+1:]
	}
	return false
}

func panelDomainOwnsDescendants(domain string) bool {
	if net.ParseIP(domain) != nil {
		return false
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(domain)
	return err == nil
}
