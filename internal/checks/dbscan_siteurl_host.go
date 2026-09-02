package checks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
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
	if creds.docrootServed != servedByPanel || len(creds.accountDomains) == 0 {
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
	host := registrableDomain(parsed.Hostname())
	if host == "" {
		return nil
	}
	for _, owned := range creds.accountDomains {
		if registrableDomain(owned) == host {
			return nil
		}
	}

	return &alert.Finding{
		Severity: alert.High,
		Check:    "db_siteurl_foreign_host",
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
