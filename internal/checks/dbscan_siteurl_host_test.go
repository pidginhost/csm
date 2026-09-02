package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A hijack that keeps a clean URL shape passes siteURLPoisonReason: the
// karmaboutique poisoning was caught only because it carried a query string.
// The host is the stronger signal -- but on its own it reports every migrated
// site, which is why siteURLPoisonReason deliberately does not test it.
//
// The served state resolves that. A root the panel serves under domains the
// account owns, whose WordPress address points somewhere unrelated, is not a
// migration: a migrated site is no longer served here.

func siteurlHostFinding(t *testing.T, value string, served servedState, owned ...string) *alert.Finding {
	t.Helper()
	creds := wpDBCreds{
		dbHost:        "localhost",
		dbName:        "wp",
		dbUser:        "wpuser",
		docrootServed: served,
		panelDomains:  newPanelDomainOwnership(map[string][]string{"alice": owned}),
	}
	return foreignSiteURLFinding("alice", creds, "wp_", "siteurl", value)
}

func TestForeignSiteURL_ServedRootPointingOffAccount(t *testing.T) {
	got := siteurlHostFinding(t, "https://slow.destinyfernandi.example/", servedByPanel, "karmaboutique.example")

	if got == nil {
		t.Fatal("a served root addressed at an unowned domain must be reported")
	}
	if got.Check != "db_siteurl_foreign_host" {
		t.Errorf("check = %q", got.Check)
	}
	if !strings.Contains(got.Details, "destinyfernandi.example") {
		t.Errorf("details must name the address, got:\n%s", got.Details)
	}
}

// The account's own domains are fine, including deeper names below one.
func TestForeignSiteURL_OwnedDomainsAreSilent(t *testing.T) {
	for _, value := range []string{
		"https://karmaboutique.example/",
		"https://www.karmaboutique.example/shop",
		"https://shop.karmaboutique.example/",
		"http://second.example/",
	} {
		if got := siteurlHostFinding(t, value, servedByPanel, "karmaboutique.example", "second.example"); got != nil {
			t.Errorf("owned address %q reported: %s", value, got.Message)
		}
	}
}

func TestForeignSiteURL_UsesMostSpecificPanelOwner(t *testing.T) {
	domains := map[string][]string{
		"alice": {"example.com", "alice.customer.co.uk"},
		"bob":   {"shop.example.com", "customer.co.uk"},
	}
	creds := wpDBCreds{dbName: "wp", docrootServed: servedByPanel, panelDomains: newPanelDomainOwnership(domains)}

	// Bob's delegated child beats Alice's parent. Registrable-domain equality
	// used to suppress this cross-account address as though Alice owned it.
	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://www.shop.example.com/"); got == nil {
		t.Fatal("another account's more-specific domain was treated as Alice's")
	}
	// Conversely, a domain delegated to Alice stays hers even though Bob owns
	// the registrable parent under a multi-label public suffix.
	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://www.alice.customer.co.uk/"); got != nil {
		t.Fatalf("Alice's delegated domain was reported: %s", got.Message)
	}
}

func TestForeignSiteURL_DoesNotTreatSiblingAsOwned(t *testing.T) {
	domains := map[string][]string{
		"alice": {"alice.example.com"},
		"bob":   {"bob.example.com"},
	}
	creds := wpDBCreds{dbName: "wp", docrootServed: servedByPanel, panelDomains: newPanelDomainOwnership(domains)}
	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://bob.example.com/"); got == nil {
		t.Fatal("a sibling domain owned by another account was treated as Alice's")
	}
}

func TestForeignSiteURL_PublicSuffixDoesNotOwnItsChildren(t *testing.T) {
	for _, tc := range []struct {
		owned string
		value string
	}{
		{owned: "com", value: "https://google.com/"},
		{owned: "co.uk", value: "https://customer.co.uk/"},
		{owned: "localhost", value: "https://www.localhost/"},
		{owned: "*.com", value: "https://google.com/"},
		{owned: "*.co.uk", value: "https://customer.co.uk/"},
		{owned: "*.localhost", value: "https://www.localhost/"},
	} {
		if got := siteurlHostFinding(t, tc.value, servedByPanel, tc.owned); got == nil {
			t.Errorf("unownable panel name %q claimed %q", tc.owned, tc.value)
		}
	}
}

func TestForeignSiteURL_IPOwnershipRequiresExactAddress(t *testing.T) {
	domains := map[string][]string{
		"alice": {"192.0.2.10", "*.192.0.2.10", "2.3.4"},
	}
	creds := wpDBCreds{dbName: "wp", docrootServed: servedByPanel, panelDomains: newPanelDomainOwnership(domains)}
	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://192.0.2.10/"); got != nil {
		t.Fatalf("Alice's exact IP address was reported: %s", got.Message)
	}
	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://1.2.3.4/"); got == nil {
		t.Fatal("a domain-shaped suffix was allowed to claim a foreign IP address")
	}
	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://www.192.0.2.10/"); got == nil {
		t.Fatal("an IP address mapping was allowed to claim a DNS descendant")
	}
}

func TestForeignSiteURL_NormalizesIDNAOwnership(t *testing.T) {
	for _, tc := range []struct {
		owned string
		value string
	}{
		{owned: "b\u00fccher.example", value: "https://xn--bcher-kva.example/"},
		{owned: "xn--bcher-kva.example", value: "https://b\u00fccher.example/"},
	} {
		if got := siteurlHostFinding(t, tc.value, servedByPanel, tc.owned); got != nil {
			t.Errorf("IDNA-equivalent address %q for %q reported: %s", tc.value, tc.owned, got.Message)
		}
	}
}

func TestForeignSiteURL_WildcardDelegationUsesMostSpecificOwner(t *testing.T) {
	domains := map[string][]string{
		"alice": {"*.tenant.example.com"},
		"bob":   {"tenant.example.com"},
	}
	creds := wpDBCreds{dbName: "wp", docrootServed: servedByPanel, panelDomains: newPanelDomainOwnership(domains)}

	if got := foreignSiteURLFinding("alice", creds, "wp_", "siteurl", "https://shop.tenant.example.com/"); got != nil {
		t.Fatalf("Alice's wildcard host was reported: %s", got.Message)
	}
	if got := foreignSiteURLFinding("bob", creds, "wp_", "siteurl", "https://shop.tenant.example.com/"); got == nil {
		t.Fatal("Alice's wildcard delegation was treated as Bob's parent domain")
	}
	if got := foreignSiteURLFinding("bob", creds, "wp_", "siteurl", "https://tenant.example.com/"); got != nil {
		t.Fatalf("Bob's exact parent domain was reported: %s", got.Message)
	}
}

// The documented false positive: a site that moved away is no longer served
// here, so an unowned address is expected rather than suspicious.
func TestForeignSiteURL_DormantRootStaysSilent(t *testing.T) {
	if got := siteurlHostFinding(t, "https://moved-elsewhere.example/", notServed, "karmaboutique.example"); got != nil {
		t.Fatalf("migrated site on an unserved root reported: %s", got.Message)
	}
}

// Without the panel's map we do not know whether it is served, so the
// migration explanation cannot be ruled out.
func TestForeignSiteURL_UnknownServedStateStaysSilent(t *testing.T) {
	if got := siteurlHostFinding(t, "https://elsewhere.example/", servedUnknown, "karmaboutique.example"); got != nil {
		t.Fatalf("unknown served state reported: %s", got.Message)
	}
}

// Knowing no domains means the comparison has no basis at all.
func TestForeignSiteURL_NoKnownDomainsStaysSilent(t *testing.T) {
	if got := siteurlHostFinding(t, "https://elsewhere.example/", servedByPanel); got != nil {
		t.Fatalf("reported without knowing which domains the account owns: %s", got.Message)
	}
}

// Shape problems are siteURLPoisonReason's job and are already reported; this
// check must not raise a second finding about the same value.
func TestForeignSiteURL_LeavesMalformedValuesToTheShapeCheck(t *testing.T) {
	for _, value := range []string{
		"", "not a url", "javascript:alert(1)", "https:///nohost",
		// The live poisoning: an unowned host AND a query string. The shape
		// check already reports this one, so reporting it again adds nothing.
		"https://slow.destinyfernandi.example/hos?/pret.js?l=1",
		"https://slow.destinyfernandi.example/x#frag",
	} {
		if got := siteurlHostFinding(t, value, servedByPanel, "karmaboutique.example"); got != nil {
			t.Errorf("malformed value %q double-reported: %s", value, got.Message)
		}
	}
}

func TestCheckWPOptions_EmitsOneStableForeignHostFinding(t *testing.T) {
	rows := [][]string{
		{
			"home\thttps://home.attacker.example/",
			"siteurl\thttps://site.attacker.example/",
		},
		{
			"siteurl\thttps://site.attacker.example/",
			"home\thttps://home.attacker.example/",
		},
	}
	var key string
	for i, queryRows := range rows {
		withMockCoreOptions(t, queryRows)
		creds := wpDBCreds{
			dbHost:        "localhost",
			dbName:        "wp",
			dbUser:        "wpuser",
			docrootServed: servedByPanel,
			panelDomains: newPanelDomainOwnership(map[string][]string{
				"alice": {"alice.example"},
			}),
		}
		var got []alert.Finding
		for _, finding := range checkWPOptions("alice", creds, "wp_") {
			if finding.Check == "db_siteurl_foreign_host" {
				got = append(got, finding)
			}
		}
		if len(got) != 1 {
			t.Fatalf("order %d produced %d foreign-host findings, want 1: %+v", i, len(got), got)
		}
		if !strings.Contains(got[0].Message, "siteurl") {
			t.Errorf("order %d selected a row-order-dependent option: %s", i, got[0].Message)
		}
		if i == 0 {
			key = got[0].Key()
		} else if got[0].Key() != key {
			t.Errorf("finding identity changed with query order: %q != %q", got[0].Key(), key)
		}
	}

	a := siteurlHostFinding(t, "https://first.attacker.example/", servedByPanel, "alice.example")
	b := siteurlHostFinding(t, "https://second.attacker.example/", servedByPanel, "alice.example")
	if a == nil || b == nil || a.Key() != b.Key() {
		t.Fatalf("ongoing foreign-host condition changed identity: a=%v b=%v", a, b)
	}
}

func TestCheckWPOptions_MalformedForeignAddressReportsOnlyInvalidShape(t *testing.T) {
	withMockCoreOptions(t, []string{
		"siteurl\thttps://attacker.example/path?loader=1",
	})
	creds := wpDBCreds{
		dbName:        "wp",
		docrootServed: servedByPanel,
		panelDomains: newPanelDomainOwnership(map[string][]string{
			"alice": {"alice.example"},
		}),
	}
	var got []string
	for _, finding := range checkWPOptions("alice", creds, "wp_") {
		if strings.HasPrefix(finding.Check, "db_siteurl_") {
			got = append(got, finding.Check)
		}
	}
	if len(got) != 1 || got[0] != "db_siteurl_invalid" {
		t.Fatalf("malformed foreign address produced %v, want only db_siteurl_invalid", got)
	}
}
