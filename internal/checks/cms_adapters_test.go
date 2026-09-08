package checks

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/cms"
)

// dbContentOwners returns the runner owner names that are database content
// adapters: db_content itself and every db_content_<cms> owner.
func dbContentOwners(names map[string][]string) []string {
	var out []string
	for owner := range names {
		if owner == "db_content" || strings.HasPrefix(owner, "db_content_") {
			out = append(out, owner)
		}
	}
	sort.Strings(out)
	return out
}

// compareAdaptersToCMSTable reports the first disagreement between the
// runner's adapter owners and the CMS table, in either direction.
func compareAdaptersToCMSTable(owners []string, descriptors []cms.Descriptor) error {
	described := map[string]cms.Kind{}
	for _, d := range descriptors {
		if prev, dup := described[d.DBContentCheck]; dup {
			return fmt.Errorf("owner %q declared by both %s and %s", d.DBContentCheck, prev, d.Kind)
		}
		described[d.DBContentCheck] = d.Kind
		if d.Kind == cms.WordPress && d.DBContentCheck != "db_content" {
			return fmt.Errorf("WordPress adapter owner is %q, want db_content", d.DBContentCheck)
		}
	}
	seen := map[string]bool{}
	for _, owner := range owners {
		if seen[owner] {
			return fmt.Errorf("runner owner %q listed twice", owner)
		}
		seen[owner] = true
		if _, ok := described[owner]; !ok {
			return fmt.Errorf("runner adapter %q has no descriptor in internal/cms", owner)
		}
	}
	for owner, kind := range described {
		if !seen[owner] {
			return fmt.Errorf("%s descriptor names adapter %q, which has no runner", kind, owner)
		}
	}
	return nil
}

// The runner's db_content* owners and the CMS table must agree in both
// directions: an adapter without a descriptor cannot be added, and a
// descriptor cannot be padded without an adapter.
func TestDBContentAdaptersMatchCMSTable(t *testing.T) {
	owners := dbContentOwners(runnerFindingNames)
	if want := "db_content,db_content_drupal,db_content_joomla,db_content_magento,db_content_opencart"; strings.Join(owners, ",") != want {
		t.Fatalf("runner adapters %v, want %s", owners, want)
	}
	if err := compareAdaptersToCMSTable(owners, cms.All()); err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		if _, registered := runnerFindingNames[owner]; !registered || len(runnerFindingNames[owner]) == 0 {
			t.Errorf("%s: adapter owns no finding names", owner)
		}
	}
}

func TestDBContentAdapterGuardRejectsDrift(t *testing.T) {
	owners := dbContentOwners(runnerFindingNames)
	if err := compareAdaptersToCMSTable(append(append([]string(nil), owners...), "db_content_prestashop"), cms.All()); err == nil || !strings.Contains(err.Error(), "db_content_prestashop") {
		t.Errorf("adapter without descriptor accepted: %v", err)
	}
	if err := compareAdaptersToCMSTable(owners[:len(owners)-1], cms.All()); err == nil {
		t.Error("descriptor without adapter accepted")
	}
	padded := append(cms.All(), cms.Descriptor{Kind: "prestashop", DBContentCheck: "db_content_prestashop", PathConstants: []string{"dir_ps"}})
	if err := compareAdaptersToCMSTable(owners, padded); err == nil || !strings.Contains(err.Error(), "prestashop") {
		t.Errorf("padded table accepted: %v", err)
	}
	renamed := cms.All()
	renamed[0].DBContentCheck = "db_content_wp"
	if err := compareAdaptersToCMSTable(owners, renamed); err == nil {
		t.Error("renamed WordPress owner accepted")
	}
}
