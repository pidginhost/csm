package checks

import (
	"context"
	"os"
	"strings"
	"testing"
)

// A dormant install reads like a live one and a live one reads like a dormant
// one, so triage orders its queue wrongly in both directions. A poisoned
// siteurl found in an unserved root is not an emergency today; the same
// poisoning on a served root is.

// servedRootsFS answers the panel domain map as well as the wp-config globs.
type servedRootsFS struct {
	mockOSGlobRoots
	domainMap    string
	domainMapErr error
}

func (m *servedRootsFS) ReadFile(name string) ([]byte, error) {
	if name == userdataDomainsPath {
		if m.domainMapErr != nil {
			return nil, m.domainMapErr
		}
		return []byte(m.domainMap), nil
	}
	return nil, os.ErrNotExist
}

func TestWPConfigPaths_SeparatesServedFromDormantRoots(t *testing.T) {
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{files: []string{
			"/home/alice/public_html/wp-config.php",
			"/home/alice/dormant.example/wp-config.php",
		}},
		domainMap: "live.example: alice==alice==main==live.example==/home/alice/public_html==1.2.3.4==1.2.3.4\n",
	}
	t.Cleanup(func() { osFS = old })

	_, served := wpConfigPaths(context.Background())

	if got := served["/home/alice/public_html/wp-config.php"]; got != servedByPanel {
		t.Errorf("panel-mapped root state = %v, want servedByPanel", got)
	}
	if got := served["/home/alice/dormant.example/wp-config.php"]; got != notServed {
		t.Errorf("unmapped root state = %v, want notServed", got)
	}
}

// Without the panel's map there is no basis to call anything dormant, and
// saying so would rank a live install as safe to leave.
func TestWPConfigPaths_UnknownWhenDomainMapUnreadable(t *testing.T) {
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}},
		domainMapErr:    os.ErrPermission,
	}
	t.Cleanup(func() { osFS = old })

	_, served := wpConfigPaths(context.Background())

	if got := served["/home/alice/public_html/wp-config.php"]; got != servedUnknown {
		t.Errorf("state = %v, want servedUnknown when the domain map cannot be read", got)
	}
}

func TestWPConfigPaths_EmptyDomainMapLeavesHomeStateUnknown(t *testing.T) {
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}},
	}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	_, served, domains := wpConfigPathsWithDomains(ctx)
	if got := served["/home/alice/public_html/wp-config.php"]; got != servedUnknown {
		t.Errorf("state = %v, want servedUnknown for an empty authoritative map", got)
	}
	if domains != nil {
		t.Errorf("empty map exposed domain ownership data: %v", domains)
	}
	if !incomplete.contains("db_content") {
		t.Fatal("empty domain map did not mark the scan incomplete")
	}
}

func TestWPConfigPaths_PartialMapDisablesOwnershipAndUnknownFallback(t *testing.T) {
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{files: []string{
			"/home/alice/public_html/wp-config.php",
			"/home/alice/dormant.example/wp-config.php",
		}},
		domainMap: "live.example: alice==root==main==live.example==/home/alice/public_html\n" +
			"broken.example: bob==root==addon==broken.example==/home/alice/bob-site\n",
	}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(
		ContextWithAccountScope(context.Background(), "alice"))
	_, served, domains := wpConfigPathsWithDomains(ctx)
	if got := served["/home/alice/public_html/wp-config.php"]; got != servedByPanel {
		t.Errorf("valid mapped root state = %v, want servedByPanel", got)
	}
	if got := served["/home/alice/dormant.example/wp-config.php"]; got != servedUnknown {
		t.Errorf("unmapped root state = %v, want unknown from partial map", got)
	}
	if domains != nil {
		t.Errorf("partial map exposed ownership data: %v", domains)
	}
	if !incomplete.contains("db_content") {
		t.Fatal("rejected map row did not mark the scan incomplete")
	}
}

func TestWPConfigPaths_CollectsAllOwnersBeforeAccountFilter(t *testing.T) {
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}},
		domainMap: "alice.example: alice==root==main==alice.example==/home/alice/public_html\n" +
			"shop.alice.example: bob==root==main==shop.alice.example==/home/bob/public_html\n",
	}
	t.Cleanup(func() { osFS = old })

	paths, _, domains := wpConfigPathsWithDomains(
		ContextWithAccountScope(context.Background(), "alice"))
	if len(paths) != 1 || paths[0] != "/home/alice/public_html/wp-config.php" {
		t.Fatalf("scoped paths = %v, want only Alice", paths)
	}
	if got := domains["bob"]; len(got) != 1 || got[0] != "shop.alice.example" {
		t.Fatalf("account filtering lost Bob's delegated ownership: %v", domains)
	}
}

func TestWPConfigPaths_PreservesWildcardOwnershipAndServedRoot(t *testing.T) {
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}},
		domainMap: "tenant.example.com: bob==root==main==tenant.example.com==/home/bob/public_html\n" +
			"*.tenant.example.com: alice==root==sub==tenant.example.com==/home/alice/public_html\n",
	}
	t.Cleanup(func() { osFS = old })

	paths, served, domains := wpConfigPathsWithDomains(
		ContextWithAccountScope(context.Background(), "alice"))
	if len(paths) != 1 || paths[0] != "/home/alice/public_html/wp-config.php" {
		t.Fatalf("wildcard vhost paths = %v, want Alice's served root", paths)
	}
	if got := served[paths[0]]; got != servedByPanel {
		t.Errorf("wildcard vhost state = %v, want servedByPanel", got)
	}
	if got := domains["alice"]; len(got) != 1 || got[0] != "*.tenant.example.com" {
		t.Errorf("wildcard ownership = %v, want Alice's wildcard", domains)
	}
}

func TestWPConfigPaths_MapDeclarationSurvivesDiscoveryRace(t *testing.T) {
	const path = "/home/alice/public_html/wp-config.php"
	lstatCalls := 0
	old := osFS
	osFS = &servedRootsFS{
		mockOSGlobRoots: mockOSGlobRoots{
			mockOS: mockOS{lstat: func(string) (os.FileInfo, error) {
				lstatCalls++
				if lstatCalls == 1 {
					return nil, os.ErrNotExist
				}
				return fakeFileInfo{name: "wp-config.php"}, nil
			}},
			files: []string{path},
		},
		domainMap: "alice.example: alice==root==main==alice.example==/home/alice/public_html\n",
	}
	t.Cleanup(func() { osFS = old })

	_, served := wpConfigPaths(context.Background())
	if got := served[path]; got != servedByPanel {
		t.Errorf("panel-declared path discovered on retry = %v, want servedByPanel", got)
	}
}

func TestDocrootServedNote_SaysWhichAndStaysSilentOnUnknown(t *testing.T) {
	if note := docrootServedNote(servedByPanel); !strings.Contains(note, "live now") {
		t.Errorf("served note = %q", note)
	}
	if note := docrootServedNote(notServed); !strings.Contains(note, "not currently served") {
		t.Errorf("dormant note = %q", note)
	}
	if note := docrootServedNote(servedUnknown); note != "" {
		t.Errorf("unknown state must not claim either way, got %q", note)
	}
}

// Every database finding carries the framing, not just the siteurl ones.
func TestDBContentFindingDetails_CarriesServedState(t *testing.T) {
	dormant := dbContentFindingDetails(wpDBCreds{dbName: "wp", docrootServed: notServed}, "wp_")
	if !strings.Contains(dormant, "not currently served") {
		t.Errorf("details lost the dormant framing:\n%s", dormant)
	}
	unknown := dbContentFindingDetails(wpDBCreds{dbName: "wp", docrootServed: servedUnknown}, "wp_")
	if strings.Contains(unknown, "Document root:") {
		t.Errorf("details guessed at an unknown state:\n%s", unknown)
	}
}
