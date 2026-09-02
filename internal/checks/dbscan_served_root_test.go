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
