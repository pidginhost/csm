package ci

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/privops"
)

// managedDirectoryRoots maps the systemd directory directives to the parent
// systemd creates the named directory under. Those directories are writable
// without a ReadWritePaths entry, so the gate has to count them as grants.
var managedDirectoryRoots = map[string]string{
	"StateDirectory":         "/var/lib",
	"RuntimeDirectory":       "/run",
	"CacheDirectory":         "/var/cache",
	"LogsDirectory":          "/var/log",
	"ConfigurationDirectory": "/etc",
}

// unitWritableGrants returns every path the packaged unit lets the daemon
// write: the ReadWritePaths allow-list with systemd's "tolerate absent" prefix
// stripped, plus the directories systemd creates from the directory
// directives.
func unitWritableGrants(t *testing.T) []string {
	t.Helper()
	var grants []string
	for _, line := range unitLines(t) {
		if strings.HasPrefix(line, "ReadWritePaths=") {
			for _, field := range strings.Fields(strings.TrimPrefix(line, "ReadWritePaths=")) {
				grants = append(grants, normalizeRunPath(strings.TrimPrefix(field, "-")))
			}
			continue
		}
		for directive, root := range managedDirectoryRoots {
			if !strings.HasPrefix(line, directive+"=") {
				continue
			}
			for _, name := range strings.Fields(strings.TrimPrefix(line, directive+"=")) {
				grants = append(grants, root+"/"+name)
			}
		}
	}
	if len(grants) == 0 {
		t.Fatal("unit grants no writable paths; the sandbox allow-list is gone")
	}
	return grants
}

// normalizeRunPath collapses the /var/run compatibility symlink onto /run so a
// grant and an inventory entry that spell the same directory differently still
// compare equal.
func normalizeRunPath(path string) string {
	if path == "/var/run" {
		return "/run"
	}
	if strings.HasPrefix(path, "/var/run/") {
		return "/run/" + strings.TrimPrefix(path, "/var/run/")
	}
	return path
}

func underGrant(path, grant string) bool {
	path, grant = normalizeRunPath(path), normalizeRunPath(grant)
	return path == grant || strings.HasPrefix(path, grant+"/")
}

// A path the daemon writes but the sandbox does not grant fails at runtime with
// EROFS, and for the state database that is a crash loop. The inventory is the
// place where those two lists are written down, so it is the place to compare
// them.
func TestEveryInventoriedWriteIsGrantedBySandbox(t *testing.T) {
	grants := unitWritableGrants(t)
	for _, op := range privops.Operations() {
		if op.Unsandboxed {
			continue
		}
		for _, w := range op.Writes {
			if !strings.HasPrefix(w, "/") {
				continue
			}
			granted := false
			for _, grant := range grants {
				if underGrant(w, grant) {
					granted = true
					break
				}
			}
			if !granted {
				t.Errorf("operation %q writes %s, which the systemd unit does not grant; add the grant to build/packaging/systemd/csm.service and cmd/csm/systemd_unit.go, or mark the operation Unsandboxed", op.ID, w)
			}
		}
	}
}

// The reverse direction: a grant nothing claims is either a path CSM no longer
// writes (and the sandbox is wider than it needs to be) or an operation missing
// from the inventory, which is exactly what the matrix promises not to have.
func TestEverySandboxGrantIsClaimedByAnOperation(t *testing.T) {
	for _, grant := range unitWritableGrants(t) {
		claimed := false
		for _, op := range privops.Operations() {
			for _, w := range op.Writes {
				if underGrant(w, grant) || underGrant(grant, w) {
					claimed = true
					break
				}
			}
			if claimed {
				break
			}
		}
		if !claimed {
			t.Errorf("systemd unit grants %s but no inventoried operation writes there; add the operation to internal/privops or drop the grant", grant)
		}
	}
}
