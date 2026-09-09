package ci

import (
	"fmt"
	"path"
	"reflect"
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
	grants, err := writableGrants(unitLines(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) == 0 {
		t.Fatal("unit grants no writable paths; the sandbox allow-list is gone")
	}
	return grants
}

func writableGrants(lines []string) ([]string, error) {
	byDirective := map[string][]string{}
	var directives []string
	inService := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// The packaged unit uses one directive per line. A continuation can
		// make the next apparent directive part of an unrelated setting.
		if strings.HasSuffix(line, "\\") {
			return nil, fmt.Errorf("writable-path gate does not support continued unit lines")
		}
		if strings.HasPrefix(line, "[") {
			inService = line == "[Service]"
			continue
		}
		if !inService {
			continue
		}
		directive, value, ok := strings.Cut(line, "=")
		directive = strings.TrimSpace(directive)
		root, managed := managedDirectoryRoots[directive]
		if !ok || (!managed && directive != "ReadWritePaths") {
			continue
		}
		if _, seen := byDirective[directive]; !seen {
			directives = append(directives, directive)
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			byDirective[directive] = nil
			continue
		}
		for _, field := range fields {
			name := strings.TrimPrefix(field, "-")
			if managed {
				name = field
			}
			// Reject unsupported quoting, specifiers and managed-directory
			// flags rather than claiming a different path or a read-only mount.
			if strings.ContainsAny(name, "\"'\\:%") || path.IsAbs(name) == managed || hasParentComponent(name) {
				return nil, fmt.Errorf("invalid or unsupported %s path %q", directive, field)
			}
			if managed {
				name = root + "/" + name
			}
			byDirective[directive] = append(byDirective[directive], normalizeRunPath(name))
		}
	}
	var grants []string
	for _, directive := range directives {
		grants = append(grants, byDirective[directive]...)
	}
	return grants, nil
}

func hasParentComponent(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func TestWritableGrantsHonorsServiceSectionAndResets(t *testing.T) {
	for _, tc := range []struct {
		name, unit string
		want       []string
	}{
		{"wrong section", "[Unit]\nReadWritePaths=/home\n[Service]\nReadWritePaths=/etc/csm\n[Install]\nStateDirectory=other", []string{"/etc/csm"}},
		{"reset paths", "[Service]\nReadWritePaths=/home\nReadWritePaths=\nReadWritePaths=-/var/run/csm", []string{"/run/csm"}},
		{"reset directories", "[Service]\nStateDirectory=old\nStateDirectory=\nStateDirectory=csm", []string{"/var/lib/csm"}},
		{"empty after reset", "[Service]\nReadWritePaths=/home\nReadWritePaths=", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := writableGrants(strings.Split(tc.unit, "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("grants = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWritableGrantsCannotInventRejectedDirectories(t *testing.T) {
	for _, directive := range []string{
		"StateDirectory=../../home",
		"StateDirectory=/home",
		"ReadWritePaths=/home/../etc",
		"ReadWritePaths=home",
		"StateDirectory=csm::ro",
		"StateDirectory=%n",
		"ReadWritePaths=\"/home\"",
		"ExecStart=/bin/true \\\nReadWritePaths=/home",
	} {
		t.Run(directive, func(t *testing.T) {
			grants, err := writableGrants(strings.Split("[Service]\n"+directive, "\n"))
			if err == nil {
				t.Errorf("invalid or unsupported directive returned grants %v without an error", grants)
			}
		})
	}
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

func underGrant(name, grant string) bool {
	if !path.IsAbs(name) || !path.IsAbs(grant) {
		return false
	}
	name, grant = normalizeRunPath(path.Clean(name)), normalizeRunPath(path.Clean(grant))
	return grant == "/" || name == grant || strings.HasPrefix(name, grant+"/")
}

// A path the daemon writes but the sandbox does not grant fails at runtime with
// EROFS, and for the state database that is a crash loop. The inventory is the
// place where those two lists are written down, so it is the place to compare
// them.
func TestEveryInventoriedWriteIsGrantedBySandbox(t *testing.T) {
	for _, err := range inventoriedWriteErrors(privops.Operations(), unitWritableGrants(t)) {
		t.Error(err)
	}
}

func inventoriedWriteErrors(ops []privops.Op, grants []string) []string {
	errs := comparableInventoryErrors(ops, grants)
	for _, op := range ops {
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
				errs = append(errs, fmt.Sprintf("operation %q writes %s, which the systemd unit does not grant", op.ID, w))
			}
		}
	}
	return errs
}

// The reverse direction: a grant nothing claims is either a path CSM no longer
// writes (and the sandbox is wider than it needs to be) or an operation missing
// from the inventory, which is exactly what the matrix promises not to have.
func TestEverySandboxGrantIsClaimedByAnOperation(t *testing.T) {
	for _, err := range sandboxGrantErrors(privops.Operations(), unitWritableGrants(t)) {
		t.Error(err)
	}
}

func sandboxGrantErrors(ops []privops.Op, grants []string) []string {
	errs := comparableInventoryErrors(ops, grants)
	for _, grant := range grants {
		claimed := false
		for _, op := range ops {
			if op.Unsandboxed {
				continue
			}
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
			errs = append(errs, fmt.Sprintf("systemd unit grants %s but no inventoried operation writes there", grant))
		}
	}
	return errs
}

func comparableInventoryErrors(ops []privops.Op, grants []string) []string {
	var errs []string
	if len(ops) == 0 {
		errs = append(errs, "inventory is empty")
	}
	if len(grants) == 0 {
		errs = append(errs, "unit grants no writable paths")
	}
	for _, grant := range grants {
		if !path.IsAbs(grant) || hasParentComponent(grant) {
			errs = append(errs, fmt.Sprintf("invalid writable grant %q", grant))
		}
	}
	writes := 0
	for _, op := range ops {
		if op.Unsandboxed {
			continue
		}
		for _, w := range op.Writes {
			if path.IsAbs(w) {
				writes++
			}
		}
	}
	if writes == 0 {
		errs = append(errs, "inventory has no sandboxed filesystem writes")
	}
	return errs
}

func TestSandboxComparisonsRejectVacuousClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ops    []privops.Op
		grants []string
	}{
		{"empty inventory", nil, []string{"/home"}},
		{"empty grants", []privops.Op{{ID: "test.read"}}, nil},
		{"no sandboxed filesystem writes", []privops.Op{{ID: "test.resource", Writes: []string{"kernel:test"}}}, []string{"/home"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(inventoriedWriteErrors(tc.ops, tc.grants)) == 0 {
				t.Error("forward comparison passed without a comparable inventory and grants")
			}
			if len(sandboxGrantErrors(tc.ops, tc.grants)) == 0 {
				t.Error("reverse comparison passed without a comparable inventory and grants")
			}
		})
	}
	for _, op := range []privops.Op{
		{ID: "test.empty", Writes: []string{""}},
		{ID: "test.external", Writes: []string{"/home"}, Unsandboxed: true},
		{ID: "test.prefix", Writes: []string{"/home-other"}},
	} {
		if len(sandboxGrantErrors([]privops.Op{op}, []string{"/home"})) == 0 {
			t.Errorf("%s incorrectly claims a sandbox grant", op.ID)
		}
	}
}

func TestUnderGrantRequiresContainedAbsolutePaths(t *testing.T) {
	for _, tc := range []struct {
		path, grant string
		want        bool
	}{
		{"/home/user", "/home", true},
		{"/home-other", "/home", false},
		{"/home/../etc/shadow", "/home", false},
		{"/home", "", false},
		{"", "", false},
		{"/run/csm/socket", "/var/run/csm", true},
		{"/etc/csm", "/", true},
	} {
		if got := underGrant(tc.path, tc.grant); got != tc.want {
			t.Errorf("underGrant(%q, %q) = %v, want %v", tc.path, tc.grant, got, tc.want)
		}
	}
}
