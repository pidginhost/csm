package inventory

import (
	"sort"
	"testing"
)

// fakeFS is an in-memory FS for deterministic enumeration tests.
type fakeFS struct {
	files    map[string]string // path -> content
	readErrs map[string]error
	globErr  error
}

func (f fakeFS) Glob(pattern string) ([]string, error) {
	if f.globErr != nil {
		return nil, f.globErr
	}
	var out []string
	for p := range f.files {
		if ok, _ := matchGlob(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f fakeFS) ReadFile(name string) ([]byte, error) {
	if err, ok := f.readErrs[name]; ok {
		return nil, err
	}
	c, ok := f.files[name]
	if !ok {
		return nil, errNotFound
	}
	return []byte(c), nil
}

var errNotFound = &fsError{"not found"}

type fsError struct{ s string }

func (e *fsError) Error() string { return e.s }

// matchGlob does a minimal "/etc/valiases/*" style match: prefix dir + no
// further slash. Enough for the fixed globs this source uses.
func matchGlob(pattern, path string) (bool, error) {
	const star = "/*"
	if len(pattern) > len(star) && pattern[len(pattern)-len(star):] == star {
		dir := pattern[:len(pattern)-1] // keep trailing slash
		if len(path) <= len(dir) || path[:len(dir)] != dir {
			return false, nil
		}
		rest := path[len(dir):]
		for i := 0; i < len(rest); i++ {
			if rest[i] == '/' {
				return false, nil
			}
		}
		return true, nil
	}
	return pattern == path, nil
}

func TestCPanelSource_Forwarders(t *testing.T) {
	fs := fakeFS{files: map[string]string{
		"/etc/localdomains": "psihologa.test\nhosted.test\n",
		"/etc/userdomains":  "psihologa.test: anauser\nhosted.test: bobuser\n",
		"/etc/valiases/psihologa.test": "" +
			"# cPanel-generated\n" +
			"contact: psi@yahoo.com\n" +
			"owner: owner@psihologa.test, ext@gmail.com\n" +
			"void: :fail: No Such User Here\n" +
			"*: :blackhole:\n",
		"/etc/valiases/hosted.test": "" +
			"team: a@hosted.test\n",
	}}

	src := &CPanelSource{
		fs:               fs,
		valiasGlob:       "/etc/valiases/*",
		localDomainsPath: "/etc/localdomains",
		userDomainsPath:  "/etc/userdomains",
	}

	fwds, err := src.Forwarders()
	if err != nil {
		t.Fatalf("Forwarders() error: %v", err)
	}
	// contact@, owner@ (psihologa.test) + team@ (hosted.test) = 3; :fail:/:blackhole: excluded.
	if len(fwds) != 3 {
		t.Fatalf("got %d forwarders, want 3: %+v", len(fwds), fwds)
	}

	bySource := map[string]Forwarder{}
	for _, f := range fwds {
		bySource[f.Source] = f
	}

	contact, ok := bySource["contact@psihologa.test"]
	if !ok {
		t.Fatal("missing contact@psihologa.test")
	}
	if contact.Owner != "anauser" {
		t.Errorf("owner = %q, want anauser", contact.Owner)
	}
	if !contact.ForwardOnly || contact.KeepLocal {
		t.Errorf("contact should be forward-only: %+v", contact)
	}
	if !contact.HasFreeProvider() {
		t.Error("contact -> yahoo should be a free provider")
	}

	owner := bySource["owner@psihologa.test"]
	if !owner.KeepLocal || owner.ForwardOnly {
		t.Errorf("owner should keep local + forward: %+v", owner)
	}

	team := bySource["team@hosted.test"]
	if team.HasExternal() {
		t.Error("team@ is a local-only alias, must not be external")
	}
	if team.Owner != "bobuser" {
		t.Errorf("team owner = %q, want bobuser", team.Owner)
	}
}

func TestCPanelSource_NoLocalDomainsClassifiesAllExternal(t *testing.T) {
	// With /etc/localdomains unreadable, a hosted-domain target must still be
	// reported (as external) rather than silently dropped.
	fs := fakeFS{files: map[string]string{
		"/etc/valiases/psihologa.test": "owner: owner@psihologa.test\n",
	}}
	src := &CPanelSource{
		fs:               fs,
		valiasGlob:       "/etc/valiases/*",
		localDomainsPath: "/etc/localdomains",
		userDomainsPath:  "/etc/userdomains",
	}
	fwds, err := src.Forwarders()
	if err != nil {
		t.Fatal(err)
	}
	if len(fwds) != 1 || !fwds[0].HasExternal() {
		t.Errorf("want 1 external forwarder when localdomains missing, got %+v", fwds)
	}
}

func TestCPanelSource_VirtualDomainsAreLocal(t *testing.T) {
	fs := fakeFS{files: map[string]string{
		"/etc/virtualdomains":       "hosted.test: owner\n",
		"/etc/valiases/hosted.test": "team: team@hosted.test\n",
	}}
	src := &CPanelSource{
		fs:                 fs,
		valiasGlob:         "/etc/valiases/*",
		localDomainsPath:   "/etc/localdomains",
		virtualDomainsPath: "/etc/virtualdomains",
		userDomainsPath:    "/etc/userdomains",
	}

	fwds, err := src.Forwarders()
	if err != nil {
		t.Fatalf("Forwarders() error: %v", err)
	}
	if len(fwds) != 1 {
		t.Fatalf("got %d forwarders, want 1: %+v", len(fwds), fwds)
	}
	if fwds[0].HasExternal() || fwds[0].ForwardOnly || !fwds[0].KeepLocal {
		t.Errorf("virtualdomains target should be local, got %+v", fwds[0])
	}
}

func TestCPanelSource_LoadersTolerateMalformedFiles(t *testing.T) {
	fs := fakeFS{files: map[string]string{
		"/etc/localdomains": "" +
			"# comment\n" +
			"HOSTED.TEST.\n" +
			": missing-domain\n" +
			"external.test: owner\n" +
			"bad line with spaces\n",
		"/etc/userdomains": "" +
			"malformed\n" +
			": missing-domain\n" +
			"Hosted.Test.: siteowner\n" +
			"other.test:\n",
		"/etc/valiases/hosted.test": "team: team@hosted.test, ext@gmail.com\n",
	}}
	src := &CPanelSource{
		fs:               fs,
		valiasGlob:       "/etc/valiases/*",
		localDomainsPath: "/etc/localdomains",
		userDomainsPath:  "/etc/userdomains",
	}
	localDomains := src.loadLocalDomains()
	for _, malformed := range []string{": missing-domain", "bad line with spaces"} {
		if localDomains[malformed] {
			t.Fatalf("malformed local-domain line %q must be skipped", malformed)
		}
	}
	if !localDomains["external.test"] {
		t.Fatal("domain: owner form should still load the domain part")
	}

	fwds, err := src.Forwarders()
	if err != nil {
		t.Fatalf("Forwarders() error: %v", err)
	}
	if len(fwds) != 1 {
		t.Fatalf("got %d forwarders, want 1: %+v", len(fwds), fwds)
	}
	if fwds[0].Owner != "siteowner" {
		t.Errorf("owner = %q, want siteowner", fwds[0].Owner)
	}
	if !fwds[0].KeepLocal || fwds[0].ForwardOnly || !fwds[0].HasExternal() {
		t.Errorf("mixed local/external forwarder classified incorrectly: %+v", fwds[0])
	}
}

func TestCPanelSource_SkipsUnreadableValiasFile(t *testing.T) {
	fs := fakeFS{
		files: map[string]string{
			"/etc/localdomains":         "hosted.test\n",
			"/etc/valiases/broken.test": "",
			"/etc/valiases/hosted.test": "team: ext@gmail.com\n",
		},
		readErrs: map[string]error{
			"/etc/valiases/broken.test": errNotFound,
		},
	}
	src := &CPanelSource{
		fs:               fs,
		valiasGlob:       "/etc/valiases/*",
		localDomainsPath: "/etc/localdomains",
		userDomainsPath:  "/etc/userdomains",
	}

	fwds, err := src.Forwarders()
	if err != nil {
		t.Fatalf("Forwarders() error: %v", err)
	}
	if len(fwds) != 1 || fwds[0].Source != "team@hosted.test" {
		t.Fatalf("unreadable valias file should be skipped, got %+v", fwds)
	}
}
