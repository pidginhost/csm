package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

func bothSignals() policy.Config {
	return policy.Config{
		Enabled: true,
		HoldSignals: policy.HoldSignals{
			BounceBackscatter: true,
			BadSenderIP:       true,
		},
	}
}

// testAdapter returns an adapter writing under a temp dir with fake side effects.
func testAdapter(t *testing.T) (*EximAdapter, *fakeState) {
	t.Helper()
	dir := t.TempDir()
	fs := &fakeState{}
	a := &EximAdapter{
		localConf:     filepath.Join(dir, "exim.conf.local"),
		badIPsPath:    filepath.Join(dir, "bad_ips"),
		quarantineDir: filepath.Join(dir, "held"),
		rebuild:       func() error { fs.rebuilds++; return fs.rebuildErr },
		chown:         func(p, u string) error { fs.chownUser = u; fs.chownPath = p; return nil },
		mkdirAll:      os.MkdirAll,
	}
	return a, fs
}

type fakeState struct {
	rebuilds   int
	rebuildErr error
	chownUser  string
	chownPath  string
}

func TestRenderRouterBothSignals(t *testing.T) {
	a, _ := testAdapter(t)
	router, err := a.renderRouter(bothSignals().HoldSignals)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"csm_forward_guard:",
		"driver = accept",
		"domains = ! +local_domains",
		"def:parent_local_part",
		"{eq{$sender_address}{}}",             // null-sender clause
		"lsearch{" + a.badIPsPath + "}{1}{0}", // bad-IP clause uses the configured path
		"transport = csm_forward_hold",
	} {
		if !strings.Contains(router, want) {
			t.Errorf("router missing %q\n%s", want, router)
		}
	}
}

func TestRenderRouterOnlyBounceOmitsBadIPClause(t *testing.T) {
	a, _ := testAdapter(t)
	router, err := a.renderRouter(policy.HoldSignals{BounceBackscatter: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(router, "lsearch") {
		t.Errorf("bad-IP clause present when only bounce enabled:\n%s", router)
	}
	if !strings.Contains(router, "{eq{$sender_address}{}}") {
		t.Errorf("null-sender clause missing:\n%s", router)
	}
}

func TestRenderRouterNoEnforceableSignalErrors(t *testing.T) {
	a, _ := testAdapter(t)
	if _, err := a.renderRouter(policy.HoldSignals{SpamFlagged: true, Malware: true, AuthFail: true}); err == nil {
		t.Fatal("expected error: no routing-time-enforceable signal")
	}
}

func TestRenderTransportMatchesQuarantineContract(t *testing.T) {
	a, _ := testAdapter(t)
	tr := a.renderTransport()
	for _, want := range []string{
		"csm_forward_hold:",
		"driver = appendfile",
		"directory = " + a.quarantineDir,
		"maildir_format",
		"user = mailnull", // NOT root (never_users)
		"X-CSM-Forwarder: $parent_local_part@$parent_domain",
		"X-CSM-Recipient: $local_part@$domain",
		"X-CSM-Sender: $sender_address",
		"X-CSM-Reasons: ${if eq{$sender_address}{}{bounce_backscatter}{bad_sender_ip}}",
	} {
		if !strings.Contains(tr, want) {
			t.Errorf("transport missing %q\n%s", want, tr)
		}
	}
}

func TestApplyInjectsIntoSkeletonAndSideEffects(t *testing.T) {
	a, fs := testAdapter(t)
	if err := a.Apply(bothSignals(), []string{"198.51.100.7", "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(a.localConf)
	s := string(conf)

	// Router under @ROUTERSTART@, transport under @TRANSPORTSTART@.
	// cPanel orders @ROUTEREND@ before @ROUTERSTART@ in the skeleton; content
	// injected after @ROUTERSTART@ is what lands in the routers section.
	rIdx := strings.Index(s, "@ROUTERSTART@")
	routerIdx := strings.Index(s, routerBegin)
	if rIdx < 0 || routerIdx <= rIdx {
		t.Errorf("router block not placed after @ROUTERSTART@")
	}
	tIdx := strings.Index(s, "@TRANSPORTSTART@")
	if tIdx < 0 || strings.Index(s, transportBegin) <= tIdx {
		t.Errorf("transport block not placed after @TRANSPORTSTART@")
	}

	// bad_ips written in lsearch format.
	bad, _ := os.ReadFile(a.badIPsPath)
	if !strings.Contains(string(bad), "198.51.100.7: 1") || !strings.Contains(string(bad), "203.0.113.9: 1") {
		t.Errorf("bad_ips contents = %q", bad)
	}
	// quarantine chowned to mailnull; rebuild ran.
	if fs.chownUser != "mailnull" {
		t.Errorf("chown user = %q, want mailnull", fs.chownUser)
	}
	if fs.rebuilds != 1 {
		t.Errorf("rebuilds = %d, want 1", fs.rebuilds)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	a, _ := testAdapter(t)
	if err := a.Apply(bothSignals(), []string{"198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(a.localConf)
	if err := a.Apply(bothSignals(), []string{"198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(a.localConf)
	if string(first) != string(second) {
		t.Errorf("re-apply changed the file (not idempotent)\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if strings.Count(string(second), routerBegin) != 1 {
		t.Errorf("router block duplicated: %d copies", strings.Count(string(second), routerBegin))
	}
}

func TestApplyPreservesExistingLocalConfContent(t *testing.T) {
	a, _ := testAdapter(t)
	// Pre-existing exim.conf.local with an operator's own ACL content.
	existing := strings.Replace(eximLocalSkeleton, "@BEGINACL@\n", "@BEGINACL@\nwarn message = operator rule\n", 1)
	if err := os.WriteFile(a.localConf, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(bothSignals(), nil); err != nil {
		t.Fatal(err)
	}
	s, _ := os.ReadFile(a.localConf)
	if !strings.Contains(string(s), "warn message = operator rule") {
		t.Error("operator's existing ACL content was lost")
	}
	if !strings.Contains(string(s), routerBegin) {
		t.Error("router block not added")
	}
}

func TestApplyRollsBackOnRebuildFailure(t *testing.T) {
	a, fs := testAdapter(t)
	prior := strings.Replace(eximLocalSkeleton, "@CONFIG@\n", "@CONFIG@\n# operator marker\n", 1)
	if err := os.WriteFile(a.localConf, []byte(prior), 0644); err != nil {
		t.Fatal(err)
	}
	fs.rebuildErr = errors.New("buildeximconf boom")

	if err := a.Apply(bothSignals(), nil); err == nil {
		t.Fatal("expected apply error on rebuild failure")
	}
	// exim.conf.local restored to the prior content (no half-installed router).
	s, _ := os.ReadFile(a.localConf)
	if strings.Contains(string(s), routerBegin) {
		t.Errorf("router block left behind after rollback:\n%s", s)
	}
	if !strings.Contains(string(s), "# operator marker") {
		t.Errorf("prior content not restored:\n%s", s)
	}
}

func TestRemoveStripsBlocksAndRebuilds(t *testing.T) {
	a, fs := testAdapter(t)
	if err := a.Apply(bothSignals(), nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(); err != nil {
		t.Fatal(err)
	}
	s, _ := os.ReadFile(a.localConf)
	if strings.Contains(string(s), routerBegin) || strings.Contains(string(s), transportBegin) {
		t.Errorf("managed blocks remain after Remove:\n%s", s)
	}
	// Markers must remain intact for cPanel.
	if !strings.Contains(string(s), "@ROUTERSTART@") || !strings.Contains(string(s), "@TRANSPORTSTART@") {
		t.Errorf("cPanel markers damaged by Remove:\n%s", s)
	}
	if fs.rebuilds != 2 { // one for Apply, one for Remove
		t.Errorf("rebuilds = %d, want 2", fs.rebuilds)
	}
}

func TestStatusReflectsInstalled(t *testing.T) {
	a, _ := testAdapter(t)
	if st, _ := a.Status(); st.Installed {
		t.Error("status installed before apply")
	}
	if err := a.Apply(bothSignals(), nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := a.Status(); !st.Installed {
		t.Error("status not installed after apply")
	}
	if err := a.Remove(); err != nil {
		t.Fatal(err)
	}
	if st, _ := a.Status(); st.Installed {
		t.Error("status installed after remove")
	}
}
