package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// openCountOS counts content opens per logical /home path.
type openCountOS struct {
	rollingRootOS
	mu    *sync.Mutex
	opens map[string]int
}

func (o openCountOS) Open(name string) (*os.File, error) {
	o.mu.Lock()
	o.opens[name]++
	o.mu.Unlock()
	return o.rollingRootOS.Open(name)
}

func (o openCountOS) count(name string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.opens[name]
}

type changedFixture struct {
	root string
	cfg  *config.Config
	os   openCountOS
}

// newChangedFixture builds accounts with clean files outside the fixed
// suspicious directories, so only rolling coverage reads them, and runs one
// cycle so every account has a watermark.
func newChangedFixture(t *testing.T, budget int, accounts ...string) changedFixture {
	t.Helper()
	resetPHPContentScanCounts(t)
	prevMargin := rollingChangedMargin
	rollingChangedMargin = 0
	t.Cleanup(func() { rollingChangedMargin = prevMargin })
	root := t.TempDir()
	for _, account := range accounts {
		dir := filepath.Join(root, "home", account, "public_html", "assets", "lib")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"a00.php", "a01.php", "a02.php", "a03.php"} {
			writeFile(t, filepath.Join(dir, name), rollingBenignPHP)
		}
	}
	fx := changedFixture{
		root: root,
		cfg:  rollingCfg(budget),
		os:   openCountOS{rollingRootOS: rollingRootOS{root: root}, mu: &sync.Mutex{}, opens: map[string]int{}},
	}
	fx.cfg.StatePath = t.TempDir()
	withMockOS(t, fx.os)
	useRollingStore(t)
	fx.cycle(t)
	return fx
}

// cycle runs one host-wide content check. Change times have coarse
// resolution, so files written after it must not share its tick.
func (fx changedFixture) cycle(t *testing.T) []alertFindings {
	t.Helper()
	findings := CheckPHPContent(context.Background(), fx.cfg, nil)
	time.Sleep(20 * time.Millisecond)
	out := make([]alertFindings, 0, len(findings))
	for _, f := range findings {
		out = append(out, alertFindings{path: f.FilePath})
	}
	return out
}

type alertFindings struct{ path string }

func foundIn(findings []alertFindings, path string) int {
	n := 0
	for _, f := range findings {
		if f.path == path {
			n++
		}
	}
	return n
}

func (fx changedFixture) write(t *testing.T, logical, content string) {
	t.Helper()
	real := filepath.Join(fx.root, logical)
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, real, content)
}

// A file planted where the fixed walk never looks waited for the rolling
// window to reach it, which on a large host took days. It is now read in the
// first cycle after it appears, ahead of the window.
func TestRollingReadsANewFileBeforeTheWindowReachesIt(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	planted := "/home/alice/public_html/wp-includes/Text/Diff/Renderer/index.php"
	fx.write(t, planted, rollingDormantPHP)

	if got := foundIn(fx.cycle(t), planted); got != 1 {
		t.Fatalf("planted file reported %d times in the next cycle, want 1", got)
	}
}

func TestRollingRereadsAFileChangedInPlace(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	changed := "/home/alice/public_html/assets/lib/a02.php"
	fx.write(t, changed, rollingDormantPHP)

	if got := foundIn(fx.cycle(t), changed); got != 1 {
		t.Fatalf("file changed in place reported %d times, want 1", got)
	}
}

// Files already present when an account is first seen, and files unchanged
// since, stay with the rolling window: only it reads them, one window at a
// time.
func TestRollingChangedPassLeavesUnchangedFilesToTheWindow(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	opens := func() int {
		n := 0
		for _, name := range []string{"a00.php", "a01.php", "a02.php", "a03.php"} {
			n += fx.os.count("/home/alice/public_html/assets/lib/" + name)
		}
		return n
	}
	if got := opens(); got != 1 {
		t.Fatalf("first cycle opened %d existing files, want the window's 1", got)
	}
	fx.cycle(t)
	if got := opens(); got != 2 {
		t.Fatalf("an unchanged cycle opened %d files in total, want the window's 2", got)
	}
}

// One read per file per cycle: the window does not read again what the
// changed pass or the fixed walk read in the same cycle, and a flagged file
// is reported once.
func TestRollingReadsEachFileOncePerCycle(t *testing.T) {
	fx := newChangedFixture(t, 100, "alice")
	clean := map[string]string{
		"custom": "/home/alice/public_html/assets/lib/z-new.php",
		"plugin": "/home/alice/public_html/wp-content/plugins/example/example.php",
	}
	flagged := map[string]string{
		"custom": "/home/alice/public_html/assets/lib/z-shell.php",
		"plugin": "/home/alice/public_html/wp-content/plugins/example/shell.php",
	}
	for _, path := range clean {
		fx.write(t, path, rollingBenignPHP)
	}
	for _, path := range flagged {
		fx.write(t, path, rollingDormantPHP)
	}

	findings := fx.cycle(t)

	for where, path := range clean {
		if got := fx.os.count(path); got != 1 {
			t.Errorf("%s file opened %d times, want 1", where, got)
		}
	}
	for where, path := range flagged {
		if got := foundIn(findings, path); got != 1 {
			t.Errorf("%s file reported %d times, want 1", where, got)
		}
	}
}

// A changed file is read once, not on every cycle after it: the watermark
// moves past it. Its finding stays with the window from then on.
func TestRollingChangedPassDoesNotRereadOldChanges(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	planted := "/home/alice/public_html/wp-includes/x.php"
	fx.write(t, planted, rollingDormantPHP)
	fx.cycle(t)
	before := fx.os.count(planted)
	fx.cycle(t)
	if after := fx.os.count(planted); after != before {
		t.Fatalf("changed pass read an old change again: opens %d -> %d", before, after)
	}
}

// A budget too small for every account's changes serves the accounts in
// turn: an account with a burst of changes cannot keep the others waiting.
func TestRollingChangedPassServesAccountsInTurn(t *testing.T) {
	fx := newChangedFixture(t, 2, "aaa", "bbb", "ccc")
	planted := map[string][]string{}
	for _, account := range []string{"aaa", "bbb", "ccc"} {
		for _, name := range []string{"p1.php", "p2.php"} {
			p := "/home/" + account + "/public_html/wp-includes/" + name
			fx.write(t, p, rollingDormantPHP)
			planted[account] = append(planted[account], p)
		}
	}

	seen := map[string]bool{}
	for cycle := 1; cycle <= 3; cycle++ {
		for _, f := range fx.cycle(t) {
			if strings.Contains(f.path, "/wp-includes/") {
				seen[f.path] = true
			}
		}
	}
	for account, paths := range planted {
		for _, p := range paths {
			if !seen[p] {
				t.Errorf("%s: %s not read within three cycles", account, p)
			}
		}
	}
}

// A burst larger than the budget inside one account is read across cycles,
// resuming after the last file read instead of starting over.
func TestRollingChangedPassResumesWithinAnAccount(t *testing.T) {
	fx := newChangedFixture(t, 2, "alice")
	var planted []string
	for _, name := range []string{"p1.php", "p2.php", "p3.php", "p4.php", "p5.php"} {
		p := "/home/alice/public_html/wp-includes/" + name
		fx.write(t, p, rollingDormantPHP)
		planted = append(planted, p)
	}
	seen := map[string]int{}
	for cycle := 1; cycle <= 3; cycle++ {
		for _, f := range fx.cycle(t) {
			seen[f.path]++
		}
	}
	for _, p := range planted {
		if seen[p] == 0 {
			t.Errorf("%s not read within three cycles", p)
		}
	}
}

// An account that keeps changing files every cycle is served, then waits its
// turn behind accounts served longer ago.
func TestRollingChangedPassDoesNotLetAFloodStarveOtherAccounts(t *testing.T) {
	fx := newChangedFixture(t, 2, "aaa", "bbb")
	victim := "/home/bbb/public_html/wp-includes/planted.php"
	fx.write(t, victim, rollingDormantPHP)

	found := false
	for cycle := 1; cycle <= 2 && !found; cycle++ {
		for _, name := range []string{"f1.php", "f2.php"} {
			fx.write(t, "/home/aaa/public_html/wp-includes/c"+string(rune('0'+cycle))+name, rollingBenignPHP)
		}
		found = foundIn(fx.cycle(t), victim) > 0
	}
	if !found {
		t.Fatal("a flooding account kept the other account's planted file unread")
	}
}
