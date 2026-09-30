package daemon

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The eval-command call sites of the wp-cli copy that cPanel's WP Toolkit
// bundles. Both are shipped root-owned under the panel's own tree.
const (
	toolkitEvalCommand     = "/usr/local/cpanel/3rdparty/wp-toolkit/plib/vendor/wp-cli/vendor/wp-cli/eval-command/src/Eval_Command.php"
	toolkitEvalFileCommand = "/usr/local/cpanel/3rdparty/wp-toolkit/plib/vendor/wp-cli/vendor/wp-cli/eval-command/src/EvalFile_Command.php"
)

type fakeEvalSiteInfo struct {
	name string
	mode fs.FileMode
	uid  uint32
}

func (i fakeEvalSiteInfo) Name() string       { return i.name }
func (i fakeEvalSiteInfo) Size() int64        { return 0 }
func (i fakeEvalSiteInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeEvalSiteInfo) ModTime() time.Time { return time.Time{} }
func (i fakeEvalSiteInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeEvalSiteInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

// fakeEvalSiteTree describes a filesystem the test cannot create for real:
// root-owned directories and files. Every ancestor of each listed path is a
// root-owned 0755 directory unless listed itself.
type fakeEvalSiteTree map[string]fakeEvalSiteInfo

func useFakeEvalSiteTree(t *testing.T, tree fakeEvalSiteTree) {
	t.Helper()
	full := fakeEvalSiteTree{}
	for p, info := range tree {
		full[p] = info
		for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
			if _, ok := full[dir]; !ok {
				if _, listed := tree[dir]; !listed {
					full[dir] = fakeEvalSiteInfo{name: filepath.Base(dir), mode: fs.ModeDir | 0o755}
				}
			}
			if dir == "/" {
				break
			}
		}
	}
	prev := phpShieldEvalSiteLstat
	phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
		if info, ok := full[name]; ok {
			return info, nil
		}
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrNotExist}
	}
	t.Cleanup(func() { phpShieldEvalSiteLstat = prev })
}

func rootFile(path string) fakeEvalSiteInfo {
	return fakeEvalSiteInfo{name: filepath.Base(path), mode: 0o644}
}

func toolkitTree(t *testing.T) {
	t.Helper()
	useFakeEvalSiteTree(t, fakeEvalSiteTree{
		"/usr/local/cpanel":    {name: "cpanel", mode: fs.ModeDir | 0o711},
		toolkitEvalCommand:     rootFile(toolkitEvalCommand),
		toolkitEvalFileCommand: rootFile(toolkitEvalFileCommand),
	})
}

// evalFatalLine is the shape WP Toolkit's bundled wp-cli produces: CLI, so
// wp-cli's own loopback address and agent, and an empty request URI.
func evalFatalLine(errorFile string) string {
	return "[2026-01-02 03:04:05] EVAL_FATAL sha256=- ip=127.0.0.1 script=" + errorFile +
		" uri= ua=WP CLI 2.12.0 details=Fatal in eval(): Uncaught TypeError: round(): Argument #1 ($num) must be of type int|float, string given in " +
		errorFile + ":1"
}

func evalSite(file string, line string) string {
	return file + "(" + line + ") : eval()'d code"
}

// A tenant can disable the Shield in its own process. A reported eval site
// in system code is therefore kept below High, with filesystem proof rather
// than trusting the sender's claimed request context.
func TestPHPShieldEvalFatalAtRootOwnedSystemScriptIsWarning(t *testing.T) {
	toolkitTree(t)
	for _, site := range []string{evalSite(toolkitEvalCommand, "44"), evalSite(toolkitEvalFileCommand, "113")} {
		f, quiet := parsePHPShieldEventLine(evalFatalLine(site))
		if f == nil || quiet {
			t.Fatalf("%s: event lost: quiet=%v finding=%+v", site, quiet, f)
		}
		if f.Severity != alert.Warning || f.Check != "php_shield_eval" {
			t.Fatalf("%s: severity=%v check=%q, want Warning php_shield_eval", site, f.Severity, f.Check)
		}
		if f.FilePath != site || f.SourceIP != "127.0.0.1" {
			t.Fatalf("%s: identity changed: %+v", site, f)
		}
		if !strings.Contains(f.Message, site) || !strings.Contains(f.Details, "root-owned") {
			t.Fatalf("%s: operator cannot see why it was not High: %+v", site, f)
		}
		if !strings.Contains(f.Message, "reported") || !strings.Contains(f.Details, "reported") || !strings.Contains(f.Details, "sender were not verified") {
			t.Fatalf("%s: finding presents forgeable event claims as verified provenance: %+v", site, f)
		}
	}
}

// Every way the reported eval site can be something other than stable,
// root-controlled code keeps the High grade.
func TestPHPShieldEvalFatalOutsideRootOwnedCodeStaysHigh(t *testing.T) {
	const tenantCopy = "/home/exampleuser/public_html/wp-cli/eval-command/src/Eval_Command.php"
	const tmpCopy = "/tmp/eval-command/src/Eval_Command.php"
	const linkedFile = "/usr/local/lib/example/Eval_Command.php"
	const linkedDir = "/usr/local/lib/example-link"
	const groupWritableDir = "/usr/local/lib/shared/Eval_Command.php"
	const tenantOwnedRootPath = "/usr/local/lib/tenantowned/Eval_Command.php"
	useFakeEvalSiteTree(t, fakeEvalSiteTree{
		"/usr/local/cpanel": {name: "cpanel", mode: fs.ModeDir | 0o711},
		toolkitEvalCommand:  rootFile(toolkitEvalCommand),
		// Same file name, but in an account's own tree.
		"/home/exampleuser": {name: "exampleuser", mode: fs.ModeDir | 0o711, uid: 1001},
		tenantCopy:          {name: "Eval_Command.php", mode: 0o644, uid: 1001},
		// A root-owned file under a world-writable sticky directory.
		"/tmp":  {name: "tmp", mode: fs.ModeDir | fs.ModeSticky | 0o777},
		tmpCopy: rootFile(tmpCopy),
		// The final component is a symlink. Linux reports 0777 for every
		// symlink; the type check must refuse one without leaning on that.
		linkedFile: {name: "Eval_Command.php", mode: fs.ModeSymlink | 0o755},
		// A parent component is a symlink; the file behind it is root-owned.
		linkedDir:                       {name: "example-link", mode: fs.ModeSymlink | 0o755},
		linkedDir + "/Eval_Command.php": rootFile(linkedDir + "/Eval_Command.php"),
		// A root-owned parent another group can write to.
		"/usr/local/lib/shared": {name: "shared", mode: fs.ModeDir | 0o775},
		groupWritableDir:        rootFile(groupWritableDir),
		// An account-owned file at a root-owned path.
		tenantOwnedRootPath: {name: "Eval_Command.php", mode: 0o644, uid: 1001},
		// Root-owned, but writable by everyone.
		"/usr/local/lib/open/Eval_Command.php": {name: "Eval_Command.php", mode: 0o666},
		// A root-owned file inside an account-owned directory.
		"/home/exampleuser/rootowned/Eval_Command.php": rootFile("Eval_Command.php"),
		"/home/exampleuser/rootowned":                  {name: "rootowned", mode: fs.ModeDir | 0o755},
		// Root-owned, but not a regular file.
		"/usr/local/lib/dir/Eval_Command.php": {name: "Eval_Command.php", mode: fs.ModeDir | 0o755},
	})
	for name, errorFile := range map[string]string{
		"account copy":                 evalSite(tenantCopy, "44"),
		"under world-writable dir":     evalSite(tmpCopy, "44"),
		"symlink file":                 evalSite(linkedFile, "44"),
		"symlink parent":               evalSite(linkedDir+"/Eval_Command.php", "44"),
		"group-writable parent":        evalSite(groupWritableDir, "44"),
		"account-owned file":           evalSite(tenantOwnedRootPath, "44"),
		"root file in account dir":     evalSite("/home/exampleuser/rootowned/Eval_Command.php", "44"),
		"world-writable file":          evalSite("/usr/local/lib/open/Eval_Command.php", "44"),
		"directory":                    evalSite("/usr/local/lib/dir/Eval_Command.php", "44"),
		"missing file":                 evalSite("/usr/local/lib/missing/Eval_Command.php", "44"),
		"nested eval":                  evalSite(toolkitEvalCommand, "44") + "(1) : eval()'d code",
		"no eval marker":               toolkitEvalCommand,
		"traversal":                    evalSite("/usr/local/cpanel/3rdparty/../3rdparty/wp-toolkit/plib/vendor/wp-cli/vendor/wp-cli/eval-command/src/Eval_Command.php", "44"),
		"doubled separator":            evalSite("/usr/local/cpanel//3rdparty/wp-toolkit/plib/vendor/wp-cli/vendor/wp-cli/eval-command/src/Eval_Command.php", "44"),
		"relative":                     evalSite("usr/local/cpanel/3rdparty/Eval_Command.php", "44"),
		"relative past its first byte": evalSite("u"+toolkitEvalCommand, "44"),
		"stream wrapper":               evalSite("phar://"+toolkitEvalCommand, "44"),
		"non-numeric line":             evalSite(toolkitEvalCommand, "4x"),
		"marker without line":          toolkitEvalCommand + " : eval()'d code",
		"marker cut off":               toolkitEvalCommand + "(44",
		"line without parenthesis":     toolkitEvalCommand + "44" + phpEvalCodeSuffix,
		"empty line number":            evalSite(toolkitEvalCommand, ""),
		"trailing text after marker":   evalSite(toolkitEvalCommand, "44") + " extra",
		"regexp-looking eval marker":   toolkitEvalCommand + "(44) : eval()'d codeX",
		"runtime-created function":     toolkitEvalCommand + "(44) : runtime-created function",
		"assert code":                  toolkitEvalCommand + "(44) : assert code",
		"regexp code":                  toolkitEvalCommand + "(44) : regexp code",
		"empty path before the line":   "(44) : eval()'d code",
		"root directory as call site":  evalSite("/", "44"),
	} {
		f, quiet := parsePHPShieldEventLine(evalFatalLine(errorFile))
		if f == nil || quiet {
			t.Fatalf("%s: event lost: quiet=%v finding=%+v", name, quiet, f)
		}
		if f.Severity != alert.High {
			t.Errorf("%s: severity=%v, want High for %q", name, f.Severity, errorFile)
		}
	}
}

// A symlink the test creates for real is refused by the live lstat walk,
// whoever owns its target.
func TestPHPShieldEvalFatalThroughRealSymlinkStaysHigh(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "Eval_Command.php")
	if err := os.Symlink("/etc/hostname", link); err != nil {
		t.Fatal(err)
	}
	// Trust synthetic ancestors so neither the runner's uid nor TMPDIR's
	// ownership can reject the walk before it reaches the real symlink.
	lstat := phpShieldEvalSiteLstat
	useFakeEvalSiteTree(t, fakeEvalSiteTree{link: rootFile(link)})
	tree := phpShieldEvalSiteLstat
	phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
		if name == link {
			return lstat(name)
		}
		return tree(name)
	}
	f := parsePHPShieldLine(evalFatalLine(evalSite(link, "44")))
	if f == nil || f.Severity != alert.High {
		t.Fatalf("symlinked eval site was demoted: %+v", f)
	}
}

// A file whose owner cannot be read proves nothing.
func TestPHPShieldEvalFatalWithoutOwnerStaysHigh(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
		info, err := tree(name)
		if err != nil {
			return nil, err
		}
		return ownerlessInfo{info}, nil
	}
	f := parsePHPShieldLine(evalFatalLine(evalSite(toolkitEvalCommand, "44")))
	if f == nil || f.Severity != alert.High {
		t.Fatalf("ownerless eval site was demoted: %+v", f)
	}
	phpShieldEvalSiteLstat = func(string) (os.FileInfo, error) { return nil, errors.New("io error") }
	f = parsePHPShieldLine(evalFatalLine(evalSite(toolkitEvalCommand, "44")))
	if f == nil || f.Severity != alert.High {
		t.Fatalf("unreadable eval site was demoted: %+v", f)
	}
}

type ownerlessInfo struct{ os.FileInfo }

func (ownerlessInfo) Sys() any { return nil }

// The walk starts at the filesystem root, which is part of the chain too.
func TestPHPShieldEvalFatalChecksFilesystemRoot(t *testing.T) {
	useFakeEvalSiteTree(t, fakeEvalSiteTree{
		"/":                {name: "/", mode: fs.ModeDir | 0o777},
		toolkitEvalCommand: rootFile(toolkitEvalCommand),
	})
	f := parsePHPShieldLine(evalFatalLine(evalSite(toolkitEvalCommand, "44")))
	if f == nil || f.Severity != alert.High {
		t.Fatalf("eval site under a writable filesystem root was demoted: %+v", f)
	}
}

// Event fields are forgeable by any local user. A path on a hung mount must
// cost the reader one timeout, and later events must not queue up behind the
// stuck lookup or each leave another blocked thread.
func TestPHPShieldEvalSiteHungLookupIsBounded(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	release := make(chan struct{})
	var calls atomic.Int32
	phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
		calls.Add(1)
		<-release
		return tree(name)
	}
	prevTimeout := phpShieldEvalSiteTimeout
	phpShieldEvalSiteTimeout = time.Second
	t.Cleanup(func() { phpShieldEvalSiteTimeout = prevTimeout })
	line := evalFatalLine(evalSite(toolkitEvalCommand, "44"))

	start := time.Now()
	if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
		t.Fatalf("unproven eval site was demoted: %+v", f)
	}
	if waited := time.Since(start); waited < phpShieldEvalSiteTimeout || waited > 10*time.Second {
		t.Fatalf("hung lookup held the reader for %v, want about %v", waited, phpShieldEvalSiteTimeout)
	}
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first event never started a lookup")
		}
		time.Sleep(time.Millisecond)
	}
	start = time.Now()
	if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
		t.Fatalf("event behind a stuck lookup was demoted: %+v", f)
	}
	if calls.Load() != 1 {
		t.Fatal("a second lookup started while the first was still stuck")
	}
	if waited := time.Since(start); waited >= phpShieldEvalSiteTimeout {
		t.Fatalf("event behind a stuck lookup waited %v", waited)
	}

	close(release)
	deadline = time.Now().Add(5 * time.Second)
	for len(phpShieldEvalSiteProbe) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("stuck lookup never released its slot")
		}
		time.Sleep(time.Millisecond)
	}
	phpShieldEvalSiteTimeout = prevTimeout
	if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.Warning {
		t.Fatalf("eval site not proven once the filesystem recovered: %+v", f)
	}
}

// A timed-out walk owns its slot until it finishes. It must not need a
// separate waiter to release the slot after publishing its result.
func TestPHPShieldEvalSiteTimeoutNeedsOnlyOneWorker(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
			<-release
			return tree(name)
		}
		defer func() {
			close(release)
			synctest.Wait()
			phpShieldEvalSiteLstat = tree
		}()
		line := evalFatalLine(evalSite(toolkitEvalCommand, "44"))
		if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
			t.Fatalf("timed-out lookup was demoted: %+v", f)
		}
		for range 100 {
			if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
				t.Fatalf("event behind a hung lookup was demoted: %+v", f)
			}
		}
		synctest.Wait()
		var stacks bytes.Buffer
		if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
			t.Fatal(err)
		}
		if workers := strings.Count(stacks.String(), "daemon.phpShieldEvalSiteProven.func"); workers != 1 {
			t.Errorf("hung lookup left %d background workers, want one", workers)
		}
	})
	if f := parsePHPShieldLine(evalFatalLine(evalSite(toolkitEvalCommand, "44"))); f == nil || f.Severity != alert.Warning {
		t.Fatalf("completed lookup left its slot held: %+v", f)
	}
}

// The loopback Warning must not share a dedup key with a later High from the
// same address: a cron job running the same wp-cli could otherwise hide one.
func TestPHPShieldEvalFatalWarningDoesNotDedupHigh(t *testing.T) {
	toolkitTree(t)
	warning := parsePHPShieldLine(evalFatalLine(evalSite(toolkitEvalCommand, "44")))
	high := parsePHPShieldLine(evalFatalLine(evalSite("/home/exampleuser/public_html/plugin.php", "12")))
	if warning == nil || high == nil || warning.Severity != alert.Warning || high.Severity != alert.High {
		t.Fatalf("grades: warning=%+v high=%+v", warning, high)
	}
	if warning.Fingerprint() == high.Fingerprint() {
		t.Fatal("demoted system eval shares a dedup key with a High eval chain from the same address")
	}
	if warning.Key() == high.Key() || len(alert.Deduplicate([]alert.Finding{*warning, *high})) != 2 {
		t.Fatal("batch dedup absorbed a High eval after a Warning from the same address")
	}
}

func TestPHPShieldEvalFatalRequestClaimsDoNotReplaceFilesystemProof(t *testing.T) {
	toolkitTree(t)
	for _, claims := range []string{
		"ip=127.0.0.1 uri= ua=WP CLI 2.12.0",
		"ip=203.0.113.9 uri=/run?code=example ua=Mozilla/5.0",
		"ip=203.0.113.9 uri= ua=",
	} {
		ip, request, _ := strings.Cut(claims, " ")
		for _, tc := range []struct {
			site string
			want alert.Severity
		}{
			{evalSite(toolkitEvalCommand, "44"), alert.Warning},
			{evalSite("/home/exampleuser/public_html/plugin.php", "12"), alert.High},
		} {
			line := "[2026-01-02 03:04:05] EVAL_FATAL " + ip + " script=" + tc.site + " " + request + " details=eval failure"
			f, quiet := parsePHPShieldEventLine(line)
			if quiet || f == nil || f.Severity != tc.want {
				t.Fatalf("claims %q site %q: quiet=%v finding=%+v, want %v", claims, tc.site, quiet, f, tc.want)
			}
		}
	}
}

func TestPHPShieldEvalFatalPacketRechecksOwnership(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	mode := fs.FileMode(0o644)
	phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
		if name == toolkitEvalCommand {
			return fakeEvalSiteInfo{name: "Eval_Command.php", mode: mode}, nil
		}
		return tree(name)
	}
	line := evalFatalLine(evalSite(toolkitEvalCommand, "44"))
	archive := filepath.Join(t.TempDir(), "events.log")
	findings := make(chan alert.Finding, 2)
	for _, tc := range []struct {
		mode fs.FileMode
		want alert.Severity
	}{
		{0o644, alert.Warning},
		{0o666, alert.High},
	} {
		mode = tc.mode
		processed, err := processPHPShieldEventPacket([]byte(line), archive, nil, findings)
		if err != nil || !processed {
			t.Fatalf("packet lost: processed=%v err=%v", processed, err)
		}
		select {
		case f := <-findings:
			if f.Severity != tc.want || f.Timestamp.IsZero() {
				t.Fatalf("packet finding=%+v, want severity %v and a receipt time", f, tc.want)
			}
		default:
			t.Fatal("eval packet emitted no alert")
		}
	}
	if got, err := os.ReadFile(archive); err != nil || string(got) != line+"\n"+line+"\n" {
		t.Fatalf("eval packets missing from archive: %q, %v", got, err)
	}
}

// Back-to-back events from one wp-cli run must each be proven: a finished
// lookup may not leave its slot held for the next event.
func TestPHPShieldEvalSiteBackToBackEventsAreEachProven(t *testing.T) {
	toolkitTree(t)
	line := evalFatalLine(evalSite(toolkitEvalCommand, "44"))
	for i := 0; i < 2000; i++ {
		if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.Warning {
			t.Fatalf("event %d graded %+v", i, f)
		}
		if held := len(phpShieldEvalSiteProbe); held != 0 {
			t.Fatalf("event %d returned while its finished lookup still held the slot", i)
		}
	}
}
