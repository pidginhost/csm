package checks

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// withRespawnMemory gives the respawn memory a fresh state on a clock the
// test moves.
func withRespawnMemory(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	prev := detachedRespawns
	detachedRespawns = newDetachedRespawnMemory(func() time.Time { return now })
	t.Cleanup(func() { detachedRespawns = prev })
	return &now
}

func withScanRequester(t *testing.T, fn func(account string) (string, error)) {
	t.Helper()
	SetAccountScanRequester(fn)
	t.Cleanup(func() { SetAccountScanRequester(nil) })
}

// withKillAll lets every eligible process be signalled and records it.
func withKillAll(t *testing.T) *[]int {
	t.Helper()
	var killed []int
	prev := signalProcess
	signalProcess = func(_ context.Context, pid int, _ syscall.Signal, verify func() error) error {
		if err := verify(); err != nil {
			return err
		}
		killed = append(killed, pid)
		return nil
	}
	t.Cleanup(func() { signalProcess = prev })
	return &killed
}

// respawnOnce runs the check and the kill for one detached shell, under a new
// PID each time, the way a respawner brings it back.
func respawnOnce(t *testing.T, pid int, uid string) []alert.Finding {
	t.Helper()
	withWebProcTable(t, map[int]fakeProc{pid: {ppid: 1, uid: uid, exe: bashPath}}, map[int][]string{pid: {socketFD(5001)}})
	findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].Severity != alert.Critical {
		t.Fatalf("setup: findings = %+v, want one detached shell", findings)
	}
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	return AutoKillProcesses(context.Background(), cfg, findings)
}

func respawnFindings(actions []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range actions {
		if f.Check == DetachedWebProcessRespawnCheck {
			out = append(out, f)
		}
	}
	return out
}

func withAccounts(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
}

// A respawner is stopped every time it comes back. From the second stop in a
// day the operator gets one Critical finding naming the PHP pool, and the
// account is scanned once.
func TestDetachedShellRespawnEscalates(t *testing.T) {
	withAccounts(t)
	now := withRespawnMemory(t)
	killed := withKillAll(t)
	var scans []string
	withScanRequester(t, func(account string) (string, error) {
		scans = append(scans, account)
		return "job-7", nil
	})

	if got := respawnFindings(respawnOnce(t, 700, "1001")); len(got) != 0 {
		t.Fatalf("the first stop escalated: %+v", got)
	}
	*now = now.Add(time.Hour)
	got := respawnFindings(respawnOnce(t, 800, "1001"))
	if len(got) != 1 {
		t.Fatalf("second stop: escalations = %+v, want one", got)
	}
	f := got[0]
	if f.Severity != alert.Critical || f.TenantID != "alice" || !strings.Contains(f.Message, "alice") ||
		!strings.Contains(f.Message, "2 times") || !strings.Contains(f.Details, "APVH_alice_Suea-php84.sock") ||
		!strings.Contains(f.Details, "job-7") {
		t.Fatalf("escalation = %+v", f)
	}
	if !slices.Equal(scans, []string{"alice"}) {
		t.Fatalf("scans = %v, want one of alice", scans)
	}

	*now = now.Add(time.Hour)
	if got := respawnFindings(respawnOnce(t, 900, "1001")); len(got) != 0 {
		t.Fatalf("escalated twice in a day: %+v", got)
	}
	if len(scans) != 1 {
		t.Fatalf("scans = %v, want one a day", scans)
	}
	if !slices.Equal(*killed, []int{700, 800, 900}) {
		t.Fatalf("killed %v, want every respawn", *killed)
	}

	// A day later the memory starts over: one stop is not a loop, two are.
	*now = now.Add(25 * time.Hour)
	if got := respawnFindings(respawnOnce(t, 1000, "1001")); len(got) != 0 {
		t.Fatalf("a stop after a quiet day escalated: %+v", got)
	}
	*now = now.Add(time.Minute)
	if got := respawnFindings(respawnOnce(t, 1100, "1001")); len(got) != 1 {
		t.Fatalf("the next day's loop did not escalate: %+v", got)
	}
	if !slices.Equal(scans, []string{"alice", "alice"}) {
		t.Fatalf("scans = %v, want one per escalation", scans)
	}
}

// Stops in different accounts are separate respawners.
func TestDetachedShellRespawnPerOwner(t *testing.T) {
	withAccounts(t)
	withRespawnMemory(t)
	withKillAll(t)
	withScanRequester(t, func(string) (string, error) { return "job", nil })
	if got := respawnFindings(slices.Concat(respawnOnce(t, 700, "1001"), respawnOnce(t, 800, "1002"))); len(got) != 0 {
		t.Fatalf("stops in two accounts escalated: %+v", got)
	}
}

// A shell owned by a user that is not a hosting account still escalates, but
// there is no account to scan, and the finding says so.
func TestDetachedShellRespawnWithoutAccount(t *testing.T) {
	withAccounts(t)
	withRespawnMemory(t)
	withKillAll(t)
	var scans []string
	withScanRequester(t, func(account string) (string, error) {
		scans = append(scans, account)
		return "job", nil
	})
	respawnOnce(t, 700, "4242")
	got := respawnFindings(respawnOnce(t, 800, "4242"))
	if len(got) != 1 || got[0].TenantID != "" || !strings.Contains(got[0].Message, "4242") ||
		!strings.Contains(got[0].Details, "not a hosting account") {
		t.Fatalf("escalation = %+v", got)
	}
	if len(scans) != 0 {
		t.Fatalf("scanned %v for a non-account owner", scans)
	}
}

// Without a scan queue, or when it refuses, the escalation still fires and
// says why no scan runs.
func TestDetachedShellRespawnScanUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requester func(string) (string, error)
		want      string
	}{
		{"no queue", nil, "scan queue is not available"},
		{"queue full", func(string) (string, error) { return "", errors.New("scan-job queue is full") }, "scan-job queue is full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withAccounts(t)
			withRespawnMemory(t)
			withKillAll(t)
			withScanRequester(t, tc.requester)
			respawnOnce(t, 700, "1001")
			got := respawnFindings(respawnOnce(t, 800, "1001"))
			if len(got) != 1 || !strings.Contains(got[0].Details, tc.want) {
				t.Fatalf("escalation = %+v, want details naming %q", got, tc.want)
			}
		})
	}
}

// A shell CSM could not stop is not a respawn CSM caused.
func TestDetachedShellRespawnCountsOnlyStops(t *testing.T) {
	withAccounts(t)
	withRespawnMemory(t)
	prev := signalProcess
	signalProcess = func(context.Context, int, syscall.Signal, func() error) error { return errProcessNotEligible }
	t.Cleanup(func() { signalProcess = prev })
	withScanRequester(t, func(string) (string, error) { return "job", nil })
	if got := respawnFindings(slices.Concat(respawnOnce(t, 700, "1001"), respawnOnce(t, 800, "1001"))); len(got) != 0 {
		t.Fatalf("refused kills escalated: %+v", got)
	}
}

// Correlation attributes the respawn to the account the shell ran as.
func TestDetachedShellRespawnStampsOwner(t *testing.T) {
	withAccounts(t)
	withRespawnMemory(t)
	withKillAll(t)
	withScanRequester(t, func(string) (string, error) { return "job", nil })
	respawnOnce(t, 700, "1002")
	got := respawnFindings(respawnOnce(t, 800, "1002"))
	if len(got) != 1 || got[0].TenantID != "bob" || extractAccountFromFinding(got[0]) != "bob" {
		t.Fatalf("escalation = %+v, want it attributed to bob", got)
	}
}

func TestDetachedRespawnFloodBounded(t *testing.T) {
	now := withRespawnMemory(t)
	withScanRequester(t, nil)
	f := alert.Finding{TenantID: "alice"}
	for range 10000 {
		detachedRespawns.noteStop(f, "1001")
	}
	// A rolling second-stop decision needs only the previous stop, not a
	// timestamp allocation for every process the account can start.
	owner := reflect.ValueOf(detachedRespawns.owners["alice"]).Elem()
	for i := 0; i < owner.NumField(); i++ {
		field := owner.Field(i)
		if field.Kind() == reflect.Slice && field.Cap() > 2 {
			t.Fatalf("respawn flood retained %d entries", field.Cap())
		}
	}
	for i := range 5000 {
		detachedRespawns.noteStop(alert.Finding{}, strconv.Itoa(i+2000))
	}
	if len(detachedRespawns.owners) > 4096 {
		t.Fatalf("owner flood retained %d owners", len(detachedRespawns.owners))
	}
	if _, ok := detachedRespawns.noteStop(f, "1001"); ok {
		t.Fatal("owner flood evicted the daily escalation suppression")
	}
	*now = now.Add(25 * time.Hour)
	detachedRespawns.noteStop(alert.Finding{TenantID: "bob"}, "1002")
	if len(detachedRespawns.owners) != 1 {
		t.Fatalf("expired owners retained: %d", len(detachedRespawns.owners))
	}
}

func TestDetachedRespawnFinishesKillsBeforeEscalation(t *testing.T) {
	withAccounts(t)
	withRespawnMemory(t)
	killed := withKillAll(t)
	withWebProcTable(t, map[int]fakeProc{
		700: {ppid: 1, uid: "1001", exe: bashPath},
		800: {ppid: 1, uid: "1001", exe: bashPath},
		900: {ppid: 1, uid: "1001", exe: bashPath},
	}, map[int][]string{700: {socketFD(5001)}, 800: {socketFD(5001)}, 900: {socketFD(5001)}})
	findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)
	calls := 0
	withScanRequester(t, func(string) (string, error) {
		calls++
		if !slices.Equal(*killed, []int{700, 800, 900}) {
			t.Errorf("scan submission preceded kills: %v", *killed)
		}
		if !detachedRespawns.mu.TryLock() {
			t.Error("scan submission holds respawn memory lock")
		} else {
			detachedRespawns.mu.Unlock()
		}
		return "job", nil
	})
	got := respawnFindings(AutoKillProcesses(context.Background(), detachedKillConfig(), findings))
	if calls != 1 || len(got) != 1 {
		t.Fatalf("scan calls=%d escalations=%d", calls, len(got))
	}
}

func TestDetachedRespawnMemoryDoesNotDelayKills(t *testing.T) {
	withAccounts(t)
	withRespawnMemory(t)
	withScanRequester(t, nil)
	withWebProcTable(t, map[int]fakeProc{
		700: {ppid: 1, uid: "1001", exe: bashPath},
		800: {ppid: 1, uid: "1001", exe: bashPath},
	}, map[int][]string{700: {socketFD(5001)}, 800: {socketFD(5001)}})
	findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)
	killed := make(chan int, 2)
	prev := signalProcess
	signalProcess = func(_ context.Context, pid int, _ syscall.Signal, verify func() error) error {
		if err := verify(); err != nil {
			return err
		}
		killed <- pid
		return nil
	}
	t.Cleanup(func() { signalProcess = prev })
	detachedRespawns.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		AutoKillProcesses(context.Background(), detachedKillConfig(), findings)
	}()
	defer func() { detachedRespawns.mu.Unlock(); <-done }()
	for range 2 {
		select {
		case <-killed:
		case <-time.After(time.Second):
			t.Fatal("respawn memory delayed a kill")
		}
	}
}

func TestDetachedRespawnRollingWindowAndConcurrentStops(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := newDetachedRespawnMemory(func() time.Time { return now })
	withScanRequester(t, nil)
	f := alert.Finding{}
	if _, ok := m.noteStop(f, "1001"); ok {
		t.Fatal("first stop escalated")
	}
	now = now.Add(24 * time.Hour)
	if _, ok := m.noteStop(f, "1001"); ok {
		t.Fatal("expired first stop counted")
	}
	now = now.Add(time.Minute)
	var escalations atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := m.noteStop(f, "1001"); ok {
				escalations.Add(1)
			}
		}()
	}
	wg.Wait()
	if escalations.Load() != 1 {
		t.Fatalf("concurrent escalations = %d", escalations.Load())
	}
	now = now.Add(23 * time.Hour)
	if _, ok := m.noteStop(f, "1001"); ok {
		t.Fatal("daily suppression expired early")
	}
	now = now.Add(time.Hour)
	if _, ok := m.noteStop(f, "1001"); !ok {
		t.Fatal("recent stop lost at daily suppression boundary")
	}
}

// Scan-job reports consume structured outcomes rather than parsing prose.
func TestAutomaticQuarantineReportsOutcome(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "")
	f := responseFile(t, homes, "alice", "evidence.bin", []byte("test evidence"))
	actions := AutoQuarantineFiles(cfg, []alert.Finding{f})
	if len(actions) != 1 || actions[0].RemediationStatus != "quarantined" {
		t.Fatalf("quarantine outcome = %+v", actions)
	}
	f = responseFile(t, homes, "alice", "wp-content/plugins/example/main.php", []byte("<?php\n@include('/tmp/payload.php');\necho 'site';\n"))
	actions = AutoQuarantineFiles(cfg, []alert.Finding{f})
	if len(actions) != 1 || actions[0].RemediationStatus != "cleaned" {
		t.Fatalf("clean outcome = %+v", actions)
	}
	assertResponseFile(t, f.FilePath, []byte("<?php\necho 'site';\n"))
}
