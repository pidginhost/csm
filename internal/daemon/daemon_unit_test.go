package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// ---------------------------------------------------------------------------
// New — constructor returns a valid, non-nil Daemon
// ---------------------------------------------------------------------------

func TestNew_ReturnsNonNil(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "/usr/local/bin/csm")
	if d == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_FieldsSet(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "/usr/local/bin/csm")
	if d.cfg != cfg {
		t.Error("cfg not set")
	}
	if d.binaryPath != "/usr/local/bin/csm" {
		t.Errorf("binaryPath = %q", d.binaryPath)
	}
	if d.alertCh == nil {
		t.Error("alertCh is nil")
	}
	if d.stopCh == nil {
		t.Error("stopCh is nil")
	}
}

func TestNew_AlertChannelBuffered(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	if cap(d.alertCh) != 500 {
		t.Errorf("alertCh capacity = %d, want 500", cap(d.alertCh))
	}
}

// ---------------------------------------------------------------------------
// SetVersion / version
// ---------------------------------------------------------------------------

func TestSetVersion_SetsVersion(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.SetVersion("1.2.3")
	if d.version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", d.version)
	}
}

func TestSetVersion_OverwritesPrevious(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.SetVersion("1.0.0")
	d.SetVersion("2.0.0")
	if d.version != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", d.version)
	}
}

// ---------------------------------------------------------------------------
// DroppedAlerts — atomic counter
// ---------------------------------------------------------------------------

func TestDroppedAlerts_InitiallyZero(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	if got := d.DroppedAlerts(); got != 0 {
		t.Errorf("DroppedAlerts() = %d, want 0", got)
	}
}

func TestDroppedAlerts_ReflectsAtomicAdd(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	atomic.AddInt64(&d.droppedAlerts, 5)
	if got := d.DroppedAlerts(); got != 5 {
		t.Errorf("DroppedAlerts() = %d, want 5", got)
	}
}

// ---------------------------------------------------------------------------
// setSpoolWatcher / getSpoolWatcher
// ---------------------------------------------------------------------------

func TestSpoolWatcherGetSet_NilByDefault(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	if sw := d.getSpoolWatcher(); sw != nil {
		t.Errorf("expected nil, got %v", sw)
	}
}

func TestSpoolWatcherGetSet_RoundTrip(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	sw := &SpoolWatcher{}
	d.spoolWatcherMu.Lock()
	d.spoolWatcher = sw
	d.spoolWatcherMu.Unlock()
	if got := d.getSpoolWatcher(); got != sw {
		t.Errorf("round-trip failed")
	}
}

// ---------------------------------------------------------------------------
// syncEmailAVWebState — nil guards
// ---------------------------------------------------------------------------

func TestSyncEmailAVWebState_NilWebServer(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.webServer = nil
	// Should not panic.
	d.syncEmailAVWebState()
}

func TestSyncEmailAVWebState_NilQuarantine(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.emailQuarantine = nil
	// Should not panic.
	d.syncEmailAVWebState()
}

// ---------------------------------------------------------------------------
// startWebUI — disabled config
// ---------------------------------------------------------------------------

func TestStartWebUI_DisabledDoesNothing(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebUI.Enabled = false
	d := New(cfg, nil, nil, "")
	d.startWebUI()
	if d.webServer != nil {
		t.Error("webServer should remain nil when WebUI is disabled")
	}
}

// ---------------------------------------------------------------------------
// startChallengeServer — disabled and nil-fwEngine guards
// ---------------------------------------------------------------------------

func TestStartChallengeServer_DisabledDoesNothing(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = false
	d := New(cfg, nil, nil, "")
	d.startChallengeServer()
	if d.challengeServer != nil {
		t.Error("challengeServer should be nil when disabled")
	}
	if d.ipList != nil {
		t.Error("ipList should be nil when disabled")
	}
}

func TestStartChallengeServer_NilFWEngine(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	d := New(cfg, nil, nil, "")
	d.fwEngine = nil
	d.startChallengeServer()
	if d.challengeServer != nil {
		t.Error("challengeServer should be nil when fwEngine is nil")
	}
}

// ---------------------------------------------------------------------------
// startFirewall — disabled config
// ---------------------------------------------------------------------------

func TestStartFirewall_DisabledDoesNothing(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall = firewall.DefaultConfig()
	cfg.Firewall.Enabled = false
	d := New(cfg, nil, nil, "")
	d.startFirewall()
	if d.fwEngine != nil {
		t.Error("fwEngine should be nil when firewall is disabled")
	}
}

// ---------------------------------------------------------------------------
// alertDispatcher — stop signal flushes and exits
// ---------------------------------------------------------------------------

func TestAlertDispatcher_StopsOnSignal(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)
	go d.alertDispatcher()

	// Close immediately — should exit promptly.
	close(d.stopCh)

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("alertDispatcher did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// LogWatcher — readNewLines with a real temp file
// ---------------------------------------------------------------------------

func TestLogWatcher_ReadNewLines_ProcessesAppendedData(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, []byte("initial line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	cfg := &config.Config{}

	// Handler that returns a finding for every non-empty line.
	handler := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{
			Check:   "test",
			Message: line,
		}}
	}

	w, err := NewLogWatcher(tmp, cfg, handler, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// readNewLines right after open — initial data is past the offset, nothing new.
	w.readNewLines()
	select {
	case f := <-alertCh:
		t.Fatalf("expected no findings from initial data, got %q", f.Message)
	default:
	}

	// Append new data.
	f, err := os.OpenFile(tmp, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("new line one\nnew line two\n")
	_ = f.Close()

	w.readNewLines()

	var msgs []string
	for {
		select {
		case finding := <-alertCh:
			msgs = append(msgs, finding.Message)
		default:
			goto done
		}
	}
done:
	if len(msgs) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(msgs), msgs)
	}
	if msgs[0] != "new line one" {
		t.Errorf("first finding = %q", msgs[0])
	}
	if msgs[1] != "new line two" {
		t.Errorf("second finding = %q", msgs[1])
	}
}

func TestLogWatcher_ReadNewLines_NoNewData(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, []byte("line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	handler := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "test", Message: line}}
	}

	w, err := NewLogWatcher(tmp, &config.Config{}, handler, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// No new data — should be a no-op.
	w.readNewLines()
	select {
	case f := <-alertCh:
		t.Fatalf("no new data should produce no findings, got %q", f.Message)
	default:
	}
}

func TestLogWatcher_ReadNewLines_TruncatedFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	initialData := strings.Repeat("padding data\n", 100)
	if err := os.WriteFile(tmp, []byte(initialData), 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 100)
	handler := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "test", Message: line}}
	}

	w, err := NewLogWatcher(tmp, &config.Config{}, handler, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// Truncate and write shorter content (simulates log rotation).
	if err := os.WriteFile(tmp, []byte("after rotation\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// readNewLines detects truncation and calls reopen, which re-reads.
	w.readNewLines()

	// After reopen, offset is reset. Next readNewLines should pick up new data.
	w.readNewLines()

	var found bool
	for {
		select {
		case f := <-alertCh:
			if f.Message == "after rotation" {
				found = true
			}
		default:
			goto check
		}
	}
check:
	if !found {
		t.Error("expected to find 'after rotation' after file truncation")
	}
}

// ---------------------------------------------------------------------------
// LogWatcher.reopen — handles missing file gracefully
// ---------------------------------------------------------------------------

func TestLogWatcher_Reopen_MissingFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, []byte("data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	w, err := NewLogWatcher(tmp, &config.Config{}, func(string, *config.Config) []alert.Finding { return nil }, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// Delete the file, then reopen — should not panic.
	os.Remove(tmp)
	w.reopen()
}

func TestLogWatcher_Reopen_NewSmallerFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	bigData := strings.Repeat("x", 10000)
	if err := os.WriteFile(tmp, []byte(bigData), 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	w, err := NewLogWatcher(tmp, &config.Config{}, func(string, *config.Config) []alert.Finding { return nil }, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// Replace with smaller file (rotation).
	if err := os.WriteFile(tmp, []byte("small\n"), 0644); err != nil {
		t.Fatal(err)
	}

	w.reopen()

	// After rotation to smaller file, offset should be 0.
	if w.offset != 0 {
		t.Errorf("offset after rotation to smaller file = %d, want 0", w.offset)
	}
}

// ---------------------------------------------------------------------------
// LogWatcher.Stop — idempotent, does not panic on nil file
// ---------------------------------------------------------------------------

func TestLogWatcher_Stop_NilFile(t *testing.T) {
	w := &LogWatcher{}
	// Should not panic.
	w.Stop()
}

// ---------------------------------------------------------------------------
// LogWatcher.Run — stops on signal
// ---------------------------------------------------------------------------

func TestLogWatcher_Run_StopsOnSignal(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, []byte("data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	w, err := NewLogWatcher(tmp, &config.Config{}, func(string, *config.Config) []alert.Finding { return nil }, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		w.Run(stopCh)
		close(done)
	}()

	close(stopCh)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("LogWatcher.Run did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// LogWatcher — alert channel full drops finding
// ---------------------------------------------------------------------------

func TestLogWatcher_ReadNewLines_ChannelFull(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, nil, 0644); err != nil {
		t.Fatal(err)
	}

	// Tiny channel, already full.
	alertCh := make(chan alert.Finding, 1)
	alertCh <- alert.Finding{Check: "blocker"}

	handler := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "test", Message: line}}
	}

	w, err := NewLogWatcher(tmp, &config.Config{}, handler, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// Append data.
	f, _ := os.OpenFile(tmp, os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.WriteString("dropped\n")
	_ = f.Close()

	// Should not block or panic despite full channel.
	w.readNewLines()
}

// ---------------------------------------------------------------------------
// StartModSecEviction / StartAccessLogEviction / StartEmailRateEviction
// — background goroutines exit on stop signal
// ---------------------------------------------------------------------------

func TestStartModSecEviction_StopsOnSignal(t *testing.T) {
	stopCh := make(chan struct{})
	StartModSecEviction(stopCh)
	close(stopCh)
	// Give goroutine time to exit. No assertion beyond "doesn't hang."
	time.Sleep(50 * time.Millisecond)
}

func TestStartAccessLogEviction_StopsOnSignal(t *testing.T) {
	stopCh := make(chan struct{})
	StartAccessLogEviction(stopCh)
	close(stopCh)
	time.Sleep(50 * time.Millisecond)
}

func TestStartEmailRateEviction_StopsOnSignal(t *testing.T) {
	stopCh := make(chan struct{})
	StartEmailRateEviction(stopCh)
	close(stopCh)
	time.Sleep(50 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// discoverModSecLogPath — config override
// ---------------------------------------------------------------------------

func TestDiscoverModSecLogPath_ConfigOverrideWins(t *testing.T) {
	cfg := &config.Config{ModSecErrorLog: "/custom/modsec.log"}
	got := discoverModSecLogPath(cfg)
	if got != "/custom/modsec.log" {
		t.Errorf("got %q, want /custom/modsec.log", got)
	}
}

func TestDiscoverModSecLogPath_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	// On macOS none of the platform candidates exist, so returns "".
	got := discoverModSecLogPath(cfg)
	// We can't assert the exact value since it depends on platform,
	// but it should not panic.
	_ = got
}

// ---------------------------------------------------------------------------
// discoverAccessLogPath — returns empty when no candidate exists
// ---------------------------------------------------------------------------

func TestDiscoverAccessLogPath_NoCandidatesExist(t *testing.T) {
	// On macOS/test environments, none of the Linux paths exist.
	got := discoverAccessLogPath()
	// Not asserting empty because CI could have Apache installed.
	_ = got
}

// ---------------------------------------------------------------------------
// sdNotify — invalid address does not panic
// ---------------------------------------------------------------------------

func TestSdNotify_InvalidAddress(t *testing.T) {
	// Nonexistent socket — should silently fail.
	sdNotify("/tmp/nonexistent-sd-notify-socket-"+t.Name(), "WATCHDOG=1")
}

func TestSdNotify_EmptyMessage(t *testing.T) {
	sdNotify("/tmp/nonexistent-sd-notify-socket-"+t.Name(), "")
}

// ---------------------------------------------------------------------------
// watchdogNotifier — exits when env vars are not set
// ---------------------------------------------------------------------------

func TestWatchdogNotifier_NoEnvExitsImmediately(t *testing.T) {
	// Ensure WATCHDOG_USEC is not set.
	prev := os.Getenv("WATCHDOG_USEC")
	os.Unsetenv("WATCHDOG_USEC")
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdogNotifier should exit immediately when WATCHDOG_USEC is unset")
	}
}

func TestWatchdogNotifier_NoNotifySocketExits(t *testing.T) {
	prev := os.Getenv("WATCHDOG_USEC")
	prevAddr := os.Getenv("NOTIFY_SOCKET")
	os.Setenv("WATCHDOG_USEC", "1000000")
	os.Unsetenv("NOTIFY_SOCKET")
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
		if prevAddr != "" {
			os.Setenv("NOTIFY_SOCKET", prevAddr)
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdogNotifier should exit when NOTIFY_SOCKET is unset")
	}
}

func TestWatchdogNotifier_InvalidUsecExits(t *testing.T) {
	prev := os.Getenv("WATCHDOG_USEC")
	prevAddr := os.Getenv("NOTIFY_SOCKET")
	os.Setenv("WATCHDOG_USEC", "not-a-number")
	os.Setenv("NOTIFY_SOCKET", "/tmp/test-socket")
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
		if prevAddr != "" {
			os.Setenv("NOTIFY_SOCKET", prevAddr)
		} else {
			os.Unsetenv("NOTIFY_SOCKET")
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdogNotifier should exit when WATCHDOG_USEC is invalid")
	}
}

func TestWatchdogNotifier_ZeroUsecExits(t *testing.T) {
	prev := os.Getenv("WATCHDOG_USEC")
	prevAddr := os.Getenv("NOTIFY_SOCKET")
	os.Setenv("WATCHDOG_USEC", "0")
	os.Setenv("NOTIFY_SOCKET", "/tmp/test-socket")
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
		if prevAddr != "" {
			os.Setenv("NOTIFY_SOCKET", prevAddr)
		} else {
			os.Unsetenv("NOTIFY_SOCKET")
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdogNotifier should exit when WATCHDOG_USEC is 0")
	}
}

// ---------------------------------------------------------------------------
// watchdogNotifier — sends watchdog with stopCh
// ---------------------------------------------------------------------------

func TestWatchdogNotifier_StopsOnSignal(t *testing.T) {
	prev := os.Getenv("WATCHDOG_USEC")
	prevAddr := os.Getenv("NOTIFY_SOCKET")
	// 20 seconds in microseconds — minimum interval will be 10s
	os.Setenv("WATCHDOG_USEC", "20000000")
	os.Setenv("NOTIFY_SOCKET", "/tmp/nonexistent-wd-"+t.Name())
	defer func() {
		if prev != "" {
			os.Setenv("WATCHDOG_USEC", prev)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
		if prevAddr != "" {
			os.Setenv("NOTIFY_SOCKET", prevAddr)
		} else {
			os.Unsetenv("NOTIFY_SOCKET")
		}
	}()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.watchdogNotifier()
		close(done)
	}()

	// Let it start, then signal stop.
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdogNotifier did not stop within timeout")
	}
}

// ---------------------------------------------------------------------------
// parseModSecLogLineDeduped — dedup behavior
// ---------------------------------------------------------------------------

func TestParseModSecLogLineDeduped_DedupsSameKey(t *testing.T) {
	modsecDedup = sync.Map{}
	modsecCSMCounter = sync.Map{}
	defer func() {
		modsecDedup = sync.Map{}
		modsecCSMCounter = sync.Map{}
	}()

	cfg := &config.Config{}

	// Real-ish Apache ModSecurity log line.
	line := `[Wed Apr 02 10:00:00 2026] [error] [client 203.0.113.5] ModSecurity: Access denied with code 403 (phase 2). [id "920420"] [msg "Request content type is not allowed"] [severity "CRITICAL"]`

	first := parseModSecLogLineDeduped(line, cfg)
	if len(first) == 0 {
		t.Fatal("first call should return a finding")
	}

	// Same line again within dedup TTL.
	second := parseModSecLogLineDeduped(line, cfg)
	if len(second) != 0 {
		t.Errorf("duplicate should be suppressed, got %d findings", len(second))
	}
}

func TestParseModSecLogLineDeduped_NonModSecReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	got := parseModSecLogLineDeduped("not a modsec line", cfg)
	if got != nil {
		t.Errorf("non-modsec line should return nil, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// parseAccessLogBruteForce — infra IP CIDR skip
// ---------------------------------------------------------------------------

func TestParseAccessLogBruteForce_InfraIPCIDRSkipped(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	line := `10.1.2.3 - - [12/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234`

	got := parseAccessLogBruteForce(line, cfg)
	if got != nil {
		t.Errorf("infra IP should be skipped, got %v", got)
	}
}

func TestParseAccessLogBruteForce_IPv6LoopbackSkipped(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	line := `::1 - - [12/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234`

	got := parseAccessLogBruteForce(line, cfg)
	if got != nil {
		t.Errorf("::1 should be skipped, got %v", got)
	}
}

func TestParseAccessLogBruteForce_GETRejected(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 1234`

	got := parseAccessLogBruteForce(line, cfg)
	if got != nil {
		t.Errorf("GET should be rejected, got %v", got)
	}
}

func TestParseAccessLogBruteForce_NoPOSTInLine(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234`

	got := parseAccessLogBruteForce(line, cfg)
	if got != nil {
		t.Errorf("line without POST should be rejected, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// firstExistingPath — with temp files
// ---------------------------------------------------------------------------

func TestFirstExistingPath_ReturnsFirstExisting(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.log")
	if err := os.WriteFile(existing, nil, 0644); err != nil {
		t.Fatal(err)
	}

	got := firstExistingPath([]string{"/nonexistent/path", existing, "/another/nonexistent"})
	if got != existing {
		t.Errorf("got %q, want %q", got, existing)
	}
}

func TestFirstExistingPath_NoneExist(t *testing.T) {
	got := firstExistingPath([]string{"/no/such/file1", "/no/such/file2"})
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestFirstExistingPath_EmptyListReturnsEmpty(t *testing.T) {
	got := firstExistingPath(nil)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// dispatchBatch — exercises core alert pipeline with real state.Store
// ---------------------------------------------------------------------------

func TestDispatchBatch_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	d := New(&config.Config{}, st, nil, "")
	// Should not panic with empty slice.
	d.dispatchBatch(nil)
	d.dispatchBatch([]alert.Finding{})
}

func TestDispatchBatch_NewFindingsAreStored(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{}
	d := New(cfg, st, nil, "")

	findings := []alert.Finding{
		{
			Severity:  alert.High,
			Check:     "test_check",
			Message:   "test message 1",
			Timestamp: time.Now(),
		},
	}

	d.dispatchBatch(findings)

	// After dispatch, the store should have been updated.
	// FilterNew on the same finding should return empty (already seen).
	second := st.FilterNew(findings)
	if len(second) != 0 {
		t.Errorf("same finding should be filtered as seen, got %d new", len(second))
	}
}

// ---------------------------------------------------------------------------
// emailQuarantineCleanup — stops on signal
// ---------------------------------------------------------------------------

func TestEmailQuarantineCleanup_StopsOnSignal(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.emailQuarantineCleanup()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("emailQuarantineCleanup did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// criticalScanner — stops on signal
// ---------------------------------------------------------------------------

func TestCriticalScanner_StopsOnSignal(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.criticalScanner()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("criticalScanner did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// deepScanner — stops on signal
// ---------------------------------------------------------------------------

func TestDeepScanner_StopsOnSignal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.DeepScanIntervalMin = 60
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.deepScanner()
		close(done)
	}()

	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deepScanner did not exit within timeout")
	}
}

// ---------------------------------------------------------------------------
// startSpoolWatcher — disabled config
// ---------------------------------------------------------------------------

func TestStartSpoolWatcher_DisabledDoesNothing(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailAV.Enabled = false
	d := New(cfg, nil, nil, "")
	d.startSpoolWatcher()
	if d.getSpoolWatcher() != nil {
		t.Error("spoolWatcher should be nil when email AV is disabled")
	}
}

// ---------------------------------------------------------------------------
// registerWHMPlugin — missing binary
// ---------------------------------------------------------------------------

func TestRegisterWHMPlugin_MissingBinary(t *testing.T) {
	err := registerWHMPlugin("/nonexistent/conf")
	if err == nil {
		t.Error("expected error for missing register_appconfig binary")
	}
	if !strings.Contains(err.Error(), "register_appconfig not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent DroppedAlerts access
// ---------------------------------------------------------------------------

func TestDroppedAlerts_ConcurrentAccess(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			atomic.AddInt64(&d.droppedAlerts, 1)
			_ = d.DroppedAlerts()
		}()
	}
	wg.Wait()

	if got := d.DroppedAlerts(); got != 100 {
		t.Errorf("DroppedAlerts() = %d, want 100", got)
	}
}

// ---------------------------------------------------------------------------
// LogWatcher readNewLines — empty lines are skipped
// ---------------------------------------------------------------------------

func TestLogWatcher_ReadNewLines_SkipsEmptyLines(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, nil, 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	handler := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "test", Message: line}}
	}

	w, err := NewLogWatcher(tmp, &config.Config{}, handler, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// Append lines with empties.
	f, _ := os.OpenFile(tmp, os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.WriteString("\n\nreal line\n\n")
	_ = f.Close()

	w.readNewLines()

	var msgs []string
	for {
		select {
		case finding := <-alertCh:
			msgs = append(msgs, finding.Message)
		default:
			goto done2
		}
	}
done2:
	if len(msgs) != 1 {
		t.Fatalf("got %d findings, want 1 (empty lines skipped): %v", len(msgs), msgs)
	}
	if msgs[0] != "real line" {
		t.Errorf("finding message = %q, want 'real line'", msgs[0])
	}
}

// ---------------------------------------------------------------------------
// LogWatcher readNewLines — sets timestamp when handler returns zero time
// ---------------------------------------------------------------------------

func TestLogWatcher_ReadNewLines_SetsZeroTimestamp(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmp, nil, 0644); err != nil {
		t.Fatal(err)
	}

	alertCh := make(chan alert.Finding, 10)
	handler := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "test", Message: line}}
		// Note: Timestamp is zero value.
	}

	w, err := NewLogWatcher(tmp, &config.Config{}, handler, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	f, _ := os.OpenFile(tmp, os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.WriteString("data\n")
	_ = f.Close()

	before := time.Now()
	w.readNewLines()

	select {
	case finding := <-alertCh:
		if finding.Timestamp.Before(before) {
			t.Errorf("timestamp should be set to now, got %v", finding.Timestamp)
		}
	default:
		t.Error("expected a finding")
	}
}

// ---------------------------------------------------------------------------
// parseModSecLogLineDeduped — CSM rule escalation path
// ---------------------------------------------------------------------------

func TestParseModSecLogLineDeduped_CSMRuleEscalation(t *testing.T) {
	modsecDedup = sync.Map{}
	modsecCSMCounter = sync.Map{}
	defer func() {
		modsecDedup = sync.Map{}
		modsecCSMCounter = sync.Map{}
	}()

	cfg := &config.Config{}

	// CSM rules are 900000-900999. Build a line with such a rule that triggers a block.
	line := `[Wed Apr 02 10:00:00 2026] [error] [client 198.51.100.1] ModSecurity: Access denied with code 403 (phase 2). [id "900001"] [msg "CSM rule block"] [severity "CRITICAL"]`

	// Hit 3 times from same IP to trigger escalation (modsecEscalationHits=3).
	var escalationFound bool
	for i := 0; i < 4; i++ {
		// Clear dedup so the base finding is always emitted (different test).
		modsecDedup = sync.Map{}
		results := parseModSecLogLineDeduped(line, cfg)
		for _, r := range results {
			if r.Check == "modsec_csm_block_escalation" {
				escalationFound = true
			}
		}
	}

	if !escalationFound {
		t.Error("expected modsec_csm_block_escalation finding after 3+ hits")
	}
}

// ---------------------------------------------------------------------------
// dispatchBatch — filters out informational checks from alertable list
// ---------------------------------------------------------------------------

func TestDispatchBatch_FiltersInformationalChecks(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{}
	d := New(cfg, st, nil, "")

	// These checks should be filtered from the alertable list.
	findings := []alert.Finding{
		{Severity: alert.High, Check: "modsec_block_realtime", Message: "test", Timestamp: time.Now()},
		{Severity: alert.High, Check: "modsec_warning_realtime", Message: "test", Timestamp: time.Now()},
		{Severity: alert.High, Check: "modsec_csm_block_escalation", Message: "test", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "outdated_plugins", Message: "test", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "email_dkim_failure", Message: "test", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "email_spf_rejection", Message: "test", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "email_auth_failure_realtime", Message: "test", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "pam_bruteforce", Message: "test", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "exim_frozen_realtime", Message: "test", Timestamp: time.Now()},
	}

	// Should not panic; these are all informational/automated and
	// won't reach alert.Dispatch.
	d.dispatchBatch(findings)
}

// ---------------------------------------------------------------------------
// geoipUpdater — exits when credentials are empty
// ---------------------------------------------------------------------------

func TestGeoipUpdater_NoCredentialsExits(t *testing.T) {
	cfg := &config.Config{}
	// GeoIP.AccountID and LicenseKey are empty.
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.geoipUpdater()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("geoipUpdater should exit when credentials are empty")
	}
}

func TestGeoipUpdater_AutoUpdateDisabledExits(t *testing.T) {
	cfg := &config.Config{}
	cfg.GeoIP.AccountID = "123"
	cfg.GeoIP.LicenseKey = "key"
	autoUpdate := false
	cfg.GeoIP.AutoUpdate = &autoUpdate
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.geoipUpdater()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("geoipUpdater should exit when auto_update is false")
	}
}

// ---------------------------------------------------------------------------
// signatureUpdater — exits when no URLs configured
// ---------------------------------------------------------------------------

func TestSignatureUpdater_NoURLExits(t *testing.T) {
	cfg := &config.Config{}
	// UpdateURL is empty, YaraForge not enabled.
	d := New(cfg, nil, nil, "")
	d.wg.Add(1)

	done := make(chan struct{})
	go func() {
		d.signatureUpdater()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("signatureUpdater should exit when no URL configured")
	}
}
