package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
)

func withUserdomains(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "userdomains")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := userdomainsPath
	userdomainsPath = path
	t.Cleanup(func() { userdomainsPath = old })
}

// stubUAPI replaces the uapi runner and returns the argument lists it saw.
func stubUAPI(t *testing.T, respond func(args []string) ([]byte, error)) *[][]string {
	t.Helper()
	var mu sync.Mutex
	calls := &[][]string{}
	prev := uapiExec
	uapiExec = func(_ context.Context, args ...string) ([]byte, error) {
		mu.Lock()
		*calls = append(*calls, append([]string(nil), args...))
		mu.Unlock()
		return respond(args)
	}
	t.Cleanup(func() { uapiExec = prev })
	return calls
}

// stubAccountHold replaces the account-wide hold and returns its targets.
func stubAccountHold(t *testing.T, result bool) *[]string {
	t.Helper()
	var mu sync.Mutex
	holds := &[]string{}
	prev := autoSuspendOutgoingMail
	autoSuspendOutgoingMail = func(target string) bool {
		mu.Lock()
		*holds = append(*holds, target)
		mu.Unlock()
		return result
	}
	t.Cleanup(func() { autoSuspendOutgoingMail = prev })
	return holds
}

func uapiOK() ([]byte, error) {
	return []byte(`{"apiversion":3,"func":"suspend_login","module":"Email","result":{"data":null,"errors":null,"messages":null,"metadata":{},"status":1,"warnings":null}}`), nil
}

func uapiFailure(msg string) ([]byte, error) {
	return []byte(`{"apiversion":3,"result":{"data":null,"errors":["` + msg + `"],"status":0}}`), errors.New("exit status 1")
}

func uapiArgs(fn string) []string {
	return []string{"--output=json", "--user=cpuser", "Email", fn, "email=real@victim.example"}
}

func TestMaybeSuspendMailbox_GatedByConfig(t *testing.T) {
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)

	dryRunOn := true
	enabledDry := &config.Config{}
	enabledDry.AutoResponse.Enabled = true
	enabledDry.AutoResponse.DryRun = &dryRunOn
	enabledDefaultDry := &config.Config{}
	enabledDefaultDry.AutoResponse.Enabled = true

	for _, tc := range []struct {
		name        string
		cfg         *config.Config
		wantRecords int
	}{
		{"nil config", nil, 0},
		{"defaults (disabled + dry-run)", &config.Config{}, 0},
		{"enabled but dry-run", enabledDry, 1},
		{"enabled with default dry-run", enabledDefaultDry, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := captureActionRecords(t)
			if maybeSuspendMailbox(tc.cfg, "real@victim.example", "test") {
				t.Error("reported the mailbox as suspended")
			}
			if len(*calls) != 0 || len(*holds) != 0 {
				t.Fatalf("gated-off response ran uapi %v and holds %v", *calls, *holds)
			}
			if len(sink.records) != tc.wantRecords {
				t.Fatalf("records = %+v, want %d", sink.records, tc.wantRecords)
			}
			for _, rec := range sink.records {
				if rec.Op != "respond.suspend_mailbox" || rec.Result != actionlog.DryRun || rec.Target != "real@victim.example" || rec.Reason != "test" {
					t.Errorf("dry-run record = %+v", rec)
				}
			}
		})
	}
}

func TestMaybeSuspendMailbox_SuspendsLoginAndOutgoing(t *testing.T) {
	withUserdomains(t, "other.example: someone\nvictim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	sink := captureActionRecords(t)

	if !maybeSuspendMailbox(eximAutoHoldConfig(), "real@victim.example", "credential abuse") {
		t.Fatal("live response must report the mailbox as suspended")
	}
	want := [][]string{uapiArgs("suspend_login"), uapiArgs("suspend_outgoing")}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("uapi calls = %v, want %v", *calls, want)
	}
	if len(*holds) != 0 {
		t.Fatalf("account hold must not run after a successful mailbox suspension: %v", *holds)
	}
	if len(sink.records) != 2 {
		t.Fatalf("action records = %d, want 2: %+v", len(sink.records), sink.records)
	}
	for i, rec := range sink.records {
		if rec.Op != "respond.suspend_mailbox" || rec.Result != actionlog.Applied {
			t.Errorf("record %d: op=%q result=%q", i, rec.Op, rec.Result)
		}
		if rec.Target != "real@victim.example" || rec.Account != "cpuser" || rec.Reason != "credential abuse" {
			t.Errorf("record %d: target=%q account=%q reason=%q", i, rec.Target, rec.Account, rec.Reason)
		}
		if !reflect.DeepEqual(rec.Command, append([]string{"/usr/local/cpanel/bin/uapi"}, want[i]...)) {
			t.Errorf("record %d: command = %v", i, rec.Command)
		}
	}
	if sink.records[0].Action != "suspend_login" || sink.records[1].Action != "suspend_outgoing" {
		t.Errorf("record actions = %q, %q", sink.records[0].Action, sink.records[1].Action)
	}
	if u := sink.records[0].Undo; !strings.Contains(u, "unsuspend_login") || !strings.Contains(u, "--user=cpuser") || !strings.Contains(u, "email=real@victim.example") {
		t.Errorf("login undo = %q", u)
	}
	if u := sink.records[1].Undo; !strings.Contains(u, "unsuspend_outgoing") {
		t.Errorf("outgoing undo = %q", u)
	}
}

func TestMaybeSuspendMailbox_LoginFailureStillCountsOutgoing(t *testing.T) {
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func(args []string) ([]byte, error) {
		if args[3] == "suspend_login" {
			return uapiFailure("The system failed to lock the mailbox")
		}
		return uapiOK()
	})
	holds := stubAccountHold(t, true)
	sink := captureActionRecords(t)

	if !maybeSuspendMailbox(eximAutoHoldConfig(), "real@victim.example", "test") {
		t.Fatal("outgoing suspension alone still stops the sending and must report success")
	}
	if len(*calls) != 2 || len(*holds) != 0 {
		t.Fatalf("calls=%v holds=%v", *calls, *holds)
	}
	if sink.records[0].Result != actionlog.Failed || !strings.Contains(sink.records[0].Error, "failed to lock") {
		t.Errorf("login record = %+v", sink.records[0])
	}
	if sink.records[1].Result != actionlog.Applied {
		t.Errorf("outgoing record = %+v", sink.records[1])
	}
}

func TestMaybeSuspendMailbox_ResultStatusControlsFallback(t *testing.T) {
	for _, tc := range []struct {
		name            string
		login, outgoing string
		execErr         error
		wantHold        bool
		wantResults     []actionlog.Result
	}{
		{"login only", `{"result":{"status":1,"errors":null}}`, `{"result":{"status":0,"errors":null}}`, errors.New("exit status 1"), false, []actionlog.Result{actionlog.Applied, actionlog.Failed}},
		{"both API failures with zero exit", `{"result":{"status":0,"errors":["login failed"]}}`, `{"result":{"status":0,"errors":["outgoing failed"]}}`, nil, true, []actionlog.Result{actionlog.Failed, actionlog.Failed}},
		{"both timed out", "", "", context.DeadlineExceeded, true, []actionlog.Result{actionlog.Failed, actionlog.Failed}},
		{"no result", `{}`, `{"result":null}`, nil, true, []actionlog.Result{actionlog.Failed, actionlog.Failed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withUserdomains(t, "example.com: cpuser\n")
			calls := stubUAPI(t, func(args []string) ([]byte, error) {
				if args[3] == "suspend_login" {
					return []byte(tc.login), tc.execErr
				}
				return []byte(tc.outgoing), tc.execErr
			})
			holds := stubAccountHold(t, true)
			sink := captureActionRecords(t)
			if !maybeSuspendMailbox(eximAutoHoldConfig(), "alice@example.com", "test") {
				t.Fatal("successful suspension or fallback did not report stopped")
			}
			if len(*calls) != 2 || len(sink.records) != 2 {
				t.Fatalf("want two attempts and records: calls=%v records=%v", *calls, sink.records)
			}
			wantHolds := []string{}
			if tc.wantHold {
				wantHolds = append(wantHolds, "alice@example.com")
			}
			if !reflect.DeepEqual(*holds, wantHolds) {
				t.Errorf("holds = %v, want %v", *holds, wantHolds)
			}
			for i, rec := range sink.records {
				if rec.Result != tc.wantResults[i] || rec.Undo == "" {
					t.Errorf("record %d = %+v", i, rec)
				}
			}
		})
	}
}

func TestMailboxSuspensionSetsTimeout(t *testing.T) {
	prev := uapiExec
	t.Cleanup(func() { uapiExec = prev })
	calls := 0
	uapiExec = func(ctx context.Context, args ...string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if left := time.Until(deadline); !ok || left <= 0 || left > 20*time.Second {
			t.Fatalf("uapi context deadline = %v, set=%v", deadline, ok)
		}
		calls++
		return uapiOK()
	}
	withUserdomains(t, "example.com: cpuser\n")
	stubAccountHold(t, true)
	captureActionRecords(t)
	if !maybeSuspendMailbox(eximAutoHoldConfig(), "alice@example.com", "test") || calls != 2 {
		t.Fatalf("expected two bounded calls, got %d", calls)
	}
}

func TestMaybeSuspendMailbox_FallsBackToAccountHold(t *testing.T) {
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) {
		return nil, errors.New("exec: \"uapi\": executable file not found in $PATH")
	})
	holds := stubAccountHold(t, true)
	sink := captureActionRecords(t)

	if !maybeSuspendMailbox(eximAutoHoldConfig(), "real@victim.example", "test") {
		t.Fatal("a successful fallback hold must be reported as stopped")
	}
	if len(*calls) != 2 {
		t.Fatalf("both suspensions must be attempted before falling back, got %v", *calls)
	}
	if !reflect.DeepEqual(*holds, []string{"real@victim.example"}) {
		t.Fatalf("holds = %v, want the mailbox once", *holds)
	}
	for i, rec := range sink.records {
		if rec.Result != actionlog.Failed || !strings.Contains(rec.Error, "not found") {
			t.Errorf("record %d = %+v", i, rec)
		}
	}
	holdsFailed := stubAccountHold(t, false)
	if maybeSuspendMailbox(eximAutoHoldConfig(), "real@victim.example", "test") {
		t.Fatal("when the fallback hold fails nothing was stopped")
	}
	if len(*holdsFailed) != 1 {
		t.Fatalf("fallback hold calls = %d, want 1", len(*holdsFailed))
	}
}

func TestMaybeSuspendMailbox_UnresolvedMailboxHoldsAccount(t *testing.T) {
	withUserdomains(t, "other.example: someone\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)

	for _, target := range []string{"real@victim.example", "victim.example"} {
		if !maybeSuspendMailbox(eximAutoHoldConfig(), target, "test") {
			t.Errorf("%s: fallback hold result must be returned", target)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi must not run without a cPanel account: %v", *calls)
	}
	if !reflect.DeepEqual(*holds, []string{"real@victim.example", "victim.example"}) {
		t.Fatalf("holds = %v", *holds)
	}
}

func TestUAPIResultError(t *testing.T) {
	for _, tc := range []struct {
		name, out, want string
	}{
		{"ok", `{"result":{"status":1,"errors":null}}`, ""},
		{"api failure", `{"result":{"status":0,"errors":["Account does not exist.","second"]}}`, "Account does not exist.; second"},
		{"failure without message", `{"result":{"status":0}}`, "without an error message"},
		{"not json", "Can't locate Cpanel/Foo.pm in @INC", "unreadable uapi reply"},
		{"empty", "", "unreadable uapi reply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := uapiResultError([]byte(tc.out))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestRunUAPI_EscapesSandboxWhenSystemdRunExists(t *testing.T) {
	var ran [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		ran = append(ran, append([]string{name}, args...))
		return []byte("{}"), nil
	}
	lookPath := func(file string) (string, error) {
		if file == "systemd-run" {
			return "/usr/bin/systemd-run", nil
		}
		return "", errors.New("not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := runUAPI(ctx, lookPath, run, "--output=json", "Email", "suspend_login"); err != nil {
		t.Fatal(err)
	}
	// A side-effect-free probe runs first, then the wrapped command.
	if len(ran) != 2 {
		t.Fatalf("commands run = %v, want probe then uapi", ran)
	}
	last := ran[1]
	if last[0] != "/usr/bin/systemd-run" || !strings.Contains(strings.Join(last, " "), "--pipe") {
		t.Fatalf("uapi was not wrapped in a transient unit: %v", last)
	}
	var runtimeLimit time.Duration
	for _, arg := range last {
		if value, ok := strings.CutPrefix(arg, "--property=RuntimeMaxSec="); ok {
			var err error
			runtimeLimit, err = time.ParseDuration(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		if arg == "--scope" {
			t.Fatal("uapi must escape the daemon's sandbox")
		}
	}
	if runtimeLimit <= 0 || runtimeLimit > 20*time.Second {
		t.Fatalf("transient unit runtime limit = %s, argv = %v", runtimeLimit, last)
	}
	if tail := last[len(last)-5:]; !reflect.DeepEqual(tail, []string{"--", "/usr/local/cpanel/bin/uapi", "--output=json", "Email", "suspend_login"}) {
		t.Fatalf("wrapped argv does not end with the uapi command: %v", last)
	}

	ran = nil
	missing := func(string) (string, error) { return "", errors.New("not found") }
	if _, err := runUAPI(context.Background(), missing, run, "--output=json"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ran, [][]string{{"/usr/local/cpanel/bin/uapi", "--output=json"}}) {
		t.Fatalf("without systemd-run uapi must run directly: %v", ran)
	}
}

func TestMailboxSuspensionUndoPreservesIdentity(t *testing.T) {
	withUserdomains(t, "example.com: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	sink := captureActionRecords(t)
	for _, mailbox := range []string{
		"alice@example.com",
		"o'brien@example.com",
		"name${INVOCATION_ID}@example.com",
		"name$(printf${IFS}changed)@example.com",
		"name`printf${IFS}changed`@example.com",
		"name;printf${IFS}changed@example.com",
	} {
		t.Run(mailbox, func(t *testing.T) {
			line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example.com [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:" + mailbox + " S=100"
			identity := extractAuthUser(line)
			if identity != mailbox {
				t.Fatalf("authenticated identity = %q, want %q", identity, mailbox)
			}
			if !maybeSuspendMailbox(eximAutoHoldConfig(), identity, "test") {
				t.Fatal("suspension failed")
			}
			for _, args := range (*calls)[len(*calls)-2:] {
				if args[4] != "email="+mailbox {
					t.Fatalf("uapi mailbox argument = %q", args[4])
				}
			}
			for _, rec := range sink.records[len(sink.records)-2:] {
				// Decode the actual undo through a shell without invoking cPanel.
				_, tail, ok := strings.Cut(rec.Undo, " ")
				if !ok {
					t.Fatalf("missing undo command: %+v", rec)
				}
				out, err := exec.Command("/bin/sh", "-c", "set -- "+tail+"\nprintf '%s\\n' \"$@\"").CombinedOutput()
				want := "--user=cpuser\nEmail\nun" + rec.Action + "\nemail=" + mailbox + "\n"
				if err != nil || string(out) != want {
					t.Errorf("undo did not preserve mailbox: output=%q error=%v, want %q", out, err, want)
				}
			}
		})
	}
	if len(*holds) != 0 {
		t.Fatalf("successful mailbox responses triggered account holds: %v", *holds)
	}
}

func TestUAPICommandSeparatesDiagnosticsFromJSON(t *testing.T) {
	for _, tc := range []struct {
		name, reply, exit string
		wantFailure       bool
	}{
		{"success", `{"result":{"status":1,"errors":null}}`, "0", false},
		{"failure", `{"result":{"status":0,"errors":["mailbox unavailable"]}}`, "1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := uapiCommand(context.Background(), "/bin/sh", "-c", "printf '%s\\n' \"$1\"; printf 'diagnostic\\n' >&2; exit \"$2\"", "sh", tc.reply, tc.exit)
			if string(out) != tc.reply+"\n" {
				t.Fatalf("API stdout contaminated by diagnostics: %q", out)
			}
			if (err != nil) != tc.wantFailure {
				t.Fatalf("process error = %v", err)
			}
			if tc.wantFailure && !strings.Contains(err.Error(), "diagnostic") {
				t.Errorf("process failure lost stderr: %v", err)
			}
			if apiErr := uapiResultError(out); (apiErr != nil) != tc.wantFailure {
				t.Errorf("API result = %v", apiErr)
			}
		})
	}
}

func TestUAPICommandBoundsInheritedPipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	// The shell exits, but its child retains stdout/stderr beyond the deadline.
	_, err := uapiCommand(ctx, "/bin/sh", "-c", "sleep 3 & wait")
	if err == nil {
		t.Fatal("timed-out command reported success")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited pipes delayed command cancellation for %s", elapsed)
	}
}

func TestCloudRelayCredentialAbuseAction_SuspendsMailboxBeforeAccountHold(t *testing.T) {
	resetEmailRateState()
	withUserdomains(t, "victim.example: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)

	handleCloudRelayCredentialAbuse(eximAutoHoldConfig(), "real@victim.example")

	if len(*calls) != 2 {
		t.Fatalf("cloud relay abuse must suspend the abused mailbox, uapi calls = %v", *calls)
	}
	if len(*holds) != 0 {
		t.Fatalf("account hold must stay the fallback, got %v", *holds)
	}
	emailRateSuppressed.mu.Lock()
	_, gotVictim := emailRateSuppressed.domains["victim.example"]
	emailRateSuppressed.mu.Unlock()
	if !gotVictim {
		t.Fatal("cloud-relay domain must be tracked as compromised after the suspension")
	}
}
