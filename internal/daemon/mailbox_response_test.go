package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

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
	sink := captureActionRecords(t)

	dryRunOn := true
	enabledDry := &config.Config{}
	enabledDry.AutoResponse.Enabled = true
	enabledDry.AutoResponse.DryRun = &dryRunOn

	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"defaults (disabled + dry-run)", &config.Config{}},
		{"enabled but dry-run", enabledDry},
	} {
		if maybeSuspendMailbox(tc.cfg, "real@victim.example", "test") {
			t.Errorf("%s: reported the mailbox as suspended", tc.name)
		}
	}
	if len(*calls) != 0 || len(*holds) != 0 {
		t.Fatalf("gated-off response ran uapi %v and holds %v", *calls, *holds)
	}
	var dryRun int
	for _, r := range sink.records {
		if r.Op != "respond.suspend_mailbox" {
			continue
		}
		if r.Result != actionlog.DryRun {
			t.Fatalf("gated-off response recorded %+v", r)
		}
		dryRun++
	}
	if dryRun != 1 {
		t.Fatalf("dry-run records = %d, want exactly one for the enabled dry-run config", dryRun)
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
		if !reflect.DeepEqual(rec.Command, append([]string{"uapi"}, want[i]...)) {
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
	if _, err := runUAPI(context.Background(), lookPath, run, "--output=json", "Email", "suspend_login"); err != nil {
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
	if tail := last[len(last)-5:]; !reflect.DeepEqual(tail, []string{"--", "uapi", "--output=json", "Email", "suspend_login"}) {
		t.Fatalf("wrapped argv does not end with the uapi command: %v", last)
	}

	ran = nil
	missing := func(string) (string, error) { return "", errors.New("not found") }
	if _, err := runUAPI(context.Background(), missing, run, "--output=json"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ran, [][]string{{"uapi", "--output=json"}}) {
		t.Fatalf("without systemd-run uapi must run directly: %v", ran)
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
