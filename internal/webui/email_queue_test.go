package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func withEximProbe(t *testing.T, lookPath func(string) (string, error), run func(context.Context, string, ...string) ([]byte, error)) {
	t.Helper()
	oldLook, oldRun := eximLookPath, eximRun
	eximLookPath, eximRun = lookPath, run
	t.Cleanup(func() { eximLookPath, eximRun = oldLook, oldRun })
}

// The daemon serves this API from inside ProtectSystem=strict, where exim
// cannot open its own log and aborts. Calling it directly made the dashboard
// report an empty queue on every request.
func TestEximQueueSizeRunsOutsideTheSandbox(t *testing.T) {
	var gotName string
	var gotArgs []string
	withEximProbe(t,
		func(string) (string, error) { return "/usr/bin/systemd-run", nil },
		func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			return []byte("29\n"), nil
		})

	size, ok := eximQueueSize()

	if !ok || size != 29 {
		t.Fatalf("queue size = (%d, %v), want (29, true)", size, ok)
	}
	if gotName != "/usr/bin/systemd-run" {
		t.Errorf("probe ran %q directly; it must go through systemd-run", gotName)
	}
	if !strings.HasSuffix(strings.Join(gotArgs, " "), "exim -bpc") {
		t.Errorf("argv = %v, want it to end with the exim queue count", gotArgs)
	}
}

// Reporting zero for a queue that could not be read is indistinguishable from a
// healthy empty queue, which is exactly how this blind spot stayed hidden.
func TestEximQueueSizeReportsUnknownWhenProbeFails(t *testing.T) {
	withEximProbe(t,
		func(string) (string, error) { return "", exec.ErrNotFound },
		func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("exit status 1")
		})

	size, ok := eximQueueSize()

	if ok {
		t.Fatalf("a failed probe must not report a queue depth, got %d", size)
	}
}

func TestEximQueueDetailsRunsOutsideTheSandbox(t *testing.T) {
	var gotArgs []string
	withEximProbe(t,
		func(string) (string, error) { return "/usr/bin/systemd-run", nil },
		func(_ context.Context, _ string, args ...string) ([]byte, error) {
			gotArgs = args
			return []byte(""), nil
		})

	eximQueueDetails()

	if !strings.HasSuffix(strings.Join(gotArgs, " "), "exim -bp") {
		t.Errorf("argv = %v, want the wrapped exim queue listing", gotArgs)
	}
}

func TestAPIEmailStatsSerializesUnavailableQueue(t *testing.T) {
	withEximProbe(t,
		func(string) (string, error) { return "", exec.ErrNotFound },
		func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("exit status 1")
		})
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{}
	w := httptest.NewRecorder()

	s.apiEmailStats(w, httptest.NewRequest("GET", "/api/v1/email/stats", nil))

	var resp emailStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.QueueUnavailable {
		t.Fatalf("failed queue probe serialized as available: %+v", resp)
	}
}
