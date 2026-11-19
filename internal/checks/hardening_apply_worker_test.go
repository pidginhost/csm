package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/systemdrun"
)

func TestHandleHardeningApplyRefusesBadRequests(t *testing.T) {
	many := make([]string, hardeningApplyMaxNames+1)
	for i := range many {
		many[i] = "ssh_use_dns"
	}
	manyBody, _ := json.Marshal(HardeningApplyRequest{Category: "ssh", Names: many})
	for name, body := range map[string]string{
		"unknown field":    `{"category":"ssh","names":[],"force":true}`,
		"duplicate names":  `{"category":"ssh","names":["ssh_use_dns"],"names":[]}`,
		"null names":       `{"category":"ssh","names":null}`,
		"trailing data":    `{"category":"ssh"}{}`,
		"unknown category": `{"category":"nope"}`,
		"no category":      `{"names":["ssh_use_dns"]}`,
		"bad name":         `{"category":"ssh","names":["../etc/shadow"]}`,
		"upper case name":  `{"category":"ssh","names":["SSH_USE_DNS"]}`,
		"too many names":   string(manyBody),
		"oversized":        `{"category":"ssh","names":["` + strings.Repeat("a", hardeningApplyRequestLimit) + `"]}`,
		"not json":         `category=ssh`,
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			var out bytes.Buffer
			err := HandleHardeningApply(strings.NewReader(body), &out, func(string, []string) ([]HardeningFixResult, error) {
				called = true
				return nil, nil
			})
			if err == nil || called || out.Len() != 0 {
				t.Fatalf("err=%v called=%v out=%q", err, called, out.String())
			}
		})
	}
}

func TestHandleHardeningApplyWritesResults(t *testing.T) {
	var gotCat string
	var gotNames []string
	var out bytes.Buffer
	err := HandleHardeningApply(strings.NewReader(`{"category":"ssh","names":["ssh_use_dns"]}`), &out, func(cat string, names []string) ([]HardeningFixResult, error) {
		gotCat, gotNames = cat, names
		return []HardeningFixResult{{Name: "ssh_use_dns", Status: "applied", Message: "done"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotCat != "ssh" || !slices.Equal(gotNames, []string{"ssh_use_dns"}) {
		t.Fatalf("apply got %q %v", gotCat, gotNames)
	}
	var reply hardeningApplyReply
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatalf("reply %q: %v", out.String(), err)
	}
	if len(reply.Results) != 1 || reply.Results[0].Status != "applied" {
		t.Fatalf("reply = %+v", reply)
	}
}

func TestHandleHardeningApplyReportsApplyError(t *testing.T) {
	var out bytes.Buffer
	err := HandleHardeningApply(strings.NewReader(`{"category":"ssh"}`), &out, func(string, []string) ([]HardeningFixResult, error) {
		return nil, errors.New("boom")
	})
	if err == nil || !strings.Contains(err.Error(), "boom") || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
}

// The daemon's sandbox leaves /etc, /usr, /opt and /proc/sys read-only, so
// every fix runs in a root worker that PID 1 starts outside it.
func TestRunHardeningApplyWorkerRunsOutsideTheSandbox(t *testing.T) {
	var calls [][]string
	var inputs [][]byte
	run := func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		inputs = append(inputs, input)
		if slices.Contains(args, "/bin/true") {
			return nil, nil
		}
		return []byte(`{"results":[{"name":"ssh_use_dns","title":"UseDNS","status":"applied","message":"ok"}]}`), nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	got, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{ConfigFile: "/etc/csm/csm.yaml", ConfigDir: "/etc/custom/conf.d"}, lookPath, run,
		HardeningApplyRequest{Category: "ssh", Names: []string{"ssh_use_dns"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Status != "applied" {
		t.Fatalf("results = %+v", got)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v", calls)
	}
	if slices.Contains(calls[0], "--unit=csm-hardening-apply.service") {
		t.Fatal("availability probe claimed the worker's unit name")
	}
	worker := calls[1]
	if worker[0] != "/usr/bin/systemd-run" || !slices.Contains(worker, "--pipe") || slices.Contains(worker, "--scope") || !slices.Contains(worker, "--unit=csm-hardening-apply.service") {
		t.Fatalf("worker argv = %v", worker)
	}
	tail := worker[slices.Index(worker, "--")+1:]
	if !slices.Equal(tail, []string{"/usr/sbin/csm", "hardening-apply-worker", "--config", "/etc/csm/csm.yaml", "--config-dir", "/etc/custom/conf.d"}) {
		t.Fatalf("worker command = %v", tail)
	}
	var req HardeningApplyRequest
	if err := json.Unmarshal(inputs[1], &req); err != nil || req.Category != "ssh" || !slices.Equal(req.Names, []string{"ssh_use_dns"}) {
		t.Fatalf("worker input %q: %v", inputs[1], err)
	}
}

func TestRunHardeningApplyWorkerNeverRunsInsideTheSandbox(t *testing.T) {
	for name, tc := range map[string]struct {
		lookPath systemdrun.LookPathFunc
		probeErr error
	}{
		"no systemd-run": {func(string) (string, error) { return "", exec.ErrNotFound }, nil},
		"probe fails":    {func(string) (string, error) { return "/usr/bin/systemd-run", nil }, errors.New("Failed to start transient service unit")},
	} {
		t.Run(name, func(t *testing.T) {
			ran := false
			run := func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
				if slices.Contains(args, "/bin/true") {
					return nil, tc.probeErr
				}
				ran = true
				return nil, nil
			}
			_, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, tc.lookPath, run, HardeningApplyRequest{Category: "ssh"})
			if !errors.Is(err, systemdrun.ErrUnavailable) || ran {
				t.Fatalf("err=%v ran=%v", err, ran)
			}
		})
	}
}

func TestRunHardeningApplyWorkerOmitsEmptyConfigPath(t *testing.T) {
	var worker []string
	run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if !slices.Contains(args, "/bin/true") {
			worker = args
		}
		return []byte(`{"results":[]}`), nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	if _, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, HardeningApplyRequest{Category: "os"}); err != nil {
		t.Fatal(err)
	}
	if tail := worker[slices.Index(worker, "--")+1:]; !slices.Equal(tail, []string{"/usr/sbin/csm", "hardening-apply-worker"}) {
		t.Fatalf("worker command = %v", tail)
	}
}

func TestRunHardeningApplyWorkerReportsWorkerFailure(t *testing.T) {
	run := func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if slices.Contains(args, "/bin/true") {
			return nil, nil
		}
		return nil, errors.New("exit status 1: loading config: no such file")
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	_, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, HardeningApplyRequest{Category: "ssh"})
	if err == nil || !strings.Contains(err.Error(), "loading config") || errors.Is(err, systemdrun.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunHardeningApplyWorkerRejectsUnreadableReply(t *testing.T) {
	run := func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		return []byte("Running as unit: run-u1.service\n"), nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	if _, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, HardeningApplyRequest{Category: "ssh"}); err == nil {
		t.Fatal("an unreadable worker reply was accepted")
	}
}

func TestRunHardeningApplyWorkerValidatesBeforeStarting(t *testing.T) {
	ran := false
	run := func(context.Context, []byte, string, ...string) ([]byte, error) { ran = true; return nil, nil }
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	if _, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, HardeningApplyRequest{Category: "nope"}); err == nil || ran {
		t.Fatalf("err=%v ran=%v", err, ran)
	}
}

func TestRunHardeningApplyWorkerRequiresResults(t *testing.T) {
	for _, reply := range []string{"null", "{}", `{"results":null}`, `{"results":[{}]}`} {
		run := func(context.Context, []byte, string, ...string) ([]byte, error) { return []byte(reply), nil }
		lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
		if _, err := runHardeningApplyWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, HardeningApplyRequest{Category: "os"}); err == nil {
			t.Errorf("accepted worker reply %s", reply)
		}
	}
}
