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

func TestHandleHardeningUndoRefusesBadRequests(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":   `{"name":"ssh_use_dns","force":true}`,
		"duplicate name":  `{"name":"ssh_use_dns","name":"cp_updates"}`,
		"null name":       `{"name":null}`,
		"no name":         `{}`,
		"names list":      `{"names":["ssh_use_dns"]}`,
		"array":           `[{"name":"ssh_use_dns"}]`,
		"trailing data":   `{"name":"ssh_use_dns"}{}`,
		"unknown fix":     `{"name":"ssh_port"}`,
		"bad name":        `{"name":"../etc/shadow"}`,
		"upper case name": `{"name":"SSH_USE_DNS"}`,
		"oversized":       `{"name":"` + strings.Repeat("a", hardeningApplyRequestLimit) + `"}`,
		"not json":        `name=ssh_use_dns`,
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			var out bytes.Buffer
			err := HandleHardeningUndo(strings.NewReader(body), &out, func(string) HardeningFixResult {
				called = true
				return HardeningFixResult{}
			})
			if err == nil || called || out.Len() != 0 {
				t.Fatalf("err=%v called=%v out=%q", err, called, out.String())
			}
		})
	}
}

func TestHandleHardeningUndoWritesResult(t *testing.T) {
	var got string
	var out bytes.Buffer
	err := HandleHardeningUndo(strings.NewReader(`{"name":"ssh_use_dns"}`), &out, func(name string) HardeningFixResult {
		got = name
		return HardeningFixResult{Name: name, Title: name, Status: "undone", Message: "done"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "ssh_use_dns" {
		t.Fatalf("undo got %q", got)
	}
	var reply HardeningFixResult
	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reply); err != nil || dec.More() {
		t.Fatalf("reply %q: %v", out.String(), err)
	}
	if want := (HardeningFixResult{Name: "ssh_use_dns", Title: "ssh_use_dns", Status: "undone", Message: "done"}); reply != want {
		t.Fatalf("reply = %+v, want %+v", reply, want)
	}
}

// Apply and undo run under one unit name, so systemd never runs both at
// once: they change the same files and records.
func TestRunHardeningUndoWorkerRunsOutsideTheSandbox(t *testing.T) {
	var calls [][]string
	var inputs [][]byte
	run := func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		inputs = append(inputs, input)
		if slices.Contains(args, "/bin/true") {
			return nil, nil
		}
		return []byte(`{"name":"ssh_use_dns","title":"ssh_use_dns","status":"undone","message":"ok"}` + "\n"), nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	got, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{ConfigFile: "/etc/csm/csm.yaml", ConfigDir: "/etc/custom/conf.d"}, lookPath, run, "ssh_use_dns")
	if err != nil {
		t.Fatal(err)
	}
	if want := (HardeningFixResult{Name: "ssh_use_dns", Title: "ssh_use_dns", Status: "undone", Message: "ok"}); got != want {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v", calls)
	}
	if slices.Contains(calls[0], "--unit=csm-hardening-apply.service") {
		t.Fatal("availability probe claimed the worker's unit name")
	}
	worker := calls[1]
	for _, flag := range []string{"--pipe", "--unit=csm-hardening-apply.service", "--property=RuntimeMaxSec=480s"} {
		if !slices.Contains(worker, flag) {
			t.Fatalf("worker argv = %v, missing %s", worker, flag)
		}
	}
	if worker[0] != "/usr/bin/systemd-run" || slices.Contains(worker, "--scope") {
		t.Fatalf("worker argv = %v", worker)
	}
	tail := worker[slices.Index(worker, "--")+1:]
	if !slices.Equal(tail, []string{"/usr/sbin/csm", "hardening-undo-worker", "--config", "/etc/csm/csm.yaml", "--config-dir", "/etc/custom/conf.d"}) {
		t.Fatalf("worker command = %v", tail)
	}
	if string(inputs[1]) != `{"name":"ssh_use_dns"}` {
		t.Fatalf("worker input = %q", inputs[1])
	}
}

func TestRunHardeningUndoWorkerNeverRunsInsideTheSandbox(t *testing.T) {
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
			_, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, tc.lookPath, run, "ssh_use_dns")
			if !errors.Is(err, systemdrun.ErrUnavailable) || ran {
				t.Fatalf("err=%v ran=%v", err, ran)
			}
		})
	}
}

func TestRunHardeningUndoWorkerOmitsEmptyConfigPath(t *testing.T) {
	var worker []string
	run := func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if !slices.Contains(args, "/bin/true") {
			worker = args
		}
		return []byte(`{"name":"cp_updates","status":"refused","message":"There is no undo record for this fix."}`), nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	if _, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, "cp_updates"); err != nil {
		t.Fatal(err)
	}
	if tail := worker[slices.Index(worker, "--")+1:]; !slices.Equal(tail, []string{"/usr/sbin/csm", "hardening-undo-worker"}) {
		t.Fatalf("worker command = %v", tail)
	}
}

func TestRunHardeningUndoWorkerReportsWorkerFailure(t *testing.T) {
	run := func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if slices.Contains(args, "/bin/true") {
			return nil, nil
		}
		return nil, errors.New("exit status 1: loading config: no such file")
	}
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	_, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, "ssh_use_dns")
	if err == nil || !strings.Contains(err.Error(), "loading config") || errors.Is(err, systemdrun.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunHardeningUndoWorkerValidatesBeforeStarting(t *testing.T) {
	for _, name := range []string{"", "ssh_port", "../cp_updates", "SSH_USE_DNS"} {
		ran := false
		run := func(context.Context, []byte, string, ...string) ([]byte, error) { ran = true; return nil, nil }
		lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
		if _, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, name); err == nil || ran {
			t.Errorf("%q: err=%v ran=%v", name, err, ran)
		}
	}
}

func TestRunHardeningUndoWorkerChecksReply(t *testing.T) {
	for _, status := range []string{"undone", "refused", "failed"} {
		reply := `{"name":"ssh_use_dns","title":"ssh_use_dns","status":"` + status + `","message":"m"}`
		run := func(context.Context, []byte, string, ...string) ([]byte, error) { return []byte(reply), nil }
		lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
		if got, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, "ssh_use_dns"); err != nil || got.Status != status {
			t.Errorf("reply %s: %+v, %v", reply, got, err)
		}
	}
	for _, reply := range []string{
		"Running as unit: run-u1.service\n",
		"null",
		"{}",
		`{"name":"cp_updates","status":"undone"}`,
		`{"name":"ssh_use_dns","status":"applied"}`,
		`{"name":"ssh_use_dns","status":"skipped"}`,
		`{"name":"ssh_use_dns","status":"undone","extra":1}`,
		`{"name":"ssh_use_dns","status":"undone"}{}`,
		`[{"name":"ssh_use_dns","status":"undone"}]`,
		`{"results":[{"name":"ssh_use_dns","status":"undone"}]}`,
	} {
		run := func(context.Context, []byte, string, ...string) ([]byte, error) { return []byte(reply), nil }
		lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
		if got, err := runHardeningUndoWorker(context.Background(), "/usr/sbin/csm", &config.Config{}, lookPath, run, "ssh_use_dns"); err == nil {
			t.Errorf("accepted worker reply %s as %+v", reply, got)
		}
	}
}
