package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func systemdRun(string) (string, error) { return "/usr/bin/systemd-run", nil }

func TestRunUsesFixedBoundedTransientCommand(t *testing.T) {
	var calls [][]string
	result, err := execute(context.Background(), "/opt/csm/csm", systemdRun, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 2 {
			return []byte(`{"operation":"remove","ok":true}` + "\n"), nil
		}
		return nil, nil
	})
	want := [][]string{
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/bin/true"},
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/opt/csm/csm", "antispam-worker"},
	}
	if err != nil || !result.OK || !reflect.DeepEqual(calls, want) {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls)
	}
}

// The worker exits 1 for a busy or failed transaction and still prints its
// result; the caller needs that result, not a generic failure.
func TestRunReturnsResultFromFailedExit(t *testing.T) {
	exit := errors.New("exit status 1")
	result, err := execute(context.Background(), "/opt/csm/csm", systemdRun, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "/bin/true" {
			return nil, nil
		}
		return []byte(`{"operation":"apply","ok":false,"busy":true,"failed_step":"lock","rollback":"none","error":"held"}` + "\n"), exit
	})
	if err != nil || !result.Busy || result.OK || result.FailedStep != "lock" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRunReportsMissingResult(t *testing.T) {
	crash := errors.New("signal: killed: worker stack")
	for name, tc := range map[string]struct {
		out  string
		err  error
		want string
	}{
		"crash":       {"", crash, "worker stack"},
		"clean exit":  {"", nil, "returned no result"},
		"garbled out": {"partial {", nil, "returned no result"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := execute(context.Background(), "/opt/csm/csm", systemdRun, func(_ context.Context, name string, args ...string) ([]byte, error) {
				if args[len(args)-1] == "/bin/true" {
					return nil, nil
				}
				return []byte(tc.out), tc.err
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The daemon and the worker agree on the wire format: a request built by
// the daemon decodes in Handle, and Handle's output parses in Run.
func TestRunAndHandleShareTheProtocol(t *testing.T) {
	settings := antispam.Settings{DryRun: false, Socket: "/var/run/rspamd/scan.sock", RejectScore: 20, TagScore: 8}
	body, err := json.Marshal(antispam.ApplyRequest(settings))
	if err != nil {
		t.Fatal(err)
	}
	tr := &fakeTransactor{result: antispam.Result{OK: true, Generation: "g2"}}
	result, err := execute(context.Background(), "/opt/csm/csm", func(string) (string, error) { return "", errors.New("not installed") },
		func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "/opt/csm/csm" || len(args) != 1 || args[0] != Command {
				t.Fatalf("ran %s %q", name, args)
			}
			var out bytes.Buffer
			Handle(bytes.NewReader(body), &out, tr, freeLock)
			return out.Bytes(), nil
		})
	if err != nil || !result.OK || result.Operation != antispam.OpApply || result.Generation != "g2" ||
		len(tr.applied) != 1 || tr.applied[0] != settings {
		t.Fatalf("result=%+v err=%v transactor=%+v", result, err, tr)
	}
}

func TestClipBoundsDiagnostics(t *testing.T) {
	if got := clip("  " + strings.Repeat("x", 2*maxStderr) + "\n"); len(got) != maxStderr {
		t.Fatalf("len = %d", len(got))
	}
}
