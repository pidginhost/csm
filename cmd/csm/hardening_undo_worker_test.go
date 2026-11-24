package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func TestHardeningUndoWorkerRefusesBeforeReading(t *testing.T) {
	for name, tc := range map[string]struct {
		euid int
		args []string
	}{
		"not root":            {1000, []string{"hardening-undo-worker"}},
		"no command":          {0, nil},
		"apply command":       {0, []string{"hardening-apply-worker"}},
		"extra argument":      {0, []string{"hardening-undo-worker", "--force"}},
		"empty config":        {0, []string{"hardening-undo-worker", "--config", ""}},
		"wrong flag":          {0, []string{"hardening-undo-worker", "--conf", "/etc/csm/csm.yaml"}},
		"relative config dir": {0, []string{"hardening-undo-worker", "--config", "/etc/csm/csm.yaml", "--config-dir", "conf.d"}},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			calls := 0
			code := hardeningUndoWorker(tc.euid, tc.args, strings.NewReader(`{"name":"ssh_use_dns"}`), &out, &errOut,
				func(string) checks.HardeningFixResult { calls++; return checks.HardeningFixResult{} })
			if code != 1 || calls != 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "requires root") {
				t.Errorf("code=%d calls=%d out=%q err=%q", code, calls, out.String(), errOut.String())
			}
		})
	}
}

func TestHardeningUndoWorkerWritesResult(t *testing.T) {
	for _, args := range [][]string{
		{"hardening-undo-worker"},
		{"hardening-undo-worker", "--config", "/etc/csm/csm.yaml"},
		{"hardening-undo-worker", "--config", "/etc/csm/csm.yaml", "--config-dir", "/etc/custom/conf.d"},
	} {
		var out, errOut bytes.Buffer
		code := hardeningUndoWorker(0, args, strings.NewReader(`{"name":"ssh_use_dns"}`), &out, &errOut,
			func(name string) checks.HardeningFixResult {
				return checks.HardeningFixResult{Name: name, Title: name, Status: "undone"}
			})
		if code != 0 || !strings.Contains(out.String(), `"name":"ssh_use_dns"`) || !strings.Contains(out.String(), `"status":"undone"`) || errOut.Len() != 0 {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestHardeningUndoWorkerRefusesBadRequest(t *testing.T) {
	var out, errOut bytes.Buffer
	calls := 0
	code := hardeningUndoWorker(0, []string{"hardening-undo-worker"}, strings.NewReader(`{"name":"ssh_port"}`), &out, &errOut,
		func(string) checks.HardeningFixResult { calls++; return checks.HardeningFixResult{} })
	if code != 1 || calls != 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "unknown hardening fix") {
		t.Errorf("code=%d calls=%d out=%q err=%q", code, calls, out.String(), errOut.String())
	}
}
