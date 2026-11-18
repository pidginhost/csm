package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func TestHardeningApplyWorkerRefusesBeforeReading(t *testing.T) {
	for name, tc := range map[string]struct {
		euid int
		args []string
	}{
		"not root":       {1000, []string{"hardening-apply-worker"}},
		"no command":     {0, nil},
		"extra argument": {0, []string{"hardening-apply-worker", "--force"}},
		"empty config":   {0, []string{"hardening-apply-worker", "--config", ""}},
		"wrong flag":     {0, []string{"hardening-apply-worker", "--conf", "/etc/csm/csm.yaml"}},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			calls := 0
			code := hardeningApplyWorker(tc.euid, tc.args, strings.NewReader(`{"category":"ssh"}`), &out, &errOut,
				func(string, []string) ([]checks.HardeningFixResult, error) { calls++; return nil, nil })
			if code != 1 || calls != 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "requires root") {
				t.Errorf("code=%d calls=%d out=%q err=%q", code, calls, out.String(), errOut.String())
			}
		})
	}
}

func TestHardeningApplyWorkerWritesResults(t *testing.T) {
	for _, args := range [][]string{
		{"hardening-apply-worker"},
		{"hardening-apply-worker", "--config", "/etc/csm/csm.yaml"},
	} {
		var out, errOut bytes.Buffer
		code := hardeningApplyWorker(0, args, strings.NewReader(`{"category":"ssh","names":["ssh_use_dns"]}`), &out, &errOut,
			func(cat string, names []string) ([]checks.HardeningFixResult, error) {
				return []checks.HardeningFixResult{{Name: names[0], Status: "applied"}}, nil
			})
		if code != 0 || !strings.Contains(out.String(), `"status":"applied"`) || errOut.Len() != 0 {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestHardeningApplyWorkerReportsFailure(t *testing.T) {
	var out, errOut bytes.Buffer
	code := hardeningApplyWorker(0, []string{"hardening-apply-worker"}, strings.NewReader(`{"category":"ssh"}`), &out, &errOut,
		func(string, []string) ([]checks.HardeningFixResult, error) {
			return nil, errors.New("loading config: boom")
		})
	if code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), "loading config: boom") {
		t.Errorf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}
