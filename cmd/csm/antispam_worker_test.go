package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

type countingTransactor struct{ calls int }

func (c *countingTransactor) Apply(antispam.Settings) antispam.Result {
	c.calls++
	return antispam.Result{OK: true, Generation: strings.Repeat("0", 64)}
}

func (c *countingTransactor) Remove() antispam.Result {
	c.calls++
	return antispam.Result{OK: true}
}

func unlocked(mutate func() error) error { return mutate() }

func TestAntispamWorkerRefusesBeforeReading(t *testing.T) {
	for name, tc := range map[string]struct {
		euid int
		args []string
	}{
		"not root":       {1000, []string{"antispam-worker"}},
		"extra argument": {0, []string{"antispam-worker", "--force"}},
	} {
		var out, errOut bytes.Buffer
		tr := &countingTransactor{}
		code := antispamWorker(tc.euid, tc.args, strings.NewReader(`{"operation":"remove"}`), &out, &errOut, tr, unlocked)
		if code != 1 || out.Len() != 0 || tr.calls != 0 || !strings.Contains(errOut.String(), "requires root") {
			t.Errorf("%s: code=%d out=%q err=%q calls=%d", name, code, out.String(), errOut.String(), tr.calls)
		}
	}
}

func TestAntispamWorkerRunsOneRequest(t *testing.T) {
	var out, errOut bytes.Buffer
	tr := &countingTransactor{}
	code := antispamWorker(0, []string{"antispam-worker"}, strings.NewReader(`{"operation":"remove"}`), &out, &errOut, tr, unlocked)
	result, err := antispam.ParseResult(out.Bytes())
	if code != 0 || err != nil || !result.OK || result.Operation != antispam.OpRemove || tr.calls != 1 || errOut.Len() != 0 {
		t.Errorf("code=%d result=%+v err=%v calls=%d stderr=%q", code, result, err, tr.calls, errOut.String())
	}
}
