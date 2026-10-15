package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

func TestActionShowCLI(t *testing.T) {
	const id = "cand_11111111111111111111111111111111"
	t.Cleanup(fakeDaemon(t, func(req control.Request) control.Response {
		var args control.ActionShowArgs
		if err := json.Unmarshal(req.Args, &args); err != nil || req.Cmd != control.CmdActionShow || args.ID != id {
			t.Errorf("request = %+v, args = %+v, error = %v", req, args, err)
		}
		return control.Response{OK: true, Result: json.RawMessage(`{"candidate_id":"` + id + `","attempts":[]}`)}
	}))
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	args, stdout := os.Args, os.Stdout
	t.Cleanup(func() { os.Args, os.Stdout = args, stdout })
	os.Args, os.Stdout = []string{"csm", "action", "show", id}, out
	runAction()
	os.Args, os.Stdout = args, stdout
	if _, err = out.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var view struct {
		Candidate string `json:"candidate_id"`
		Attempts  []any  `json:"attempts"`
	}
	if err = json.NewDecoder(out).Decode(&view); err != nil || view.Candidate != id || view.Attempts == nil || len(view.Attempts) != 0 {
		t.Fatalf("CLI JSON = %+v, %v", view, err)
	}
}

func TestActionShowCLIUsage(t *testing.T) {
	if mode := os.Getenv("CSM_TEST_ACTION_USAGE"); mode != "" {
		os.Args = []string{"csm", "action"}
		if mode == "mutation" {
			os.Args = append(os.Args, "resolve", "cand_11111111111111111111111111111111")
		}
		runAction()
		return
	}
	for _, mode := range []string{"missing", "mutation"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestActionShowCLIUsage$")
		cmd.Env = append(os.Environ(), "CSM_TEST_ACTION_USAGE="+mode)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "usage: csm action show") {
			t.Fatalf("%s: expected usage failure, got %v: %s", mode, err, out)
		}
	}
}
