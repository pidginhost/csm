package inventory

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// fakeUAPI records the uapi command a remover runs through systemd-run and
// answers it with reply and err. The availability probe always succeeds.
type fakeUAPI struct {
	calls [][]string
	reply string
	err   error
}

func (f *fakeUAPI) lookPath(string) (string, error) { return "/usr/bin/systemd-run", nil }

func (f *fakeUAPI) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if slices.Contains(args, "/bin/true") {
		return nil, nil
	}
	f.calls = append(f.calls, append([]string{name}, args...))
	return []byte(f.reply), f.err
}

var shopForwarder = Forwarder{Source: "sales@shop.example", Domain: "shop.example", Owner: "shopuser"}

func TestCPanelRemoverRunsUAPIAsTheOwner(t *testing.T) {
	f := &fakeUAPI{reply: `{"result":{"status":1,"errors":null}}`}
	if err := NewCPanelRemover(f.lookPath, f.run).Remove(shopForwarder, "boss@example.net"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("calls = %v, want one uapi run", f.calls)
	}
	call := f.calls[0]
	if call[0] != "/usr/bin/systemd-run" {
		t.Errorf("ran %q, want uapi outside the sandbox through systemd-run", call[0])
	}
	want := []string{"/usr/local/cpanel/bin/uapi", "--output=json", "--user=shopuser", "Email", "delete_forwarder",
		"address=sales%40shop.example", "forwarder=boss%40example.net"}
	if len(call) < len(want) || !slices.Equal(call[len(call)-len(want):], want) {
		t.Errorf("argv = %v, want it to end with %v", call, want)
	}
}

// uapi URI-decodes its command-line values, so a plus or a percent sign in
// an address would reach cPanel as something else.
func TestCPanelRemoverEncodesValuesForUAPI(t *testing.T) {
	f := &fakeUAPI{reply: `{"result":{"status":1,"errors":null}}`}
	fwd := Forwarder{Source: "a+b@shop.example", Owner: "shopuser"}
	if err := NewCPanelRemover(f.lookPath, f.run).Remove(fwd, "x%41 y@example.net"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	call := f.calls[0]
	for _, want := range []string{"address=a%2Bb%40shop.example", "forwarder=x%2541%20y%40example.net"} {
		if !slices.Contains(call, want) {
			t.Errorf("argv %v lacks %q", call, want)
		}
	}
}

func TestCPanelRemoverReportsUAPIErrors(t *testing.T) {
	f := &fakeUAPI{reply: `{"result":{"status":0,"errors":["No such forwarder"]}}`, err: errors.New("exit status 1")}
	err := NewCPanelRemover(f.lookPath, f.run).Remove(shopForwarder, "boss@example.net")
	if err == nil || !strings.Contains(err.Error(), "No such forwarder") {
		t.Fatalf("err = %v, want cPanel's own error", err)
	}
}

func TestCPanelRemoverReportsUnreadableReplies(t *testing.T) {
	f := &fakeUAPI{reply: "Can't locate Cpanel/API.pm", err: errors.New("exit status 2")}
	err := NewCPanelRemover(f.lookPath, f.run).Remove(shopForwarder, "boss@example.net")
	if err == nil || !strings.Contains(err.Error(), "exit status 2") || !strings.Contains(err.Error(), "Can't locate") {
		t.Fatalf("err = %v, want the exit status and what uapi printed", err)
	}
}

// Inside the daemon sandbox uapi could rewrite the alias file and then fail
// on cPanel's caches, so it never runs there.
func TestCPanelRemoverRefusesWithoutSystemdRun(t *testing.T) {
	f := &fakeUAPI{}
	lookPath := func(string) (string, error) { return "", exec.ErrNotFound }
	err := NewCPanelRemover(lookPath, f.run).Remove(shopForwarder, "boss@example.net")
	if !errors.Is(err, systemdrun.ErrUnavailable) {
		t.Fatalf("err = %v, want systemdrun.ErrUnavailable", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("uapi ran %v without systemd-run", f.calls)
	}
}
