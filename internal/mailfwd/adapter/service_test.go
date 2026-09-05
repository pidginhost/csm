package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

func mutationBody(t *testing.T, request eximMutation) string {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEximMutationPreservesTransaction(t *testing.T) {
	a, side := testAdapter(t)
	original := eximLocalSkeleton + "# operator setting\n"
	if err := os.WriteFile(a.localConf, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	request := eximMutation{Operation: "apply", Config: policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}, BadIPs: []string{"192.0.2.1"}}
	body := mutationBody(t, request)
	if err := handleEximMutation(strings.NewReader(body), a); err != nil {
		t.Fatal(err)
	}
	status, err := a.Status()
	if err != nil || !status.Installed || side.rebuilds != 1 {
		t.Fatalf("status=%+v error=%v rebuilds=%d", status, err, side.rebuilds)
	}
	if err = handleEximMutation(strings.NewReader(`{"operation":"remove"}`), a); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.localConf)
	if err != nil || string(data) != original || side.rebuilds != 2 {
		t.Fatalf("remove lost operator config: %s %v rebuilds=%d", data, err, side.rebuilds)
	}
	failure := errors.New("rebuild failed")
	calls := 0
	a.rebuild = func() error {
		calls++
		if calls == 1 {
			return failure
		}
		return nil
	}
	if err = handleEximMutation(strings.NewReader(body), a); !errors.Is(err, failure) {
		t.Fatalf("error=%v", err)
	}
	data, err = os.ReadFile(a.localConf)
	if err != nil || string(data) != original || calls != 2 {
		t.Fatalf("rollback failed: %s %v calls=%d", data, err, calls)
	}
}

func TestEximMutationRejectsInvalidRequestsBeforeSideEffects(t *testing.T) {
	cases := []string{
		``, `null`, `{}`, `{"operation":"shell"}`, `{"operation":"remove","path":"/etc/passwd"}`,
		`{"operation":"remove"} {}`, `{"operation":"remove"} junk`,
		`{"operation":"apply","config":{"Enabled":true,"DryRun":true}}`,
		`{"operation":"apply","config":{"Enabled":true}}`,
		`{"operation":"apply","config":{"Enabled":true,"HoldSignals":{"BounceBackscatter":true}},"bad_ips":["192.0.2.1\ncommand"]}`,
		`{"operation":"remove","bad_ips":["192.0.2.1"]}`,
		strings.Repeat(" ", eximMutationLimit+1),
	}
	for i, input := range cases {
		a, side := testAdapter(t)
		if err := handleEximMutation(strings.NewReader(input), a); err == nil {
			t.Errorf("case %d accepted", i)
		}
		entries, err := os.ReadDir(strings.TrimSuffix(a.localConf, "/exim.conf.local"))
		if err != nil || len(entries) != 0 || side.rebuilds != 0 {
			t.Fatalf("case %d had side effects: %+v %v", i, entries, err)
		}
	}
	readErr := errors.New("read failed")
	if err := handleEximMutation(errorReader{readErr}, nil); !errors.Is(err, readErr) {
		t.Fatalf("read error=%v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestEximServiceAdapterDelegatesMutationsOnly(t *testing.T) {
	a, side := testAdapter(t)
	var got []eximMutation
	service := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error { got = append(got, r); return io.ErrClosedPipe }}
	cfg := policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}
	ips := []string{"192.0.2.9"}
	if err := service.Apply(cfg, ips); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := service.Remove(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []eximMutation{{Operation: "apply", Config: cfg, BadIPs: ips}, {Operation: "remove"}}) {
		t.Fatalf("requests=%+v", got)
	}
	if err := service.RefreshBadIPs(ips); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.badIPsPath)
	if err != nil || string(data) != "192.0.2.9: 1\n" {
		t.Fatalf("lookup=%s %v", data, err)
	}
	status, err := service.Status()
	if err != nil || status.Installed || side.rebuilds != 0 || len(got) != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestEximServiceUsesFixedBoundedTransientCommand(t *testing.T) {
	failure := errors.New("worker failed")
	var calls [][]string
	err := executeEximMutation(context.Background(), "/opt/csm/csm", func(string) (string, error) { return "/usr/bin/systemd-run", nil }, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 2 {
			return []byte("rollback complete"), failure
		}
		return nil, nil
	})
	want := [][]string{
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/bin/true"},
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/opt/csm/csm", "forward-guard-worker"},
	}
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "rollback complete") || !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%q error=%v", calls, err)
	}
}
