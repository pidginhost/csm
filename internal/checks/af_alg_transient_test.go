package checks

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestAFAlgUnloadUsesBoundedTransientService(t *testing.T) {
	failure := errors.New("module in use")
	var calls [][]string
	withMockCmd(t, &mockCmd{
		lookPath: func(string) (string, error) { return "/usr/bin/systemd-run", nil },
		runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("unbounded command")
			}
			calls = append(calls, append([]string{name}, args...))
			if len(calls) == 2 {
				return nil, failure
			}
			return nil, nil
		},
	})
	err := unloadAFAlgModules()
	want := [][]string{
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=30s", "--", "/bin/true"},
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=30s", "--", "modprobe", "-r", "algif_aead", "af_alg"},
	}
	if !errors.Is(err, failure) || !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%q error=%v", calls, err)
	}
}
