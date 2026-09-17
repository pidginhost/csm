//go:build linux && bpf

package daemon

import (
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	afalg "github.com/pidginhost/csm/internal/daemon/af_alg_bpfprog"
	connection "github.com/pidginhost/csm/internal/daemon/connection_bpfprog"
	execution "github.com/pidginhost/csm/internal/daemon/exec_bpfprog"
	sensitive "github.com/pidginhost/csm/internal/daemon/sensitive_file_bpfprog"
)

func TestBPFProgramsCarryKernelLossCounters(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{"af_alg", afalg.LoadAFAlg},
		{"connection", connection.LoadConnection},
		{"execution", execution.LoadExec},
		{"sensitive_files", sensitive.LoadSensitiveFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			native, err := tc.load()
			if err != nil {
				t.Fatal(err)
			}
			specs := []*ebpf.CollectionSpec{native}
			dir := tc.name
			if dir == "execution" {
				dir = "exec"
			}
			if dir == "sensitive_files" {
				dir = "sensitive_file"
			}
			objects, err := filepath.Glob(filepath.Join(dir+"_bpfprog", "*_bpfel.o"))
			if err != nil || len(objects) != 2 {
				t.Fatalf("architecture objects=%v err=%v", objects, err)
			}
			for _, path := range objects {
				spec, err := ebpf.LoadCollectionSpec(path)
				if err != nil {
					t.Fatal(err)
				}
				specs = append(specs, spec)
			}
			for _, spec := range specs {
				counters := spec.Maps["queue_stats"]
				if counters == nil {
					t.Fatal("shipped BPF object cannot report kernel reservation loss")
				}
				if counters.Type != ebpf.Array || counters.KeySize != 4 || counters.ValueSize != 16 || counters.MaxEntries != 1 {
					t.Fatalf("kernel counters do not match the userspace wire contract: %+v", counters)
				}
				for name, program := range spec.Programs {
					referenced := false
					for _, insn := range program.Instructions {
						referenced = referenced || insn.Reference() == "queue_stats"
					}
					if !referenced {
						t.Errorf("%s has no kernel loss accounting instructions", name)
					}
				}
			}
		})
	}
}
