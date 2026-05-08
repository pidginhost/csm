package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

func TestBPFEnforcementActiveRequiresBPFConnectionBackend(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	d := &Daemon{cfg: cfg}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() {
		config.SetActive(prev)
		bpf.SetActive("connection_tracker", bpf.BackendNone)
	})

	bpf.SetActive("connection_tracker", bpf.BackendLegacy)
	if d.BPFEnforcementActive() {
		t.Fatal("legacy runtime backend must not report BPF enforcement active")
	}

	bpf.SetActive("connection_tracker", bpf.BackendBPF)
	if !d.BPFEnforcementActive() {
		t.Fatal("BPF runtime backend with enabled gate should report active")
	}
}
