package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The PAM listener read infra_ips from the startup snapshot while its
// thresholds came from the live config, so an infrastructure address added
// by reload kept accumulating failures until a restart.
func TestPAMListenerInfraIPsFollowLiveConfig(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })

	startup := &config.Config{}
	startup.Thresholds.PAMBruteforceThreshold = 100
	active := &config.Config{InfraIPs: []string{"203.0.113.90"}}
	active.Thresholds.PAMBruteforceThreshold = 100
	config.SetActive(active)

	p := &PAMListener{
		cfg:             startup,
		alertCh:         make(chan alert.Finding, 8),
		failures:        make(map[string]*pamFailureTracker),
		useActiveConfig: true,
	}
	p.processEvent("FAIL ip=203.0.113.90 user=alice service=sshd")
	if _, tracked := p.failures["203.0.113.90"]; tracked {
		t.Fatal("failure recorded for an address the live config lists as infrastructure")
	}
}
