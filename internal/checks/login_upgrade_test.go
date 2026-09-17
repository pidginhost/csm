package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestLoginUpgradePendingSSHBlock(t *testing.T) {
	calls := 0
	cfg := autoBlockQueueFixture(t, func() error { calls++; return nil })
	cfg.AutoResponse.BlockCpanelLogins = false
	if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{
		IP: "192.0.2.140", Reason: "SSH login", Check: "ssh_login_realtime",
		Severity: alert.Critical, QueuedAt: time.Now(),
	}}}); err != nil {
		t.Fatal(err)
	}
	if actions := AutoBlockIPs(cfg, nil); calls != 1 || len(actions) != 1 {
		t.Fatalf("pending SSH block lost across upgrade: calls=%d actions=%+v", calls, actions)
	}
}
