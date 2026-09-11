package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

func TestDaemonReportsAutoBlockAdmissionQueues(t *testing.T) {
	rows := (&Daemon{}).QueueStatuses()
	for _, name := range []string{"waiting", "active"} {
		q, ok := rows["auto_block."+name]
		if !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 {
			t.Fatalf("auto-block %s missing or not idle: found=%v status=%+v", name, ok, q)
		}
		if name == "active" {
			if q.Capacity != 1 || q.CapacityUnavailable {
				t.Fatalf("actual state slot capacity missing: %+v", q)
			}
		} else if !q.CapacityUnavailable {
			t.Fatalf("invented fixed waiting capacity: %+v", q)
		}
	}
}

func TestDaemonReportsAutoBlockRetryQueues(t *testing.T) {
	rows := (&Daemon{}).QueueStatuses()
	pending, exists := rows["auto_block.pending"]
	if !exists || pending.Capacity != 1000 || pending.CapacityUnavailable {
		t.Fatalf("durable retry capacity missing: found=%v status=%+v", exists, pending)
	}
	candidates, exists := rows["auto_block.candidates"]
	if !exists || !candidates.CapacityUnavailable {
		t.Fatalf("in-cycle candidate queue missing: found=%v status=%+v", exists, candidates)
	}
}

func TestAutoBlockRetryStartupIncludesDisabledFirewall(t *testing.T) {
	dir := t.TempDir()
	cleanupDir := t.TempDir()
	t.Cleanup(func() {
		if err := checks.InitAutoBlockQueueHealth(cleanupDir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "blocked_ips.json")
	data := []byte(`{"pending":[{"ip":"192.0.2.90","reason":"restored retry"}],"cleanup_pending":["192.0.2.91","192.0.2.92","192.0.2.91"]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &config.Config{StatePath: dir}}
	d.startFirewallUsing(firewallStartupOps{})
	row := d.QueueStatuses()["auto_block.pending"]
	if row.Depth != 1 || row.DepthUnavailable || row.InFlight != 0 || row.Status != "ok" {
		t.Fatalf("disabled firewall concealed existing retry: %+v", row)
	}
	cleanup, exists := d.QueueStatuses()["auto_block.cleanup"]
	if !exists || cleanup.Depth != 2 || cleanup.InFlight != 0 || cleanup.DepthUnavailable || !cleanup.CapacityUnavailable || cleanup.Status != "ok" || cleanup.LagBasis != "deferred_checkpoint" {
		t.Fatalf("disabled firewall concealed deferred cleanup: exists=%v status=%+v", exists, cleanup)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(data) != string(after) {
		t.Fatalf("startup mutated retry state: %v", err)
	}
}
