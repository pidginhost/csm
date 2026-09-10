package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestDaemonReportsActualBlockDigestQueue(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.BlockDigest.Enabled = true
	cfg.Alerts.BlockDigest.Interval = "1h"
	cfg.Alerts.BlockDigest.SendOn = "any"
	cfg.Alerts.BlockDigest.MinBlock = 1
	cfg.Alerts.BlockDigest.Channel = "email"
	d := New(cfg, nil, nil, "")
	collector := d.buildBlockDigest(cfg)
	if collector == nil {
		t.Fatal("enabled collector missing")
	}
	// The health API can run before startup assigns the collector field.
	if row, ok := d.QueueStatuses()["block_digest.records"]; !ok || row.Capacity != 5000 || row.Depth != 0 || row.DepthUnit != "records" {
		t.Fatalf("actual constructed collector not registered: found=%v row=%+v", ok, row)
	}
	d.blockDigest = collector
	d.observeBlocks([]alert.Finding{{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: 192.0.2.61 blocked (expires in 24h)", Details: "Reason: fixture customer block", Timestamp: time.Now()}})
	if row := d.QueueStatuses()["block_digest.records"]; row.Depth != 1 || row.DroppedTotal != 0 {
		t.Fatalf("real auto-block observation missing: %+v", row)
	}
	// Explicit delivery to a disabled email channel fails without network I/O.
	collector.Flush()
	rows := d.QueueStatuses()
	if row := rows["block_digest.email"]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 1 || row.DroppedLowerBound || !row.CapacityUnavailable || row.DepthUnit != "notifications" {
		t.Fatalf("actual daemon sink failure missing: %+v", row)
	}
	if _, ok := rows["block_digest.webhook"]; ok {
		t.Fatal("unconfigured webhook owner invented")
	}
	if row := rows["block_digest.records"]; row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 {
		t.Fatalf("delivered buffer ownership remains: %+v", row)
	}
	disabled := New(&config.Config{}, nil, nil, "")
	if disabled.buildBlockDigest(&config.Config{}) != nil {
		t.Fatal("disabled collector created")
	}
	for name := range disabled.QueueStatuses() {
		if strings.HasPrefix(name, "block_digest.") {
			t.Fatalf("disabled feature publishes phantom queue %s", name)
		}
	}
}
