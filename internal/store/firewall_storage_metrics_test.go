package store

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
)

func storageMetric(t testing.TB, name string) float64 {
	t.Helper()
	var out bytes.Buffer
	if err := metrics.WriteOpenMetrics(&out); err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(out.String(), "\n") {
		if strings.HasPrefix(line, name+" ") {
			value, err := strconv.ParseFloat(strings.TrimPrefix(line, name+" "), 64)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	t.Fatalf("missing storage metric %s", name)
	return 0
}

func TestFirewallStorageMetricsSeparateWriterWait(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	waitBefore := storageMetric(t, "csm_storage_firewall_write_wait_seconds_sum")
	txBefore := storageMetric(t, "csm_storage_firewall_write_transaction_seconds_count")
	rowsBefore := storageMetric(t, "csm_storage_firewall_batch_rows_sum")
	holder, err := db.bolt.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Rollback() })
	done := make(chan error, 1)
	go func() { _, err := s.ReplaceFirewallState(1, completeFirewallState()); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for storageMetric(t, "csm_storage_firewall_pending_writes") != 1 {
		if time.Now().After(deadline) {
			t.Fatal("writer did not become pending")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	if got := storageMetric(t, "csm_storage_firewall_write_transaction_seconds_count"); got != txBefore {
		t.Fatal("lock wait counted as completed transaction")
	}
	if err := holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := storageMetric(t, "csm_storage_firewall_write_wait_seconds_sum") - waitBefore; got < .03 {
		t.Fatalf("write wait = %f", got)
	}
	if got := storageMetric(t, "csm_storage_firewall_write_transaction_seconds_count") - txBefore; got != 1 {
		t.Fatalf("transactions = %f", got)
	}
	if got := storageMetric(t, "csm_storage_firewall_pending_writes"); got != 0 {
		t.Fatalf("pending = %f", got)
	}
	if got := storageMetric(t, "csm_storage_firewall_batch_rows_sum") - rowsBefore; got != 7 {
		t.Fatalf("batch rows = %f", got)
	}
	readBefore := storageMetric(t, "csm_storage_firewall_read_seconds_count")
	assertFirewallSnapshot(t, s, completeFirewallState(), 2)
	if got := storageMetric(t, "csm_storage_firewall_read_seconds_count") - readBefore; got != 1 {
		t.Fatalf("reads = %f", got)
	}
	failures := storageMetric(t, "csm_storage_firewall_write_failures_total")
	conflicts := storageMetric(t, "csm_storage_firewall_conflicts_total")
	commitFailures := storageMetric(t, "csm_storage_firewall_commit_failures_total")
	if _, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); err == nil {
		t.Fatal("expected stale write")
	}
	if got := storageMetric(t, "csm_storage_firewall_conflicts_total") - conflicts; got != 1 {
		t.Fatalf("conflicts = %f", got)
	}
	if got := storageMetric(t, "csm_storage_firewall_write_failures_total") - failures; got != 1 {
		t.Fatalf("write failures = %f", got)
	}
	if got := storageMetric(t, "csm_storage_firewall_commit_failures_total") - commitFailures; got != 0 {
		t.Fatal("revision refusal counted as failed commit")
	}
}
