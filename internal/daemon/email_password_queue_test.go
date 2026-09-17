package daemon

import "testing"

func TestDaemonReportsEmailPasswordQueues(t *testing.T) {
	d := &Daemon{}
	rows := d.QueueStatuses()
	mailboxes, ok := rows["email_password.mailboxes"]
	if !ok || !mailboxes.CapacityUnavailable || mailboxes.Depth != 0 || mailboxes.InFlight != 0 || mailboxes.DroppedTotal != 0 || mailboxes.Status != "ok" {
		t.Fatalf("idle mailbox audit queue = %+v present=%v", mailboxes, ok)
	}
	hashes, ok := rows["email_password.hashes"]
	if !ok || hashes.Capacity != 3 || hashes.Depth != 0 || hashes.InFlight != 0 || hashes.DroppedTotal != 0 || hashes.Status != "ok" {
		t.Fatalf("idle password hash queue = %+v present=%v", hashes, ok)
	}
	waiting, ok := rows["email_password.waiting"]
	if !ok || !waiting.CapacityUnavailable || waiting.Capacity != 0 || waiting.Depth != 0 || waiting.InFlight != 0 || waiting.DroppedTotal != 0 || waiting.Status != "ok" {
		t.Fatalf("idle password admission queue = %+v present=%v", waiting, ok)
	}
}
