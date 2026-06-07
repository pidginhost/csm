package quarantine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleBody() []byte {
	return []byte("Subject: cheap watches\r\nFrom: spammer@bad.example\r\n\r\nbuy now\r\n")
}

func held() HeldMessage {
	return HeldMessage{
		Forwarder: "sales@shop.example",
		Recipient: "owner@yahoo.com",
		Sender:    "", // null-sender bounce
		Reasons:   []string{"bounce_backscatter"},
	}
}

func TestHoldThenListParsesMetadata(t *testing.T) {
	q := New(t.TempDir())
	id, err := q.Hold(held(), sampleBody())
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := q.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("list len = %d, want 1", len(msgs))
	}
	m := msgs[0]
	if m.ID != id {
		t.Errorf("id = %q, want %q", m.ID, id)
	}
	if m.Forwarder != "sales@shop.example" || m.Recipient != "owner@yahoo.com" {
		t.Errorf("metadata = %+v", m)
	}
	if m.Sender != "" {
		t.Errorf("sender = %q, want empty (null-sender)", m.Sender)
	}
	if len(m.Reasons) != 1 || m.Reasons[0] != "bounce_backscatter" {
		t.Errorf("reasons = %v", m.Reasons)
	}
	if m.Size == 0 || m.HeldAt.IsZero() {
		t.Errorf("size/held_at unset: %+v", m)
	}
}

func TestReleaseReinjectsCleanedMessageAndRemoves(t *testing.T) {
	q := New(t.TempDir())
	var gotSender, gotRcpt string
	var gotBody []byte
	q.sendmail = func(sender, recipient string, body []byte) error {
		gotSender, gotRcpt, gotBody = sender, recipient, body
		return nil
	}
	m := held()
	m.Sender = "real@shop.example"
	id, err := q.Hold(m, sampleBody())
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Release(id); err != nil {
		t.Fatalf("release: %v", err)
	}
	if gotSender != "real@shop.example" || gotRcpt != "owner@yahoo.com" {
		t.Errorf("reinject envelope = -f %q %q", gotSender, gotRcpt)
	}
	// The internal X-CSM-* control headers must NOT be re-injected to the recipient.
	if strings.Contains(string(gotBody), "X-CSM-") {
		t.Errorf("re-injected body still carries X-CSM headers:\n%s", gotBody)
	}
	if !strings.Contains(string(gotBody), "buy now") {
		t.Errorf("re-injected body lost the original content:\n%s", gotBody)
	}
	if msgs, _ := q.List(); len(msgs) != 0 {
		t.Errorf("message still present after release: %d", len(msgs))
	}
}

func TestReleaseDoesNotRemoveOnSendmailFailure(t *testing.T) {
	q := New(t.TempDir())
	q.sendmail = func(sender, recipient string, body []byte) error {
		return errInjectTest
	}
	id, err := q.Hold(held(), sampleBody())
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Release(id); err == nil {
		t.Fatal("expected release error when sendmail fails")
	}
	// Message must survive a failed re-injection so it is not lost.
	if msgs, _ := q.List(); len(msgs) != 1 {
		t.Fatalf("message lost after failed release: %d", len(msgs))
	}
}

func TestDeleteRemoves(t *testing.T) {
	q := New(t.TempDir())
	id, err := q.Hold(held(), sampleBody())
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Delete(id); err != nil {
		t.Fatal(err)
	}
	if msgs, _ := q.List(); len(msgs) != 0 {
		t.Errorf("message present after delete: %d", len(msgs))
	}
}

func TestPruneOlderThan(t *testing.T) {
	q := New(t.TempDir())
	oldID, _ := q.Hold(held(), sampleBody())
	freshID, _ := q.Hold(held(), sampleBody())

	// Backdate the old message's file.
	oldPath := q.pathOf(oldID)
	if oldPath == "" {
		t.Fatal("old message path not found")
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatal(err)
	}

	n, err := q.PruneOlderThan(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	msgs, _ := q.List()
	if len(msgs) != 1 || msgs[0].ID != freshID {
		t.Errorf("after prune = %+v, want only fresh %s", msgs, freshID)
	}
}

func TestCountsByForwarder(t *testing.T) {
	q := New(t.TempDir())
	a := held()
	b := held()
	b.Forwarder = "info@corp.example"
	if _, err := q.Hold(a, sampleBody()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Hold(a, sampleBody()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Hold(b, sampleBody()); err != nil {
		t.Fatal(err)
	}
	counts, err := q.CountsByForwarder()
	if err != nil {
		t.Fatal(err)
	}
	if counts["sales@shop.example"] != 2 || counts["info@corp.example"] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestListEmptyWhenNoMaildir(t *testing.T) {
	q := New(filepath.Join(t.TempDir(), "does-not-exist-yet"))
	msgs, err := q.List()
	if err != nil {
		t.Fatalf("List on absent maildir errored: %v", err)
	}
	if msgs == nil {
		t.Error("List must return non-nil empty slice")
	}
}

type injectTestError struct{}

func (injectTestError) Error() string { return "sendmail boom" }

var errInjectTest = injectTestError{}
