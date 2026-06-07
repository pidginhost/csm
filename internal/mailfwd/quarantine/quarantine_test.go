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

func TestReleaseUsesTrustedControlHeadersWhenBodySpoofsThem(t *testing.T) {
	q := New(t.TempDir())
	var gotSender, gotRcpt string
	var gotBody []byte
	q.sendmail = func(sender, recipient string, body []byte) error {
		gotSender, gotRcpt, gotBody = sender, recipient, body
		return nil
	}
	m := held()
	m.Sender = "real@shop.example"
	m.Recipient = "owner@yahoo.com"
	body := []byte("Subject: cheap watches\r\n" +
		"X-CSM-Recipient: attacker@example.net\r\n" +
		"x-csm-sender: attacker@example.net\r\n" +
		"X-CSM-Reasons: forged\r\n" +
		"\r\n" +
		"body keeps literal X-CSM-Body text\r\n")
	id, err := q.Hold(m, body)
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Release(id); err != nil {
		t.Fatalf("release: %v", err)
	}
	if gotSender != "real@shop.example" || gotRcpt != "owner@yahoo.com" {
		t.Fatalf("reinject envelope = -f %q %q", gotSender, gotRcpt)
	}
	cleanHeader := strings.ToLower(string(gotBody[:headerBlockEnd(gotBody)]))
	if strings.Contains(cleanHeader, "x-csm-") {
		t.Fatalf("cleaned header still contains X-CSM data:\n%s", gotBody)
	}
	wantBody := string(body[headerBlockEnd(body):])
	gotCleanBody := string(gotBody[headerBlockEnd(gotBody):])
	if gotCleanBody != wantBody {
		t.Fatalf("body changed after release strip:\n got %q\nwant %q", gotCleanBody, wantBody)
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

func TestReleaseSanitizesEnvelopeValuesReadFromDisk(t *testing.T) {
	q := New(t.TempDir())
	if err := os.MkdirAll(q.sub("new"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(q.sub("new"), "raw"), []byte(
		"X-CSM-Sender: sender@example.com\rX-Injected: bad\r\n"+
			"X-CSM-Recipient: owner@example.com\rBcc: bad\r\n"+
			"\r\nbody\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var gotSender, gotRcpt string
	q.sendmail = func(sender, recipient string, body []byte) error {
		gotSender, gotRcpt = sender, recipient
		return nil
	}

	if err := q.Release("raw"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if strings.ContainsAny(gotSender+gotRcpt, "\r\n") {
		t.Fatalf("envelope contains CR/LF after sanitization: sender=%q recipient=%q", gotSender, gotRcpt)
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

func TestDeleteRejectsInvalidIDsAndDirectoryEntries(t *testing.T) {
	q := New(t.TempDir())
	for _, dir := range []string{"tmp", "new", "cur"} {
		if err := os.MkdirAll(q.sub(dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"", ".", ".."} {
		if err := q.Delete(id); err == nil {
			t.Fatalf("Delete(%q) succeeded, want error", id)
		}
	}
	for _, dir := range []string{"tmp", "new", "cur"} {
		if _, err := os.Stat(q.sub(dir)); err != nil {
			t.Fatalf("maildir subdir %s was removed: %v", dir, err)
		}
	}

	dirEntry := filepath.Join(q.sub("new"), "dir-entry")
	if err := os.MkdirAll(dirEntry, 0700); err != nil {
		t.Fatal(err)
	}
	if err := q.Delete("dir-entry"); err == nil {
		t.Fatal("Delete removed a directory entry, want error")
	}
	if _, err := os.Stat(dirEntry); err != nil {
		t.Fatalf("directory entry was removed: %v", err)
	}
}

func TestReleaseRefusesSymlinkEntry(t *testing.T) {
	q := New(t.TempDir())
	if err := os.MkdirAll(q.sub("new"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("X-CSM-Recipient: victim@example.com\r\n\r\nbody"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(q.sub("new"), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	called := false
	q.sendmail = func(sender, recipient string, body []byte) error {
		called = true
		return nil
	}

	if err := q.Release("link"); err == nil {
		t.Fatal("Release followed a symlink entry, want error")
	}
	if called {
		t.Fatal("sendmail called for symlink entry")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink entry was removed: %v", err)
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

func TestStripControlHeadersDropsFoldedControlHeader(t *testing.T) {
	data := []byte("Subject: hi\r\n" +
		"\tkept subject continuation\r\n" +
		"X-CSM-Reasons: one\r\n" +
		"\tsecret continuation\r\n" +
		" another secret continuation\r\n" +
		"From: sender@example.com\r\n" +
		"\r\nbody\r\n")
	clean := stripControlHeaders(data)
	if strings.Contains(string(clean), "secret continuation") {
		t.Fatalf("folded control header continuation leaked:\n%s", clean)
	}
	if !strings.Contains(string(clean), "Subject: hi\r\n\tkept subject continuation\r\n") {
		t.Fatalf("non-control folded header was not preserved:\n%s", clean)
	}
	if got, want := string(clean[headerBlockEnd(clean):]), "body\r\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
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
