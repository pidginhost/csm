package quarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/systemdrun"
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

type sendmailCall struct {
	name  string
	args  []string
	input []byte
}

// fakeSystemdRun stands in for systemd-run and the units it starts; without
// systemd-run, lookPath finds nothing.
func fakeSystemdRun(q *Quarantine, available bool, calls *[]sendmailCall) {
	q.lookPath = func(file string) (string, error) {
		if file == "systemd-run" && available {
			return "/usr/bin/systemd-run", nil
		}
		return "", exec.ErrNotFound
	}
	q.run = func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, sendmailCall{name, args, input})
		return nil, nil
	}
}

// exim aborts inside csm.service's ProtectSystem=strict sandbox, where it
// cannot open its logs, so a sendmail run there can fail, or queue the copy
// and still report failure. Release runs it as a transient unit, with the
// message on stdin.
func TestReleaseRunsSendmailAsTransientUnit(t *testing.T) {
	q := New(t.TempDir())
	var calls []sendmailCall
	fakeSystemdRun(q, true, &calls)
	m := held()
	m.Sender = "real@shop.example"
	id, err := q.Hold(m, sampleBody())
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Release(id); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(calls) != 2 || calls[0].input != nil {
		t.Fatalf("runs = %+v, want the availability probe, then sendmail", calls)
	}
	want := []string{"--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=30s", "--",
		"/usr/sbin/sendmail", "-i", "-f", "real@shop.example", "--", "owner@yahoo.com"}
	if calls[1].name != "/usr/bin/systemd-run" || !reflect.DeepEqual(calls[1].args, want) {
		t.Errorf("sendmail run = %s %q, want /usr/bin/systemd-run %q", calls[1].name, calls[1].args, want)
	}
	if !bytes.Equal(calls[1].input, sampleBody()) {
		t.Errorf("stdin = %q, want the original message %q", calls[1].input, sampleBody())
	}
	if msgs, _ := q.List(); len(msgs) != 0 {
		t.Errorf("message still held after release: %d", len(msgs))
	}
}

// Without systemd-run the release fails and the copy stays held: sendmail
// never runs inside the sandbox.
func TestReleaseWithoutSystemdRunKeepsTheCopyHeld(t *testing.T) {
	q := New(t.TempDir())
	var calls []sendmailCall
	fakeSystemdRun(q, false, &calls)
	id, err := q.Hold(held(), sampleBody())
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Release(id); !errors.Is(err, systemdrun.ErrUnavailable) {
		t.Errorf("release error = %v, want ErrUnavailable", err)
	}
	if len(calls) != 0 {
		t.Errorf("sendmail ran without systemd-run: %+v", calls)
	}
	if msgs, _ := q.List(); len(msgs) != 1 || msgs[0].ID != id {
		t.Errorf("held = %+v, want the copy still held", msgs)
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

// Release must never reinterpret a recorded mailbox as several recipients or
// as an Exim option. A refusal retains the copy and never invokes sendmail.
func TestReleaseRefusesAmbiguousEnvelope(t *testing.T) {
	for _, field := range []string{hdrSender, hdrRecipient} {
		for _, value := range []string{
			"root,owner@example.net", `"root,x"@example.net`,
			`"two words"@example.net`, "owner@example.net other@example.net",
			"owner@example.net\tother@example.net", "-owner@example.net",
			"Display <owner@example.net>", "<owner@example.net>",
			"owner@example.net(comment)", "localonly", "@example.net",
			"owner@example.net\rBcc: bad", "owner@example.net\x00", `"-flag"@example.net`,
		} {
			t.Run(field+"/"+value, func(t *testing.T) {
				q := New(t.TempDir())
				q.sendmail = func(string, string, []byte) error {
					t.Error("sendmail called for an unsafe envelope")
					return nil
				}
				raw := eximHeld("Subject: test\n")
				old := field + ": real@example.com"
				if field == hdrRecipient {
					old = field + ": owner@example.net"
				}
				writeRawHeld(t, q, "unsafe", strings.Replace(raw, old, field+": "+value, 1))
				if err := q.Release("unsafe"); err == nil {
					t.Error("release accepted an unsafe envelope")
				}
				if q.pathOf("unsafe") == "" {
					t.Error("refused release removed the held copy")
				}
			})
		}
	}
}

func TestReleaseRequiresEnvelopeFields(t *testing.T) {
	for _, field := range []string{hdrSender, hdrRecipient} {
		t.Run(field, func(t *testing.T) {
			q := New(t.TempDir())
			q.sendmail = func(string, string, []byte) error {
				t.Error("sendmail called without a recorded envelope")
				return nil
			}
			raw := eximHeld("Subject: test\n")
			start := strings.Index(raw, field+":")
			end := start + strings.IndexByte(raw[start:], '\n') + 1
			writeRawHeld(t, q, "missing", raw[:start]+raw[end:])
			if err := q.Release("missing"); err == nil || q.pathOf("missing") == "" {
				t.Errorf("release = %v; want refusal and a retained copy", err)
			}
		})
	}
}

func TestReleasePreservesSingleEnvelopeAddress(t *testing.T) {
	for _, sender := range []string{"", "sender@example.com", `"quoted"@example.com`} {
		t.Run(sender, func(t *testing.T) {
			q := New(t.TempDir())
			calls := 0
			q.sendmail = func(gotSender, recipient string, body []byte) error {
				calls++
				if gotSender != sender || recipient != "owner+tag@example.net" || string(body) != "Subject: test\n\nbody\n" {
					t.Errorf("reinjection changed the envelope or content: %q %q %q", gotSender, recipient, body)
				}
				return nil
			}
			id, err := q.Hold(HeldMessage{Sender: sender, Recipient: "owner+tag@example.net"}, []byte("Subject: test\n\nbody\n"))
			if err != nil {
				t.Fatal(err)
			}
			if err := q.Release(id); err != nil || calls != 1 || q.pathOf(id) != "" {
				t.Errorf("release = %v, calls = %d; want one delivery and removal", err, calls)
			}
		})
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

// The held list shows each copy's subject: the first Subject field of the
// message's own header block, unfolded, with RFC 2047 encoded words decoded.
// The subject is the sender's text and the page renders it, so it comes back
// without control, bidi or format characters and cut to maxSubjectLen runes.
// Only the header block is read; the size is still the whole file.
func TestHeldMessageSubject(t *testing.T) {
	filler := "X-Filler: " + strings.Repeat("f", 200) + "\r\n"
	cases := []struct {
		name, header, want string
	}{
		{"plain", "Subject: cheap watches\r\n", "cheap watches"},
		{"encoded words over a fold", "subject: =?UTF-8?B?w45uY8SDIG8=?=\r\n =?UTF-8?Q?_ofert=C4=83?=\r\n", "\u00cenc\u0103 o ofert\u0103"},
		{"latin-1", "Subject: =?ISO-8859-1?Q?caf=E9?= menu\r\n", "caf\u00e9 menu"},
		{"folded plain text", "Subject: part one\r\n\tpart two\r\n", "part one part two"},
		{"control characters", "Subject: =?UTF-8?B?YRtbMzFtYgBjDQpkCWU=?=\r\n", "a [31mb c d e"},
		{"unknown charset kept as sent", "Subject: =?x-unknown?Q?abc?=\r\n", "=?x-unknown?Q?abc?="},
		{"long", "Subject: " + strings.Repeat("\u0103", 300) + "\r\n", strings.Repeat("\u0103", maxSubjectLen)},
		{"continuation is not a field", "X-Note: hi\r\n Subject: spoofed\r\nSubject: real\r\n", "real"},
		{"first field wins", "Subject: first\r\nSubject: second\r\n", "first"},
		{"none", "From: a@example.com\r\n", ""},
		{"bidi and format controls", "Subject: invoice\u202efdp.exe \u2066x\u2069\u200b\u00ad\r\n", "invoicefdp.exe x"},
		{"after 64 KiB of headers", strings.Repeat(filler, (64<<10)/len(filler)+1) + "Subject: late\r\n", "late"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := New(t.TempDir())
			body := []byte(tc.header + "\r\nSubject: in the body\r\n" + strings.Repeat("b", 128<<10))
			if _, err := q.Hold(held(), body); err != nil {
				t.Fatal(err)
			}
			msgs, err := q.List()
			if err != nil || len(msgs) != 1 {
				t.Fatalf("list = %v, %v; want one message", msgs, err)
			}
			if msgs[0].Subject != tc.want {
				t.Errorf("subject = %q, want %q", msgs[0].Subject, tc.want)
			}
			if msgs[0].Forwarder != "sales@shop.example" {
				t.Errorf("control headers lost: %+v", msgs[0])
			}
			if msgs[0].Size <= int64(len(body)) {
				t.Errorf("size = %d, want the whole file (body alone is %d)", msgs[0].Size, len(body))
			}
		})
	}
	raw, err := json.Marshal(HeldMessage{Subject: "s"})
	if err != nil || !strings.Contains(string(raw), `"subject":"s"`) {
		t.Errorf("held message JSON = %s, %v; want a subject field", raw, err)
	}
}

// eximHeld is a held copy in the layout exim's csm_forward_hold transport
// writes: the message's own header fields, then the four control headers it
// appends, then the body.
func eximHeld(ownHeaders string) string {
	return ownHeaders +
		"X-CSM-Forwarder: sales@example.com\n" +
		"X-CSM-Recipient: owner@example.net\n" +
		"X-CSM-Sender: real@example.com\n" +
		"X-CSM-Reasons: bad_sender_ip\n" +
		"\n" +
		"body\n"
}

func writeRawHeld(t *testing.T, q *Quarantine, id, content string) {
	t.Helper()
	if err := os.MkdirAll(q.sub("new"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(q.sub("new"), id), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func wantRealControlHeaders(t *testing.T, m HeldMessage) {
	t.Helper()
	if m.Forwarder != "sales@example.com" || m.Recipient != "owner@example.net" || m.Sender != "real@example.com" ||
		len(m.Reasons) != 1 || m.Reasons[0] != "bad_sender_ip" {
		t.Errorf("listed control headers = %+v, want the ones exim appended", m)
	}
}

// Exim appends the control headers after the message's own headers, which
// may be up to header_maxsize (1 MiB) long. List must reach them.
func TestListReadsControlHeadersAfterLargeMessageHeaders(t *testing.T) {
	q := New(t.TempDir())
	own := "Subject: big\n" + strings.Repeat("X-Filler: "+strings.Repeat("f", 500)+"\n", 200)
	if len(own) <= 64<<10 {
		t.Fatalf("fixture headers are only %d bytes", len(own))
	}
	writeRawHeld(t, q, "big", eximHeld(own))

	msgs, err := q.List()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("list = %v, %v; want one message", msgs, err)
	}
	wantRealControlHeaders(t, msgs[0])
	if msgs[0].Subject != "big" {
		t.Errorf("subject = %q, want big", msgs[0].Subject)
	}
}

// A header block longer than the read bound cannot come from exim and may
// end before the appended control headers, leaving only copies the message
// carried. It is neither listed nor released.
func TestOversizedHeaderBlockIsNotListedOrReleased(t *testing.T) {
	q := New(t.TempDir())
	q.sendmail = func(string, string, []byte) error {
		t.Error("sendmail called for an oversized header block")
		return nil
	}
	own := "X-CSM-Recipient: attacker@example.net\n" + strings.Repeat("X-Filler: "+strings.Repeat("f", 1000)+"\n", maxHeaderBlock/1000+1)
	writeRawHeld(t, q, "huge", eximHeld(own))

	if msgs, err := q.List(); err != nil || len(msgs) != 0 {
		t.Errorf("list = %+v, %v; want the oversized copy left out", msgs, err)
	}
	if err := q.Release("huge"); err == nil {
		t.Error("release of an oversized header block succeeded")
	}
	if q.pathOf("huge") == "" {
		t.Error("refused release removed the held copy")
	}
}

// A message may carry its own X-CSM-* fields. Exim appends the real ones
// last, so the last occurrence is the one CSM recorded: List shows it and
// Release delivers only to it.
func TestForgedControlHeadersLose(t *testing.T) {
	q := New(t.TempDir())
	own := "Subject: hi\n" +
		"X-CSM-Recipient: attacker@example.net\n" +
		"x-csm-sender: attacker@example.net\n" +
		"X-CSM-Forwarder: attacker@example.net\n" +
		"X-CSM-Reasons: forged\n" +
		"From: a@example.com\n"
	writeRawHeld(t, q, "forged", eximHeld(own))

	msgs, err := q.List()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("list = %v, %v; want one message", msgs, err)
	}
	wantRealControlHeaders(t, msgs[0])

	var gotSender, gotRcpt string
	var gotBody []byte
	q.sendmail = func(sender, recipient string, body []byte) error {
		gotSender, gotRcpt, gotBody = sender, recipient, body
		return nil
	}
	if err := q.Release("forged"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if gotSender != "real@example.com" || gotRcpt != "owner@example.net" {
		t.Errorf("reinject envelope = -f %q %q, want the recorded sender and recipient", gotSender, gotRcpt)
	}
	if strings.Contains(strings.ToLower(string(gotBody)), "x-csm-") || !strings.Contains(string(gotBody), "From: a@example.com") {
		t.Errorf("re-injected message = %q, want the own headers without any X-CSM field", gotBody)
	}
}

// Hold writes the layout exim writes: control headers after the message's
// own headers, so the forged copies a message carries come first and lose.
func TestHoldAppendsControlHeadersAfterOwnHeaders(t *testing.T) {
	for _, tc := range []struct{ name, body, wantPrefix, wantRest string }{
		{"crlf message", "Subject: hi\r\nX-CSM-Recipient: attacker@example.net\r\n\r\nbody\r\n", "Subject: hi\r\nX-CSM-Recipient: attacker@example.net\r\n", "\r\nbody\r\n"},
		{"lf message", "Subject: hi\nX-CSM-Recipient: attacker@example.net\n\nbody\n", "Subject: hi\nX-CSM-Recipient: attacker@example.net\n", "\nbody\n"},
		{"no body", "Subject: hi\nX-CSM-Recipient: attacker@example.net", "Subject: hi\nX-CSM-Recipient: attacker@example.net\r\n", ""},
		{"no headers", "\r\nbody\r\n", "", "\r\nbody\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := New(t.TempDir())
			m := held()
			m.Sender = "real@shop.example"
			id, err := q.Hold(m, []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(q.pathOf(id))
			if err != nil {
				t.Fatal(err)
			}
			control := "X-CSM-Forwarder: sales@shop.example\r\nX-CSM-Recipient: owner@yahoo.com\r\nX-CSM-Sender: real@shop.example\r\nX-CSM-Reasons: bounce_backscatter\r\n"
			if want := tc.wantPrefix + control + tc.wantRest; string(raw) != want {
				t.Fatalf("held file = %q, want %q", raw, want)
			}
			msgs, err := q.List()
			if err != nil || len(msgs) != 1 || msgs[0].Recipient != "owner@yahoo.com" || msgs[0].Sender != "real@shop.example" {
				t.Errorf("list = %+v, %v; want the recorded recipient and sender", msgs, err)
			}
		})
	}
}
