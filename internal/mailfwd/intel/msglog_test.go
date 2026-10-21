package intel

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const msglogTestID = "1wVR8E-0000000C9po-1DDg"

// writeMsglog places content at the split (<root>/msglog/<id[5]>/<id>) or
// flat (<root>/msglog/<id>) layout and returns the path.
func writeMsglog(t *testing.T, root, id, content string, split bool) string {
	t.Helper()
	path := msglogTestPath(t, root, id, split)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func msglogTestPath(t *testing.T, root, id string, split bool) string {
	t.Helper()
	dir := filepath.Join(root, "msglog")
	if split {
		dir = filepath.Join(dir, id[5:6])
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, id)
}

// Synthetic msglog tails typed after the shapes Exim writes: a host-level
// line, then the address-level line for the same attempt.
const (
	msglogRateLimited = `2026-10-21 08:14:02 Received from sender@example.com H=(client.example.com) [192.0.2.10]:40512 P=esmtpa A=dovecot_plain:sender@example.com S=4120 id=a1@example.com T="Invoice"
2026-10-21 08:14:05 H=mx1.example.net [203.0.113.20] SMTP error from remote mail server after end of data: 421 4.7.28 Unusual rate of unsolicited mail from 198.51.100.7, deferred
2026-10-21 08:14:05 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx1.example.net [203.0.113.20]: SMTP error from remote mail server after end of data: 421 4.7.28 Unusual rate of unsolicited mail from 198.51.100.7, deferred
`
	msglogMailboxFull = `2026-10-21 08:20:00 H=mx2.example.net [203.0.113.21] SMTP error from remote mail server after RCPT TO:<full@example.net>: 452 4.2.2 The mailbox of this recipient is over quota
2026-10-21 08:20:00 full@example.net R=lookuphost T=remote_smtp defer H=mx2.example.net [203.0.113.21]: SMTP error from remote mail server after RCPT TO:<full@example.net>: 452 4.2.2 The mailbox of this recipient is over quota
`
	msglogSenderRejected = `2026-10-21 09:30:11 H=mx3.example.net [203.0.113.22] SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 450 4.1.8 <sender@example.com>: Sender address rejected: Domain not found
2026-10-21 09:30:11 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx3.example.net [203.0.113.22]: SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 450 4.1.8 <sender@example.com>: Sender address rejected: Domain not found
`
	msglogConnRefused = `2026-10-21 09:40:00 H=mx4.example.net [203.0.113.23]: Connection refused
2026-10-21 09:40:00 rcpt@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx4.example.net [203.0.113.23]: mx4.example.net [203.0.113.23]
`
	msglogNoRoute = `2026-10-21 10:02:44 H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]: No route to host
2026-10-21 10:02:44 rcpt@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]
2026-10-21 10:32:44 H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]: No route to host
2026-10-21 10:32:44 rcpt@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]
`
	msglogLookupFailed = `2026-10-21 10:40:00 rcpt@example.net R=lookuphost defer (-1): host lookup did not complete
`
	msglogGreylisted = `2026-10-21 10:50:00 H=mx6.example.net [203.0.113.25] SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later
2026-10-21 10:50:00 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx6.example.net [203.0.113.25]: SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later
`
	msglogBlocked = `2026-10-21 10:55:00 H=mx7.example.net [203.0.113.26] SMTP error from remote mail server after end of data: 421 4.7.1 Client host [198.51.100.7] blocked using a local list
2026-10-21 10:55:00 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx7.example.net [203.0.113.26]: SMTP error from remote mail server after end of data: 421 4.7.1 Client host [198.51.100.7] blocked using a local list
`
	msglogProviderCode = `2026-10-21 10:58:00 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx7.example.net [203.0.113.26]: SMTP error from remote mail server after end of data: 421 4.7.0 [TSS04] Messages from 198.51.100.7 temporarily deferred due to user complaints
`
	msglogRetryWait = `2026-10-21 11:00:00 rcpt@example.net R=lookuphost T=remote_smtp defer (-53): retry time not reached for any host for 'example.net'
`
	msglogFrozen = `2026-10-21 06:10:00 Received from <> R=1tAbCd-000001-Ab U=mailnull P=local S=2210 T="Mail delivery failed: returning message to sender"
2026-10-21 06:10:01 H=mx8.example.net [203.0.113.27] SMTP error from remote mail server after RCPT TO:<gone@example.net>: 550 5.1.1 <gone@example.net>: Recipient address rejected: User unknown in local recipient table
2026-10-21 06:10:01 gone@example.net R=dkim_lookuphost T=dkim_remote_smtp H=mx8.example.net [203.0.113.27] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes : SMTP error from remote mail server after RCPT TO:<gone@example.net>: 550 5.1.1 <gone@example.net>: Recipient address rejected: User unknown in local recipient table
*** Frozen (delivery error message)
`
	// The subject is sender-controlled; a Received line is never a reason.
	msglogReceivedOnly = `2026-10-21 12:30:00 Received from sender@example.com H=(client.example.com) [192.0.2.11]:51000 P=esmtp S=9000 id=a2@example.com T="rate limit greylisted blocked over quota error defer"
`
	msglogOther = `2026-10-21 13:00:00 H=mx9.example.net [203.0.113.28] SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem
2026-10-21 13:00:00 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx9.example.net [203.0.113.28]: SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem
`
	// Addresses, host names and quoted domains are chosen by senders and
	// recipient domains; words inside them must not pick the class.
	msglogKeywordAddress = `2026-10-21 14:00:00 H=mx6.example.net [203.0.113.25] SMTP error from remote mail server after RCPT TO:<complaints@example.net>: 451 4.7.1 Greylisted, please try again later
2026-10-21 14:00:00 complaints@example.net R=lookuphost T=remote_smtp defer H=mx6.example.net [203.0.113.25]: SMTP error from remote mail server after RCPT TO:<complaints@example.net>: 451 4.7.1 Greylisted, please try again later
`
	msglogKeywordHost = `2026-10-21 14:10:00 H=mx.unlisted.example.net [203.0.113.25]: mx.unlisted.example.net [203.0.113.25]: No route to host
2026-10-21 14:10:00 rcpt@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx.unlisted.example.net [203.0.113.25]: mx.unlisted.example.net [203.0.113.25]
`
	msglogKeywordDomain = `2026-10-21 14:20:00 rcpt@unlisted.example.net R=lookuphost T=remote_smtp defer (-53): retry time not reached for any host for 'unlisted.example.net'
`
	msglogRoutingOther = `2026-10-21 11:30:00 rcpt@example.net R=lookuphost defer (-1): temporary internal problem
`
	// One attempt to two recipients: both address lines come after the
	// host line that explains them.
	msglogTwoRecipients = `2026-10-21 15:00:00 H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]: No route to host
2026-10-21 15:00:00 one@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]
2026-10-21 15:00:00 two@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]
`
	// A delivery to another recipient after the deferral; its address
	// holds the word error.
	msglogDeliveredToError = msglogGreylisted + `2026-10-21 17:00:00 error@example.net R=lookuphost T=remote_smtp H=mx6.example.net [203.0.113.25] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes C="250 2.0.0 Ok: queued"
`
	// One delivery run to two domains in the same second: the newest
	// recipient's own attempt decides, not the other domain's.
	msglogTwoDomains = `2026-10-21 18:00:00 H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]: No route to host
2026-10-21 18:00:00 one@example.net R=dkim_lookuphost T=dkim_remote_smtp defer H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]
2026-10-21 18:00:00 H=mx9.example.com [203.0.113.28] SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem
2026-10-21 18:00:00 two@example.com R=lookuphost T=remote_smtp defer H=mx9.example.com [203.0.113.28]: SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem
`
	// A connect timeout logs the host line well before the address line.
	msglogSlowAttempt = `2026-10-21 16:00:00 H=mx1.example.net [203.0.113.20]: Connection timed out
2026-10-21 16:05:00 rcpt@example.net R=lookuphost T=remote_smtp defer H=mx1.example.net [203.0.113.20]: mx1.example.net [203.0.113.20]
`
)

func TestMsglogReasonClasses(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    StuckReason
	}{
		{"rate limited", msglogRateLimited, StuckReason{
			Class: "rate_limited", Text: "rate limited",
			Raw: "SMTP error from remote mail server after end of data: 421 4.7.28 Unusual rate of unsolicited mail from 198.51.100.7, deferred",
		}},
		{"mailbox full", msglogMailboxFull, StuckReason{
			Class: "mailbox_full", Text: "mailbox full",
			Raw: "SMTP error from remote mail server after RCPT TO:<full@example.net>: 452 4.2.2 The mailbox of this recipient is over quota",
		}},
		{"sender rejected", msglogSenderRejected, StuckReason{
			Class: "refused", Text: "refused by the receiving server",
			Raw: "SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 450 4.1.8 <sender@example.com>: Sender address rejected: Domain not found",
		}},
		{"connection refused", msglogConnRefused, StuckReason{
			Class: "refused", Text: "refused by the receiving server",
			Raw: "H=mx4.example.net [203.0.113.23]: Connection refused",
		}},
		{"no route to host", msglogNoRoute, StuckReason{
			Class: "host_not_found", Text: "receiving server not found or unreachable",
			Raw: "H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]: No route to host",
		}},
		{"host lookup failed", msglogLookupFailed, StuckReason{
			Class: "host_not_found", Text: "receiving server not found or unreachable",
			Raw: "defer (-1): host lookup did not complete",
		}},
		{"greylisted", msglogGreylisted, StuckReason{
			Class: "greylisted", Text: "greylisted",
			Raw: "SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later",
		}},
		{"blocked", msglogBlocked, StuckReason{
			Class: "blocked", Text: "blocked by the receiving server",
			Raw: "SMTP error from remote mail server after end of data: 421 4.7.1 Client host [198.51.100.7] blocked using a local list",
		}},
		{"provider code with complaint text", msglogProviderCode, StuckReason{
			Class: "blocked", Text: "blocked by the receiving server",
			Raw: "SMTP error from remote mail server after end of data: 421 4.7.0 [TSS04] Messages from 198.51.100.7 temporarily deferred due to user complaints",
		}},
		{"retry wait", msglogRetryWait, StuckReason{
			Class: "retry_wait", Text: "retry time not reached",
			Raw: "defer (-53): retry time not reached for any host for 'example.net'",
		}},
		{"frozen", msglogFrozen, StuckReason{
			Class: "frozen", Text: "frozen: delivery error message",
			Raw: "SMTP error from remote mail server after RCPT TO:<gone@example.net>: 550 5.1.1 <gone@example.net>: Recipient address rejected: User unknown in local recipient table",
		}},
		{"received only", msglogReceivedOnly, StuckReason{
			Class: "none", Text: "no delivery attempt logged yet",
		}},
		{"other", msglogOther, StuckReason{
			Class: "other", Text: "other",
			Raw: "SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem",
		}},
		{"newest reason wins", msglogRateLimited + msglogGreylisted, StuckReason{
			Class: "greylisted", Text: "greylisted",
			Raw: "SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later",
		}},
		{"deferred again after thaw", msglogFrozen + msglogGreylisted, StuckReason{
			Class: "greylisted", Text: "greylisted",
			Raw: "SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later",
		}},
		{"unknown error after thaw", msglogFrozen + msglogOther, StuckReason{
			Class: "other", Text: "other",
			Raw: "SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem",
		}},
		{"frozen without reason", "*** Frozen\n", StuckReason{
			Class: "frozen", Text: "frozen",
		}},
		{"keyword in an address", msglogKeywordAddress, StuckReason{
			Class: "greylisted", Text: "greylisted",
			Raw: "SMTP error from remote mail server after RCPT TO:<complaints@example.net>: 451 4.7.1 Greylisted, please try again later",
		}},
		{"keyword in a host name", msglogKeywordHost, StuckReason{
			Class: "host_not_found", Text: "receiving server not found or unreachable",
			Raw: "H=mx.unlisted.example.net [203.0.113.25]: mx.unlisted.example.net [203.0.113.25]: No route to host",
		}},
		{"keyword in a quoted domain", msglogKeywordDomain, StuckReason{
			Class: "retry_wait", Text: "retry time not reached",
			Raw: "defer (-53): retry time not reached for any host for 'unlisted.example.net'",
		}},
		{"older recognized attempt does not explain a newer one", msglogRateLimited + msglogOther, StuckReason{
			Class: "other", Text: "other",
			Raw: "SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem",
		}},
		{"older routing defer does not explain a newer one", msglogLookupFailed + msglogRoutingOther, StuckReason{
			Class: "other", Text: "other",
			Raw: "defer (-1): temporary internal problem",
		}},
		{"two recipients in one attempt", msglogTwoRecipients, StuckReason{
			Class: "host_not_found", Text: "receiving server not found or unreachable",
			Raw: "H=mx5.example.net [203.0.113.24]: mx5.example.net [203.0.113.24]: No route to host",
		}},
		{"two domains in one delivery run", msglogTwoDomains, StuckReason{
			Class: "other", Text: "other",
			Raw: "SMTP error from remote mail server after end of data: 451 4.3.0 Temporary local problem",
		}},
		{"delivery to an address named error", msglogDeliveredToError, StuckReason{
			Class: "greylisted", Text: "greylisted",
			Raw: "SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later",
		}},
		{"host line logged before a slow attempt ends", msglogSlowAttempt, StuckReason{
			Class: "host_not_found", Text: "receiving server not found or unreachable",
			Raw: "H=mx1.example.net [203.0.113.20]: Connection timed out",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeMsglog(t, root, msglogTestID, tc.content, true)

			got, lines, err := ReadMsglogReason(root, msglogTestID)
			if err != nil {
				t.Fatalf("ReadMsglogReason: %v", err)
			}
			if got != tc.want {
				t.Errorf("reason =\n%+v\nwant\n%+v", got, tc.want)
			}
			wantLines := strings.Split(strings.TrimSuffix(tc.content, "\n"), "\n")
			if !reflect.DeepEqual(lines, wantLines) {
				t.Errorf("lines =\n%q\nwant\n%q", lines, wantLines)
			}
		})
	}
}

func TestMsglogReasonBoundedAndNoFollow(t *testing.T) {
	noAttempt := StuckReason{Class: "none", Text: "no delivery attempt logged yet"}

	t.Run("symlink refused", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.WriteFile(target, []byte(msglogRateLimited), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, msglogTestPath(t, root, msglogTestID, true)); err != nil {
			t.Fatal(err)
		}

		got, lines, err := ReadMsglogReason(root, msglogTestID)
		if err == nil {
			t.Fatal("symlinked msglog read without error, want refusal")
		}
		if got != noAttempt || lines != nil {
			t.Errorf("symlink: reason %+v lines %q, want %+v and no lines", got, lines, noAttempt)
		}
	})

	t.Run("directory refused", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(msglogTestPath(t, root, msglogTestID, true), 0o755); err != nil {
			t.Fatal(err)
		}

		got, lines, err := ReadMsglogReason(root, msglogTestID)
		if err == nil {
			t.Fatal("directory msglog read without error, want refusal")
		}
		if got != noAttempt || lines != nil {
			t.Errorf("directory: reason %+v lines %q, want %+v and no lines", got, lines, noAttempt)
		}
	})

	t.Run("fifo refused without blocking", func(t *testing.T) {
		root := t.TempDir()
		if err := syscall.Mkfifo(msglogTestPath(t, root, msglogTestID, true), 0o600); err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)
		go func() {
			_, _, err := ReadMsglogReason(root, msglogTestID)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("fifo msglog read without error, want refusal")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ReadMsglogReason blocked opening a fifo")
		}
	})

	t.Run("50 MB file reads only the tail", func(t *testing.T) {
		root := t.TempDir()
		path := msglogTestPath(t, root, msglogTestID, true)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		// The head says rate limited; only the tail may decide the reason.
		if _, err = f.WriteString(msglogRateLimited); err != nil {
			t.Fatal(err)
		}
		var tail strings.Builder
		tail.WriteString("\n")
		for i := 0; i < 30; i++ {
			fmt.Fprintf(&tail, "2026-10-21 09:%02d:00 H=mx6.example.net [203.0.113.25] SMTP error from remote mail server after RCPT TO:<rcpt@example.net>: 451 4.7.1 Greylisted, please try again later\n", i)
		}
		const size = 50 << 20
		if _, err = f.WriteAt([]byte(tail.String()), size-int64(tail.Len())); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}

		var before int64
		if runtime.GOOS == "linux" {
			before = processReadBytes(t)
		}
		got, lines, err := ReadMsglogReason(root, msglogTestID)
		if runtime.GOOS == "linux" {
			if read := processReadBytes(t) - before; read > 1<<20 {
				t.Errorf("read %d bytes of a 50 MB msglog, want only the tail", read)
			}
		}
		if err != nil {
			t.Fatalf("ReadMsglogReason: %v", err)
		}
		if got.Class != "greylisted" {
			t.Errorf("class = %q, want greylisted from the tail", got.Class)
		}
		if len(lines) != 20 {
			t.Fatalf("lines = %d, want the last 20", len(lines))
		}
		if !strings.HasPrefix(lines[0], "2026-10-21 09:10:00 ") || !strings.HasPrefix(lines[19], "2026-10-21 09:29:00 ") {
			t.Errorf("lines span %q .. %q, want 09:10 .. 09:29", lines[0][:19], lines[19][:19])
		}
	})

	t.Run("missing file", func(t *testing.T) {
		got, lines, err := ReadMsglogReason(t.TempDir(), msglogTestID)
		if err != nil {
			t.Fatalf("missing msglog error = %v, want nil", err)
		}
		if got != noAttempt || lines != nil {
			t.Errorf("missing: reason %+v lines %q, want %+v and no lines", got, lines, noAttempt)
		}
	})

	t.Run("flat layout", func(t *testing.T) {
		root := t.TempDir()
		writeMsglog(t, root, msglogTestID, msglogGreylisted, false)

		got, _, err := ReadMsglogReason(root, msglogTestID)
		if err != nil {
			t.Fatalf("ReadMsglogReason: %v", err)
		}
		if got.Class != "greylisted" {
			t.Errorf("flat layout class = %q, want greylisted", got.Class)
		}
	})

	t.Run("invalid id", func(t *testing.T) {
		// <root>/msglog/../x is where the flat layout would land for "../x".
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "x"), []byte(msglogRateLimited), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"../x", "-qff", "", msglogTestID + " "} {
			got, lines, err := ReadMsglogReason(root, id)
			if err == nil {
				t.Errorf("ReadMsglogReason(%q) error = nil, want invalid id", id)
			}
			if got.Class == "rate_limited" || lines != nil {
				t.Errorf("ReadMsglogReason(%q) read a file: %+v %q", id, got, lines)
			}
		}
	})
}

// processReadBytes returns the bytes this process has read through read
// syscalls so far (rchar in /proc/self/io).
func processReadBytes(t *testing.T) int64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/io")
	if err != nil {
		t.Fatalf("read /proc/self/io: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "rchar: "); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				t.Fatalf("parse rchar %q: %v", v, err)
			}
			return n
		}
	}
	t.Fatal("no rchar line in /proc/self/io")
	return 0
}
