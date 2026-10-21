package intel

import (
	"net"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseDeferralLine feeds attacker-controlled log content (a deferral line
// echoes a remote server's free-text error) through the parser. It must never
// panic and must keep every bounded-field invariant.
func FuzzParseDeferralLine(f *testing.F) {
	for _, seed := range []string{
		yahooTSS04, gmailRate, spamhausBlock,
		deliveryLine, arrivalLine, failureLine,
		"", "==", "a b c == ",
		"2026-13-99 99:99:99 x == a@b.example [not-an-ip]: 999",
		"2026-06-07 10:00:00 m == \x00@\x00.example []: \x00 421",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		d, ok := parseDeferralLine(line)
		if !ok {
			return
		}
		if len(d.Text) > maxTextLen {
			t.Fatalf("Text exceeds bound: %d", len(d.Text))
		}
		if !utf8.ValidString(d.Text) {
			t.Fatalf("Text is not valid UTF-8: %q", d.Text)
		}
		if len(d.Recipient) > maxAddressLen {
			t.Fatalf("Recipient exceeds bound: %d", len(d.Recipient))
		}
		if len(d.Domain) > maxDomainLen {
			t.Fatalf("Domain exceeds bound: %d", len(d.Domain))
		}
		if len(d.RemoteHost) > maxHostLen {
			t.Fatalf("RemoteHost exceeds bound: %d", len(d.RemoteHost))
		}
		if d.OutboundIP != "" && firstIPv4(d.OutboundIP) != d.OutboundIP {
			t.Fatalf("OutboundIP not a valid IPv4: %q", d.OutboundIP)
		}
		if d.RemoteIP != "" && net.ParseIP(d.RemoteIP) == nil {
			t.Fatalf("RemoteIP not a valid IP: %q", d.RemoteIP)
		}
		// A parsed deferral always carries a recipient with a domain.
		if d.Recipient == "" {
			t.Fatal("parsed deferral has empty recipient")
		}
	})
}

// FuzzParseQueue feeds arbitrary `exim -bp`-shaped content (recipient addresses
// are attacker-influenced) through the queue parser. It must never panic and
// must keep its counts internally consistent.
func FuzzParseQueue(f *testing.F) {
	f.Add(eximBpSample)
	f.Add("")
	f.Add(" 1d 1K aaaaaa-bbbbbb-cc <>\n   a@b.example")
	f.Add("garbage\nlines\nonly")
	f.Fuzz(func(t *testing.T, out string) {
		c := ParseQueue(out)
		if c.Bounce+c.Real != c.Total {
			t.Fatalf("bounce(%d)+real(%d) != total(%d)", c.Bounce, c.Real, c.Total)
		}
		if c.Frozen > c.Total {
			t.Fatalf("frozen(%d) > total(%d)", c.Frozen, c.Total)
		}
		if len(c.TopRecipients) > topRecipientLimit {
			t.Fatalf("top recipients exceeds limit: %d", len(c.TopRecipients))
		}
	})
}

// FuzzParseQueueList checks the per-message queue list against the
// composition parser: both read the same headers, so their counts must agree,
// and every listed field stays within its bound.
func FuzzParseQueueList(f *testing.F) {
	f.Add(eximBpListSample)
	f.Add(eximBpSample)
	f.Add(eximBpSampleNewID)
	f.Add("")
	f.Add("garbage\nlines\nonly")
	f.Add(" 1d 1K aaaaaa-bbbbbb-cc <>\n   a@b.example\n   D c@d.example")
	f.Add(" 1d 99999999999999999999T aaaaaa-bbbbbb-cc (u) <s@example.com> *** frozen ***\n   a@b.example")
	f.Fuzz(func(t *testing.T, out string) {
		msgs, err := ParseQueueList([]byte(out))
		comp := ParseQueue(out)
		if err != nil {
			if len(msgs) != 0 || comp.Total != 0 {
				t.Fatalf("error %v with %d listed and %d counted messages", err, len(msgs), comp.Total)
			}
			return
		}
		if len(msgs) != comp.Total {
			t.Fatalf("listed %d messages, composition counted %d", len(msgs), comp.Total)
		}
		frozen, bounce := 0, 0
		for _, m := range msgs {
			if !ValidMessageID(m.ID) {
				t.Fatalf("listed invalid message id %q", m.ID)
			}
			if m.Recipients == nil || len(m.Recipients) > maxQueueRecipients {
				t.Fatalf("recipients = %d (nil %v), want a non-nil list of at most %d", len(m.Recipients), m.Recipients == nil, maxQueueRecipients)
			}
			for _, r := range m.Recipients {
				if len(r) > maxAddressLen || !strings.Contains(r, "@") {
					t.Fatalf("recipient %q is not a bounded address", r)
				}
			}
			if m.Size < 0 || m.Delivered < 0 {
				t.Fatalf("size %d delivered %d, want non-negative", m.Size, m.Delivered)
			}
			if m.Frozen {
				frozen++
			}
			if m.Bounce {
				bounce++
			}
		}
		if frozen != comp.Frozen || bounce != comp.Bounce {
			t.Fatalf("frozen/bounce %d/%d, composition %d/%d", frozen, bounce, comp.Frozen, comp.Bounce)
		}
	})
}

// FuzzMsglogReason feeds attacker-influenced msglog text (remote SMTP replies
// and sender-chosen subjects) through the reason picker.
func FuzzMsglogReason(f *testing.F) {
	for _, seed := range []string{
		msglogRateLimited, msglogNoRoute, msglogFrozen, msglogReceivedOnly,
		msglogOther, msglogRetryWait, "", "*** Frozen", "*** Frozen (",
		"2026-10-21 12:00:00 ", "H=", " defer", "2026-10-21 12:00:00 x defer " + strings.Repeat("\xff", 300),
	} {
		f.Add(seed)
	}
	classes := map[string]bool{
		"rate_limited": true, "mailbox_full": true, "refused": true, "host_not_found": true,
		"greylisted": true, "blocked": true, "retry_wait": true, "frozen": true, "none": true, "other": true,
	}
	f.Fuzz(func(t *testing.T, tail string) {
		r := msglogReason(strings.Split(tail, "\n"))
		if !classes[r.Class] {
			t.Fatalf("class %q is not a documented class", r.Class)
		}
		for name, s := range map[string]string{"text": r.Text, "raw": r.Raw} {
			if len(s) > maxTextLen || !utf8.ValidString(s) {
				t.Fatalf("%s %q is not bounded valid UTF-8", name, s)
			}
		}
		if r.Text == "" {
			t.Fatal("empty reason text")
		}
	})
}
