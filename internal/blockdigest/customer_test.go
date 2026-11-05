package blockdigest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var customerLoginAt = time.Date(2026, 6, 10, 8, 15, 0, 0, time.UTC)

func subnetCustomerHits(n int) []CustomerHit {
	hits := make([]CustomerHit, 0, n)
	for i := range n {
		hits = append(hits, CustomerHit{IP: fmt.Sprintf("198.51.100.%d", i+1), Kind: "webmail", Account: fmt.Sprintf("user%d@example.com", i+1), At: customerLoginAt})
	}
	return hits
}

// One call is one email and one webhook naming every block, sent without
// Watch and on both channels whatever block_digest.channel selects.
func TestCustomerBlockAlertSendsOneNotification(t *testing.T) {
	var capture summaryCapture
	c := summaryCollector(Options{LiveChannel: "webhook", EmailSink: capture.email, WebhookSink: capture.webhook})
	c.AlertCustomerBlocks([]CustomerBlock{
		{Target: "203.0.113.5", Reason: "SMTP brute force from 203.0.113.5", Check: "smtp_bruteforce",
			Hits: []CustomerHit{{IP: "203.0.113.5", Kind: "cpanel", Account: "alice", At: customerLoginAt}}},
		{Target: "198.51.100.0/24", Reason: "AUTO-NETBLOCK: 198.51.100.0/24 blocked (5 IPs from same subnet)",
			Hits: subnetCustomerHits(5), More: 195},
	})

	mails := capture.sent()
	if len(mails) != 1 {
		t.Fatalf("emails = %d, want 1", len(mails))
	}
	if want := "[CSM] host.example.com - 2 automatic blocks hit known customers"; mails[0].subject != want {
		t.Fatalf("subject = %q, want %q", mails[0].subject, want)
	}
	body := mails[0].body
	for _, want := range []string{
		"Block: 203.0.113.5\n",
		"Reason: SMTP brute force from 203.0.113.5",
		"Check: smtp_bruteforce",
		"Known customer: 203.0.113.5 cpanel login as alice at 2026-06-10 08:15 UTC",
		"Block: 198.51.100.0/24\n",
		"200 known customers, the latest 5:",
		"198.51.100.1 webmail login as user1@example.com at 2026-06-10 08:15 UTC",
		"and 195 more",
		"csm firewall remove",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body has no %q:\n%s", want, body)
		}
	}
	if n := strings.Count(body, " webmail login as "); n != 5 {
		t.Fatalf("subnet examples = %d, want 5:\n%s", n, body)
	}

	if len(capture.webhooks) != 1 {
		t.Fatalf("webhooks = %d, want 1", len(capture.webhooks))
	}
	p := capture.webhooks[0]
	if p.CSM.Event != "customer_block" || p.Text != body || len(p.CSM.CustomerBlocks) != 2 {
		t.Fatalf("webhook = %+v, want a customer_block event with both blocks and the email text", p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		CSM map[string]json.RawMessage `json:"csm"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	// csm.blocks is block_live's list of blocked addresses; customer blocks
	// have a shape of their own under their own key.
	for _, field := range []string{"window", "counts", "countries", "summary", "blocks"} {
		if _, ok := decoded.CSM[field]; ok {
			t.Fatalf("customer_block payload carries %q: %s", field, raw)
		}
	}
	var blocks []CustomerBlock
	if err := json.Unmarshal(decoded.CSM["customer_blocks"], &blocks); err != nil {
		t.Fatalf("csm.customer_blocks does not decode: %v (%s)", err, raw)
	}
	if len(blocks) != 2 || blocks[0].Target != "203.0.113.5" || blocks[0].Hits[0].Account != "alice" || blocks[1].More != 195 || len(blocks[1].Hits) != 5 {
		t.Fatalf("csm.customer_blocks = %+v", blocks)
	}
}

func TestCustomerBlockAlertSubjectNamesASingleBlock(t *testing.T) {
	var capture summaryCapture
	c := summaryCollector(Options{EmailSink: capture.email})
	c.AlertCustomerBlocks([]CustomerBlock{{Target: "2001:db8:1::5", Reason: "fixture",
		Hits: []CustomerHit{{IP: "2001:db8:1::/64", Kind: "imap", Account: "office@example.com", At: customerLoginAt}}}})
	mails := capture.sent()
	if len(mails) != 1 || mails[0].subject != "[CSM] host.example.com - automatic block hit a known customer: 2001:db8:1::5" {
		t.Fatalf("emails = %+v", mails)
	}
	if !strings.Contains(mails[0].body, "Known customer: 2001:db8:1::/64 imap login as office@example.com at ") {
		t.Fatalf("body does not name the customer /64:\n%s", mails[0].body)
	}
}

// The alert asks the delivery policy for its own event, so a destination
// that takes no customer alerts gets no job and counts no delivery.
func TestCustomerBlockAlertFollowsItsDeliveryEvent(t *testing.T) {
	var capture summaryCapture
	var events []string
	c := summaryCollector(Options{EmailSink: capture.email, WebhookSink: capture.webhook,
		DeliveryEnabled: func(event, channel string) bool {
			events = append(events, event)
			return channel == "email"
		}})
	c.AlertCustomerBlocks([]CustomerBlock{{Target: "203.0.113.5", Reason: "fixture",
		Hits: []CustomerHit{{IP: "203.0.113.5", Kind: "ftp", At: customerLoginAt}}}})
	if len(capture.sent()) != 1 || len(capture.webhooks) != 0 {
		t.Fatalf("emails = %d webhooks = %d, want 1/0", len(capture.sent()), len(capture.webhooks))
	}
	if len(events) == 0 {
		t.Fatal("delivery policy never asked")
	}
	for _, e := range events {
		if e != "customer_block" {
			t.Fatalf("delivery policy asked for %q, want customer_block only (%v)", e, events)
		}
	}
	for name, row := range c.QueueStatuses(time.Now()) {
		if row.DroppedTotal != 0 || row.Depth != 0 || row.InFlight != 0 {
			t.Fatalf("%s after the alert: %+v", name, row)
		}
	}
	if !strings.Contains(capture.sent()[0].body, "Known customer: 203.0.113.5 ftp login at ") {
		t.Fatalf("accountless hit rendered as:\n%s", capture.sent()[0].body)
	}
}

func TestCustomerBlockAlertWithNoBlocksSendsNothing(t *testing.T) {
	var capture summaryCapture
	c := summaryCollector(Options{EmailSink: capture.email, WebhookSink: capture.webhook})
	c.AlertCustomerBlocks(nil)
	if len(capture.sent()) != 0 || len(capture.webhooks) != 0 {
		t.Fatalf("emails = %d webhooks = %d, want none", len(capture.sent()), len(capture.webhooks))
	}
}

// Would-block verdicts on known customers are listed once per target, up to
// maxWouldBlock, with a count of the rest, and survive a restart.
func TestWouldBlockListedInDailySummary(t *testing.T) {
	var capture summaryCapture
	saved := &summaryStore{}
	opts := Options{EmailSink: capture.email, WebhookSink: capture.webhook, LoadSummary: saved.load, SaveSummary: saved.save}
	c := summaryCollector(opts)
	note := func(b CustomerBlock) {
		c.NoteHandled([]Handled{{Check: "auto_block", Severity: "WARNING", WouldBlock: &b}})
	}
	first := CustomerBlock{Target: "203.0.113.5", Reason: "SMTP brute force from 203.0.113.5", Check: "smtp_bruteforce",
		Hits: []CustomerHit{{IP: "203.0.113.5", Kind: "smtp", Account: "office@example.com", At: customerLoginAt}}}
	note(first)
	note(first)
	for i := range maxWouldBlock + 3 {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		note(CustomerBlock{Target: ip, Reason: "fixture", Hits: []CustomerHit{{IP: ip, Kind: "pop", At: customerLoginAt}}})
	}
	c.Flush()

	c = summaryCollector(opts)
	c.load()
	note(CustomerBlock{Target: "198.51.100.9", Reason: "fixture", Hits: []CustomerHit{{IP: "198.51.100.9", Kind: "pop", At: customerLoginAt}}})
	c.SendDue(summaryDueOf(c))

	if len(capture.webhooks) != 1 || capture.webhooks[0].CSM.Summary == nil {
		t.Fatalf("summary webhooks = %+v", capture.webhooks)
	}
	s := capture.webhooks[0].CSM.Summary
	if got := s.Checks["auto_block"]["WARNING"]; got != maxWouldBlock+6 {
		t.Fatalf("would-block findings = %d, want %d including repeats and overflow", got, maxWouldBlock+6)
	}
	if len(s.WouldBlock) != maxWouldBlock || s.WouldBlockMore != 5 {
		t.Fatalf("would-block = %d listed + %d more, want %d + 5", len(s.WouldBlock), s.WouldBlockMore, maxWouldBlock)
	}
	if s.WouldBlock[0].Target != "203.0.113.5" || s.WouldBlock[0].Hits[0].Account != "office@example.com" {
		t.Fatalf("first would-block = %+v", s.WouldBlock[0])
	}
	body := capture.sent()[0].body
	for _, want := range []string{
		"Known customers a dry-run or observe-mode verdict would have blocked:",
		"Block: 203.0.113.5\n",
		"Known customer: 203.0.113.5 smtp login as office@example.com at 2026-06-10 08:15 UTC",
		"and 5 more verdicts",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("summary body has no %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "Block: 203.0.113.5\n") != 1 {
		t.Fatalf("repeated verdict listed twice:\n%s", body)
	}
}

func TestWouldBlockSectionEmptyByDefault(t *testing.T) {
	var capture summaryCapture
	c := summaryCollector(Options{EmailSink: capture.email})
	c.SendDue(summaryDueOf(c))
	body := capture.sent()[0].body
	_, section, ok := strings.Cut(body, "Known customers a dry-run or observe-mode verdict would have blocked:\n")
	if !ok || !strings.HasPrefix(section, "  (none)\n") {
		t.Fatalf("summary has no empty would-block section:\n%s", body)
	}
}

// Applied blocks that hit known customers are listed in the next daily
// summary, so a failed customer alert still reaches the operator. The list is
// capped like the would-block list, survives a restart and rolls over with
// the summary.
func TestAppliedCustomerBlocksListedInDailySummary(t *testing.T) {
	var capture summaryCapture
	saved := &summaryStore{}
	opts := Options{
		EmailSink: func(subject, body string) error {
			if strings.Contains(subject, "known customer") {
				return errors.New("fixture smtp down")
			}
			return capture.email(subject, body)
		},
		WebhookSink: capture.webhook, LoadSummary: saved.load, SaveSummary: saved.save,
	}
	c := summaryCollector(opts)
	c.AlertCustomerBlocks([]CustomerBlock{{Target: "203.0.113.5", Reason: "SMTP brute force from 203.0.113.5", Check: "smtp_bruteforce",
		Hits: []CustomerHit{{IP: "203.0.113.5", Kind: "cpanel", Account: "alice", At: customerLoginAt}}}})
	if len(capture.sent()) != 0 {
		t.Fatalf("customer alert email delivered: %+v", capture.sent())
	}
	for i := range maxWouldBlock + 1 {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		c.AlertCustomerBlocks([]CustomerBlock{{Target: ip, Reason: "fixture", Hits: []CustomerHit{{IP: ip, Kind: "pop", At: customerLoginAt}}}})
	}
	c.Flush()

	c = summaryCollector(opts)
	c.load()
	c.AlertCustomerBlocks([]CustomerBlock{{Target: "198.51.100.0/24", Reason: "AUTO-NETBLOCK: 198.51.100.0/24 blocked (5 IPs from same subnet)",
		Hits: subnetCustomerHits(5), More: 195}})
	due := summaryDueOf(c)
	c.SendDue(due)

	summaries := func() []*Summary {
		var out []*Summary
		for _, p := range capture.webhooks {
			if p.CSM.Event == "daily_summary" {
				out = append(out, p.CSM.Summary)
			}
		}
		return out
	}
	sent := summaries()
	if len(sent) != 1 {
		t.Fatalf("daily summary webhooks = %d, want 1", len(sent))
	}
	s := sent[0]
	if len(s.CustomerBlocks) != maxWouldBlock || s.CustomerBlocksMore != 3 {
		t.Fatalf("customer blocks = %d listed + %d more, want %d + 3", len(s.CustomerBlocks), s.CustomerBlocksMore, maxWouldBlock)
	}
	if b := s.CustomerBlocks[0]; b.Target != "203.0.113.5" || b.Check != "smtp_bruteforce" || b.Reason != "SMTP brute force from 203.0.113.5" || len(b.Hits) != 1 || b.Hits[0].Account != "alice" {
		t.Fatalf("first customer block = %+v", b)
	}
	mails := capture.sent()
	if len(mails) != 1 || !strings.Contains(mails[0].subject, "daily summary") {
		t.Fatalf("emails = %+v, want the daily summary only", mails)
	}
	body := mails[0].body
	for _, want := range []string{
		"Automatic blocks that hit known customers:\n  Block: 203.0.113.5\n",
		"    Check: smtp_bruteforce\n",
		"    Known customer: 203.0.113.5 cpanel login as alice at 2026-06-10 08:15 UTC\n",
		"  and 3 more blocks\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("summary body has no %q:\n%s", want, body)
		}
	}

	c.SendDue(nextSummaryDue(due, time.UTC))
	if sent = summaries(); len(sent) != 2 || len(sent[1].CustomerBlocks) != 0 || sent[1].CustomerBlocksMore != 0 {
		t.Fatalf("next summary keeps the sent customer blocks: %+v", sent)
	}
	if _, section, _ := strings.Cut(capture.sent()[1].body, "Automatic blocks that hit known customers:\n"); !strings.HasPrefix(section, "  (none)\n") {
		t.Fatalf("next summary has no empty customer block section:\n%s", capture.sent()[1].body)
	}
}

// Each block names how to lift it: csm firewall remove for an address and
// remove-subnet for a network. An allow rule does not pass a blocked network
// but keeps later range blocks off the address, so it is offered as that.
// The daily summary repeats the hints for applied blocks only.
func TestCustomerBlockUnblockHintPerTargetKind(t *testing.T) {
	var capture summaryCapture
	c := summaryCollector(Options{EmailSink: capture.email})
	c.AlertCustomerBlocks([]CustomerBlock{
		{Target: "203.0.113.5", Reason: "fixture", Hits: []CustomerHit{{IP: "203.0.113.5", Kind: "cpanel", Account: "alice", At: customerLoginAt}}},
		{Target: "2001:db8:1::5", Reason: "fixture", Hits: []CustomerHit{{IP: "2001:db8:1::/64", Kind: "imap", At: customerLoginAt}}},
		{Target: "198.51.100.0/24", Reason: "AUTO-NETBLOCK: 198.51.100.0/24 blocked (5 IPs from same subnet)", Hits: subnetCustomerHits(2)},
	})
	c.NoteHandled([]Handled{{Check: "auto_block", Severity: "WARNING", WouldBlock: &CustomerBlock{Target: "192.0.2.9", Reason: "fixture",
		Hits: []CustomerHit{{IP: "192.0.2.9", Kind: "pop", At: customerLoginAt}}}}})
	c.SendDue(summaryDueOf(c))

	mails := capture.sent()
	if len(mails) != 2 {
		t.Fatalf("emails = %d, want the customer alert and the summary", len(mails))
	}
	address := "  Unblock: csm firewall remove 203.0.113.5\n"
	address6 := "  Unblock: csm firewall remove 2001:db8:1::5\n"
	network := "  Unblock: csm firewall remove-subnet 198.51.100.0/24\n  Keep a customer address out of later range blocks: csm firewall allow <ip>\n"
	for i, m := range mails {
		indent := ""
		if i == 1 {
			indent = "  "
		}
		for _, want := range []string{address, address6, network} {
			want = strings.ReplaceAll(want, "  ", "  "+indent)
			if strings.Count(m.body, want) != 1 {
				t.Fatalf("%s has %q %d times, want once:\n%s", m.subject, want, strings.Count(m.body, want), m.body)
			}
		}
		for _, wrong := range []string{"csm firewall remove 198.51.100.0/24", "csm firewall remove <ip>", "csm firewall remove 192.0.2.9"} {
			if strings.Contains(m.body, wrong) {
				t.Fatalf("%s has %q:\n%s", m.subject, wrong, m.body)
			}
		}
	}
}
