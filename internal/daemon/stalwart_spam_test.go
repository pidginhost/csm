package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/mailstats"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

// stalwartIngestLine builds a delivery line for one recipient of a queued
// message, as Stalwart writes it.
func stalwartIngestLine(at time.Time, spam bool, queueID int, rcpt string) string {
	desc, event, mailbox := "Message ingested", "message-ingest.ham", 0
	if spam {
		desc, event, mailbox = "Possible spam message ingested", "message-ingest.spam", 2
	}
	return fmt.Sprintf(`%s INFO %s (%s) queueId = %d, queueName = "local", from = "sender@example.net", to = ["%s"], total = 1, accountId = 2, documentId = 11, mailboxId = [%d], messageId = "m1@example.net", size = 1569, elapsed = 0ms`+"\n",
		at.UTC().Format(time.RFC3339), desc, event, queueID, rcpt, mailbox)
}

// stalwartQueuedLine builds an unauthenticated queued message on port.
func stalwartQueuedLine(port int, ip string, queueID int) string {
	return stalwartLine(stalwartTestStart, "queue.message-queued", port, ip,
		fmt.Sprintf(`, queueId = %d, from = "sender@example.net", to = ["user1@example.org", "user2@example.org"], size = 1569`, queueID))
}

func stalwartClassifyLine(ip string, queueID int, result string) string {
	return stalwartLine(stalwartTestStart, "spam.classify", 25, ip,
		fmt.Sprintf(`, queueId = %d, result = "%s", reason = "Message rejected due to excessive spam score."`, queueID, result))
}

type stalwartFilterCounts struct {
	delivered, junk, filterRejected, discarded, unmatched, rejected int
}

func stalwartCounts(d *Daemon) stalwartFilterCounts {
	t := d.mailStats.Overview(stalwartTestStart.Add(-time.Hour), stalwartTestStart.Add(time.Hour)).Totals
	return stalwartFilterCounts{t.Delivered, t.Junk, t.FilterRejected, t.Discarded, t.Unmatched, t.Rejected}
}

func newStalwartVerdictDaemon(t *testing.T, cfg *config.Config) (*Daemon, *attackdb.DB) {
	t.Helper()
	d, _ := newStalwartAuthDaemon(t, cfg)
	d.mailStats = mailstats.New(func() time.Time { return stalwartTestStart })
	return d, useTestAttackDB(t)
}

// sweepAfterHold books every message read so far.
func sweepAfterHold(d *Daemon, cfg *config.Config) {
	d.sweepStalwartVerdicts(time.Now().Add(stalwartVerdictHold), cfg)
}

func spamOf(adb *attackdb.DB, ip string) (spam, ham int, ok bool) {
	rec := adb.LookupIP(ip)
	if rec == nil || rec.Mail == nil {
		return 0, 0, false
	}
	return rec.Mail.Spam, rec.Mail.Ham, true
}

func TestStalwartVerdictDelivered(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001), stalwartIngestLine(stalwartTestStart, false, 1001, "user1@example.org"))
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("before the hold: %+v, want nothing", got)
	}
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{delivered: 1}) {
		t.Fatalf("counts = %+v, want one delivered", got)
	}
	if rec := adb.LookupIP("198.51.100.20"); rec != nil {
		t.Fatalf("ham created a record: %+v", rec)
	}

	adb.RecordMailVerdict("198.51.100.20", true, stalwartTestStart.Add(-time.Hour))
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1002), stalwartIngestLine(stalwartTestStart, false, 1002, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if spam, ham, _ := spamOf(adb, "198.51.100.20"); spam != 1 || ham != 1 {
		t.Fatalf("spam %d ham %d, want 1 and 1", spam, ham)
	}
}

func TestStalwartVerdictJunk(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 1}) {
		t.Fatalf("counts = %+v, want one junk", got)
	}
	if spam, _, _ := spamOf(adb, "198.51.100.20"); spam != 1 {
		t.Fatalf("spam verdicts = %d, want 1", spam)
	}
}

func TestStalwartVerdictSeveralRecipients(t *testing.T) {
	ham := stalwartIngestLine(stalwartTestStart, false, 1001, "user1@example.org")
	spam := stalwartIngestLine(stalwartTestStart, true, 1001, "user2@example.org")
	for name, order := range map[string][]string{"ham first": {ham, spam}, "spam first": {spam, ham}} {
		t.Run(name, func(t *testing.T) {
			cfg := stalwartBruteConfig()
			d, adb := newStalwartVerdictDaemon(t, cfg)
			feedStalwart(d, append([]string{stalwartQueuedLine(25, "198.51.100.20", 1001)}, order...)...)
			sweepAfterHold(d, cfg)
			if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 1}) {
				t.Fatalf("counts = %+v, want one junk", got)
			}
			if s, h, _ := spamOf(adb, "198.51.100.20"); s != 1 || h != 0 {
				t.Fatalf("spam %d ham %d, want one spam verdict", s, h)
			}
		})
	}
}

func TestStalwartVerdictRejectAndDiscard(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d,
		stalwartClassifyLine("198.51.100.21", 1002, "reject"),
		stalwartClassifyLine("198.51.100.22", 1003, "discard"),
		stalwartClassifyLine("198.51.100.23", 1004, "spam"),
	)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{filterRejected: 1, discarded: 1}) {
		t.Fatalf("counts = %+v, want one filter reject and one discard", got)
	}
	for _, ip := range []string{"198.51.100.21", "198.51.100.22"} {
		if spam, _, _ := spamOf(adb, ip); spam != 1 {
			t.Errorf("%s spam verdicts = %d, want 1", ip, spam)
		}
	}
	if rec := adb.LookupIP("198.51.100.23"); rec != nil {
		t.Fatalf("another result recorded: %+v", rec)
	}
}

func TestStalwartIngestWithoutQueuedLineIgnored(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d,
		stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"),
		stalwartLine(stalwartTestStart, "queue.authenticated-message-queued", 25, "198.51.100.20", `, queueId = 1002, from = "user@example.com", to = ["user1@example.org"]`),
		stalwartIngestLine(stalwartTestStart, true, 1002, "user1@example.org"),
	)
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("counts = %+v, want nothing", got)
	}
	if rec := adb.LookupIP("198.51.100.20"); rec != nil {
		t.Fatalf("recorded: %+v", rec)
	}
}

func TestStalwartQueuedWithoutIngestDropped(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, _ := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("counts = %+v, want nothing", got)
	}
	// A late ingest line finds nothing to join.
	feedStalwart(d, stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
	if n := len(d.stalwart.verdicts.drain()); n != 0 {
		t.Fatalf("%d messages still held after the hold", n)
	}
}

func TestStalwartIngestWithoutQueueIDIgnored(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001),
		stalwartTestStart.Format(time.RFC3339)+` INFO Possible spam message ingested (message-ingest.spam) accountId = 3, documentId = 1, mailboxId = [2], messageId = "m1@example.net", size = 1569, elapsed = 0ms`+"\n")
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("counts = %+v, want nothing", got)
	}
	if rec := adb.LookupIP("198.51.100.20"); rec != nil {
		t.Fatalf("recorded: %+v", rec)
	}
}

func TestStalwartVerdictHeldUntilExpiry(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, _ := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001), stalwartIngestLine(stalwartTestStart, false, 1001, "user1@example.org"))
	read := d.stalwart.verdicts.order[0].read
	d.sweepStalwartVerdicts(read.Add(stalwartVerdictHold-time.Nanosecond), cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("booked before the hold ended: %+v", got)
	}
	d.sweepStalwartVerdicts(read.Add(stalwartVerdictHold), cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{delivered: 1}) {
		t.Fatalf("counts = %+v, want one delivered", got)
	}
}

func TestStalwartVerdictQueueIDReusedAfterExpiry(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001), stalwartIngestLine(stalwartTestStart, false, 1001, "user1@example.org"))
	sweepAfterHold(d, cfg)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.24", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{delivered: 1, junk: 1}) {
		t.Fatalf("counts = %+v, want one delivered and one junk", got)
	}
	if rec := adb.LookupIP("198.51.100.20"); rec != nil {
		t.Fatalf("first sender recorded: %+v", rec.Mail)
	}
	if spam, _, _ := spamOf(adb, "198.51.100.24"); spam != 1 {
		t.Fatalf("second sender spam verdicts = %d, want 1", spam)
	}
}

func TestStalwartVerdictMemoryFull(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	for id := 1; id <= stalwartVerdictMax; id++ {
		feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", id), stalwartIngestLine(stalwartTestStart, false, id, "user1@example.org"))
	}
	over := stalwartVerdictMax + 1
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.25", over))
	if got := stalwartCounts(d); got != (stalwartFilterCounts{unmatched: 1}) {
		t.Fatalf("counts = %+v, want one unmatched", got)
	}
	if v := d.stalwart.verdicts; len(v.m) != stalwartVerdictMax || len(v.order) != stalwartVerdictMax {
		t.Fatalf("held memory grew past its cap: map=%d order=%d", len(v.m), len(v.order))
	}
	feedStalwart(d, stalwartIngestLine(stalwartTestStart, true, over, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{delivered: stalwartVerdictMax, unmatched: 1}) {
		t.Fatalf("counts = %+v, want %d delivered and one unmatched", got, stalwartVerdictMax)
	}
	if rec := adb.LookupIP("198.51.100.25"); rec != nil {
		t.Fatalf("unheld message recorded: %+v", rec.Mail)
	}
}

func TestStalwartVerdictExcludedSenders(t *testing.T) {
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	checks.GetThreatDB().AddWhitelist("203.0.113.110")
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.111")}, nil }))
	cfg := stalwartBruteConfig()
	cfg.InfraIPs = []string{"203.0.113.112/32"}
	d, adb := newStalwartVerdictDaemon(t, cfg)
	senders := []string{"127.0.0.1", "10.1.2.3", "203.0.113.112", "203.0.113.110", "203.0.113.111"}
	for i, ip := range senders {
		feedStalwart(d, stalwartQueuedLine(25, ip, 1001+i), stalwartIngestLine(stalwartTestStart, true, 1001+i, "user1@example.org"))
	}
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: len(senders)}) {
		t.Fatalf("counts = %+v, want %d junk", got, len(senders))
	}
	for _, ip := range senders {
		if rec := adb.LookupIP(ip); rec != nil {
			t.Errorf("%s recorded: %+v", ip, rec.Mail)
		}
	}
}

func TestStalwartVerdictIgnoresHTTPListener(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d, stalwartQueuedLine(8080, "198.51.100.26", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"),
		stalwartLine(stalwartTestStart, "spam.classify", 8080, "198.51.100.26", `, result = "reject"`),
		stalwartLine(stalwartTestStart, "spam.classify", 8080, "198.51.100.26", `, result = "discard"`))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("counts = %+v, want nothing", got)
	}
	if rec := adb.LookupIP("198.51.100.26"); rec != nil {
		t.Fatalf("HTTP sender recorded: %+v", rec.Mail)
	}
}

func TestStalwartVerdictForgedSenderText(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	forged := stalwartLine(stalwartTestStart, "queue.message-queued", 25, "198.51.100.27",
		`, queueId = 1001, from = "x\", queueId = 7, remoteIp = 203.0.113.9, y = \"@example.net", to = ["user1@example.org"], size = 1569`)
	feedStalwart(d, forged,
		stalwartIngestLine(stalwartTestStart, true, 7, "user1@example.org"),
		stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 1}) {
		t.Fatalf("counts = %+v, want one junk", got)
	}
	if spam, _, _ := spamOf(adb, "198.51.100.27"); spam != 1 {
		t.Fatalf("real sender spam verdicts = %d, want 1", spam)
	}
	if rec := adb.LookupIP("203.0.113.9"); rec != nil {
		t.Fatalf("forged address recorded: %+v", rec.Mail)
	}
}

func TestStalwartVerdictsDrainOnStop(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	feedStalwart(d,
		stalwartQueuedLine(25, "198.51.100.28", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"),
		stalwartQueuedLine(25, "198.51.100.29", 1002))
	d.drainStalwartVerdicts(cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 1}) {
		t.Fatalf("counts = %+v, want one junk", got)
	}
	if spam, _, _ := spamOf(adb, "198.51.100.28"); spam != 1 {
		t.Fatalf("spam verdicts = %d, want 1", spam)
	}
	feedStalwart(d, stalwartIngestLine(stalwartTestStart, true, 1002, "user1@example.org"))
	if n := len(d.stalwart.verdicts.drain()); n != 0 {
		t.Fatalf("%d messages still held after the drain", n)
	}
}

func TestStalwartEvidenceDoesNotNeedAntispam(t *testing.T) {
	cfg := stalwartBruteConfig()
	cfg.EmailProtection.Antispam.Enabled = false
	d, adb := newStalwartVerdictDaemon(t, cfg)
	if fs := feedStalwart(d, stalwartQueuedLine(25, "198.51.100.30", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org")); len(fs) != 0 {
		t.Fatalf("spam evidence raised findings: %+v", fs)
	}
	sweepAfterHold(d, cfg)
	if spam, _, _ := spamOf(adb, "198.51.100.30"); spam != 1 {
		t.Fatalf("spam verdicts = %d, want 1", spam)
	}
	if rec := adb.LookupIP("198.51.100.30"); rec.ThreatScore != 0 || rec.EventCount != 0 || len(rec.AttackCounts) != 0 {
		t.Fatalf("spam evidence changed threat state: %+v", rec)
	}
	if len(d.alertCh) != 0 {
		t.Fatal("spam evidence queued an alert")
	}
}

// A reused id cannot tell us which message a later delivery belongs to.
func TestStalwartVerdictHeldIDCollision(t *testing.T) {
	first := stalwartQueuedLine(25, "198.51.100.20", 1001)
	for name, second := range map[string]string{
		"different sender":     stalwartQueuedLine(25, "198.51.100.21", 1001),
		"different time":       strings.Replace(first, stalwartTestStart.Format(time.RFC3339), stalwartTestStart.Add(time.Second).Format(time.RFC3339), 1),
		"different connection": strings.Replace(first, "remotePort = 40000", "remotePort = 40001", 1),
		"HTTP":                 stalwartQueuedLine(8080, "198.51.100.21", 1001),
		"authenticated":        strings.Replace(stalwartQueuedLine(25, "198.51.100.21", 1001), "queue.message-queued", "queue.authenticated-message-queued", 1),
		"no session":           stalwartTestStart.Format(time.RFC3339) + ` INFO Synthetic event (queue.message-queued) queueId = 1001`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := stalwartBruteConfig()
			d, adb := newStalwartVerdictDaemon(t, cfg)
			feedStalwart(d, first, stalwartIngestLine(stalwartTestStart, false, 1001, "user@example.org"), second,
				stalwartIngestLine(stalwartTestStart, true, 1001, "user@example.org"), first, second)
			sweepAfterHold(d, cfg)
			if got := stalwartCounts(d); got != (stalwartFilterCounts{unmatched: 1}) {
				t.Fatalf("ambiguous queue id counts = %+v, want one unmatched join", got)
			}
			for _, ip := range []string{"198.51.100.20", "198.51.100.21"} {
				if adb.LookupIP(ip) != nil {
					t.Errorf("ambiguous queue id recorded evidence for %s", ip)
				}
			}
		})
	}
}

// The queue id is a slice of the whole log line, whose length the sender
// influences. Holding that string would pin the line until the hold ends.
func TestStalwartVerdictKeepsNoCallerString(t *testing.T) {
	v := newStalwartVerdicts()
	line := strings.Repeat("x", 1<<16) + " 1001"
	id := line[len(line)-len("1001"):]
	if !v.queued(id, stalwartlog.Session{LocalPort: 25}, stalwartTestStart, stalwartTestStart) {
		t.Fatal("queued refused the first message")
	}
	if len(v.m) != 1 {
		t.Fatalf("held %d messages, want 1", len(v.m))
	}
	for key, h := range v.m {
		if key != "1001" || h.id != "1001" {
			t.Fatalf("held key %q id %q, want 1001", key, h.id)
		}
		if unsafe.StringData(key) == unsafe.StringData(id) || unsafe.StringData(h.id) == unsafe.StringData(id) {
			t.Fatal("held queue id shares the log line's buffer")
		}
	}
}

func TestStalwartVerdictDuplicateQueued(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	queued := stalwartQueuedLine(25, "198.51.100.20", 1001)
	feedStalwart(d, queued)
	read := d.stalwart.verdicts.order[0].read
	feedStalwart(d, queued, stalwartIngestLine(stalwartTestStart, true, 1001, "user@example.org"), queued)
	if h := d.stalwart.verdicts.order; len(h) != 1 || !h[0].read.Equal(read) {
		t.Fatal("duplicate queued line grew memory or reset expiry")
	}
	sweepAfterHold(d, cfg)
	d.drainStalwartVerdicts(cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 1}) {
		t.Fatalf("counts = %+v, want one junk", got)
	}
	if spam, ham, _ := spamOf(adb, "198.51.100.20"); spam != 1 || ham != 0 {
		t.Fatalf("spam %d ham %d, want one spam", spam, ham)
	}
}

func TestStalwartVerdictForgedJoinFields(t *testing.T) {
	for _, event := range []string{"queue.message-queued", "message-ingest.spam"} {
		for _, field := range []string{"from", "to", "messageId"} {
			t.Run(event+"/"+field, func(t *testing.T) {
				cfg := stalwartBruteConfig()
				d, adb := newStalwartVerdictDaemon(t, cfg)
				value := `"x\", queueId = 1001, remoteIp = 203.0.113.9, y = \"@example.net"`
				if field == "to" {
					value = "[" + value + "]"
				}
				forged := stalwartLine(stalwartTestStart, event, 25, "198.51.100.20", ", "+field+" = "+value)
				if ev, ok := stalwartlog.Parse(forged); !ok || ev.Fields["queueId"] != "" {
					t.Fatalf("fixture must parse without a queue id: %q", forged)
				}
				if event == "queue.message-queued" {
					feedStalwart(d, forged, stalwartIngestLine(stalwartTestStart, true, 1001, "user@example.org"))
				} else {
					feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", 1001), forged)
				}
				sweepAfterHold(d, cfg)
				if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
					t.Fatalf("forged join counted: %+v", got)
				}
				for _, ip := range []string{"198.51.100.20", "203.0.113.9"} {
					if adb.LookupIP(ip) != nil {
						t.Errorf("forged join recorded %s", ip)
					}
				}
			})
		}
	}
}

func TestStalwartVerdictConcurrentSweeps(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	var wg sync.WaitGroup
	wg.Go(func() {
		for id := 1; id <= 100; id++ {
			feedStalwart(d, stalwartQueuedLine(25, "198.51.100.20", id), stalwartIngestLine(stalwartTestStart, true, id, "user@example.org"))
		}
	})
	wg.Go(func() {
		for range 100 {
			d.sweepStalwartVerdicts(time.Time{}, cfg)
		}
	})
	wg.Wait()
	for range 2 {
		wg.Go(func() { sweepAfterHold(d, cfg) })
	}
	wg.Wait()
	d.drainStalwartVerdicts(cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 100}) {
		t.Fatalf("counts = %+v, want 100 junk", got)
	}
	if spam, ham, _ := spamOf(adb, "198.51.100.20"); spam != 100 || ham != 0 {
		t.Fatalf("spam %d ham %d, want 100 spam", spam, ham)
	}
}

// guardStalwartList stores the state an address list tick would leave.
func guardStalwartList(d *Daemon, entries map[string][]string, filterOff, ruleOff bool) {
	m := ipmap.Build(ipmap.Sources{Entries: entries})
	d.stalwart.list.Store(&stalwartListState{m: &m, filterOff: filterOff, ruleOff: ruleOff})
}

func TestStalwartGuardSkipsListedSender(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	guardStalwartList(d, map[string][]string{ipmap.Spam.Name: {"198.51.100.40"}}, false, false)
	feedStalwart(d,
		stalwartQueuedLine(25, "198.51.100.40", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"),
		stalwartQueuedLine(25, "198.51.100.41", 1002), stalwartIngestLine(stalwartTestStart, true, 1002, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{junk: 2}) {
		t.Fatalf("counts = %+v, want two junk", got)
	}
	if rec := adb.LookupIP("198.51.100.40"); rec != nil {
		t.Fatalf("listed sender recorded: %+v", rec.Mail)
	}
	if spam, _, _ := spamOf(adb, "198.51.100.41"); spam != 1 {
		t.Fatalf("unlisted sender spam verdicts = %d, want 1", spam)
	}

	// Ham only adds to an existing record, so seed one to see it skipped.
	adb.RecordMailVerdict("198.51.100.40", true, stalwartTestStart.Add(-time.Hour))
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.40", 1003), stalwartIngestLine(stalwartTestStart, false, 1003, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{delivered: 1, junk: 2}) {
		t.Fatalf("counts = %+v, want one delivered and two junk", got)
	}
	if spam, ham, _ := spamOf(adb, "198.51.100.40"); spam != 1 || ham != 0 {
		t.Fatalf("listed sender spam %d ham %d, want only the seeded spam verdict", spam, ham)
	}
}

func TestStalwartGuardIPv4MappedSender(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	guardStalwartList(d, map[string][]string{ipmap.Spam.Name: {"198.51.100.40"}}, false, false)
	d.recordStalwartVerdict(netip.MustParseAddr("::ffff:198.51.100.40"), true, stalwartTestStart, cfg)
	for _, ip := range []string{"198.51.100.40", "::ffff:198.51.100.40"} {
		if rec := adb.LookupIP(ip); rec != nil {
			t.Fatalf("mapped listed sender recorded as %s: %+v", ip, rec.Mail)
		}
	}
}

func TestStalwartGuardRuleOffRecords(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	guardStalwartList(d, map[string][]string{ipmap.Spam.Name: {"198.51.100.40"}}, false, true)
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.40", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if spam, _, _ := spamOf(adb, "198.51.100.40"); spam != 1 {
		t.Fatalf("spam verdicts = %d, want 1 while the rule is off", spam)
	}
}

func TestStalwartGuardFilterOffRecordsNothing(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	guardStalwartList(d, nil, true, false)
	adb.RecordMailVerdict("198.51.100.42", true, stalwartTestStart.Add(-time.Hour))
	feedStalwart(d,
		stalwartQueuedLine(25, "198.51.100.42", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"),
		stalwartQueuedLine(25, "198.51.100.42", 1002), stalwartIngestLine(stalwartTestStart, false, 1002, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{delivered: 1, junk: 1}) {
		t.Fatalf("counts = %+v, want one delivered and one junk", got)
	}
	if spam, ham, _ := spamOf(adb, "198.51.100.42"); spam != 1 || ham != 0 {
		t.Fatalf("spam %d ham %d, want only the earlier spam verdict", spam, ham)
	}
}

func TestStalwartGuardIPv6Network(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, adb := newStalwartVerdictDaemon(t, cfg)
	guardStalwartList(d, map[string][]string{ipmap.Spam.Name: {"2001:db8:0:5::/64"}}, false, false)
	feedStalwart(d,
		stalwartQueuedLine(25, "2001:db8:0:5::77", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"),
		stalwartQueuedLine(25, "2001:db8:0:6::77", 1002), stalwartIngestLine(stalwartTestStart, true, 1002, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if rec := adb.LookupIP("2001:db8:0:5::77"); rec != nil {
		t.Fatalf("sender inside the listed network recorded: %+v", rec.Mail)
	}
	if spam, _, _ := spamOf(adb, "2001:db8:0:6::77"); spam != 1 {
		t.Fatalf("sender outside the listed network spam verdicts = %d, want 1", spam)
	}
}
