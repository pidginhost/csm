package daemon

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailstats"
	"github.com/pidginhost/csm/internal/netutil"
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
	d.sweepStalwartVerdicts(time.Now().Add(stalwartVerdictHold-time.Second), cfg)
	if got := stalwartCounts(d); got != (stalwartFilterCounts{}) {
		t.Fatalf("booked before the hold ended: %+v", got)
	}
	d.sweepStalwartVerdicts(time.Now().Add(stalwartVerdictHold), cfg)
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
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, nil }))
	cfg := stalwartBruteConfig()
	cfg.InfraIPs = []string{"203.0.113.112/32"}
	d, adb := newStalwartVerdictDaemon(t, cfg)
	senders := []string{"127.0.0.1", "10.1.2.3", "203.0.113.112", "203.0.113.110"}
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
	feedStalwart(d, stalwartQueuedLine(8080, "198.51.100.26", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
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
	feedStalwart(d, stalwartQueuedLine(25, "198.51.100.30", 1001), stalwartIngestLine(stalwartTestStart, true, 1001, "user1@example.org"))
	sweepAfterHold(d, cfg)
	if spam, _, _ := spamOf(adb, "198.51.100.30"); spam != 1 {
		t.Fatalf("spam verdicts = %d, want 1", spam)
	}
}
