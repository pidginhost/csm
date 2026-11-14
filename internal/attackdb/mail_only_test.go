package attackdb

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestMailOnly(t *testing.T) {
	const ip = "192.0.2.10"
	spamRecord := func() (*DB, *IPRecord) {
		db := NewForTest(nil)
		db.RecordMailVerdict(ip, true, mailNow)
		return db, db.records[ip]
	}

	if _, rec := spamRecord(); !mailOnly(rec, mailNow) {
		t.Error("a record made by one spam verdict is not mail-only")
	}
	if mailOnly(&IPRecord{IP: ip}, mailNow) {
		t.Error("a record with no mail section is mail-only")
	}

	db, rec := spamRecord()
	db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Timestamp: mailNow, Message: "x"})
	if mailOnly(rec, mailNow) {
		t.Error("a record with a finding is mail-only")
	}
	// Past the login attack window only the counted finding keeps it out.
	if mailOnly(rec, mailNow.Add(mailAuthWindow+24*time.Hour)) {
		t.Error("a record with a finding is mail-only once its login attack aged out")
	}

	db, rec = spamRecord()
	db.MarkBlocked(ip)
	if mailOnly(rec, mailNow) {
		t.Error("a blocked record is mail-only")
	}

	authAttack := func(age time.Duration) *IPRecord {
		return &IPRecord{IP: ip, Mail: &MailEvidence{AuthAttacks: 1, LastAuthAttack: mailNow.Add(-age)}}
	}
	if mailOnly(authAttack(29*24*time.Hour), mailNow) {
		t.Error("a record with a login attack 29 days ago is mail-only")
	}
	if !mailOnly(authAttack(31*24*time.Hour), mailNow) {
		t.Error("a record with a login attack 31 days ago is not mail-only")
	}
}

// Three spam-verdict records, one of them two days old, and one finding record.
func mailOnlyStatsDB() *DB {
	now := time.Now()
	db := NewForTest(nil)
	db.RecordMailVerdict("192.0.2.1", true, now)
	db.RecordMailVerdict("192.0.2.2", true, now)
	db.RecordMailVerdict("192.0.2.3", true, now.Add(-48*time.Hour))
	db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: "192.0.2.4", Timestamp: now, Message: "x"})
	return db
}

func TestStatsCountMailOnlyRecords(t *testing.T) {
	stats := mailOnlyStatsDB().computeStats()
	if stats.MailOnlyIPs != 3 || stats.MailOnlyNew24h != 2 {
		t.Fatalf("MailOnlyIPs = %d, MailOnlyNew24h = %d, want 3 and 2", stats.MailOnlyIPs, stats.MailOnlyNew24h)
	}
}

func TestFormatTopLineCountsMailOnly(t *testing.T) {
	const want = "4 IPs tracked, 0 auto-blocked, 3 spam evidence only (2 new in 24h)"
	if got := mailOnlyStatsDB().FormatTopLine(); got != want {
		t.Fatalf("top line = %q, want %q", got, want)
	}
}

func BenchmarkMailOnlyRecordMemory(b *testing.B) {
	const records = 100_000
	at := time.Now()
	var before, after runtime.MemStats
	for range b.N {
		runtime.GC()
		runtime.ReadMemStats(&before)
		db := NewForTest(nil)
		for i := range records {
			// One address per /64, so every verdict makes its own record.
			db.RecordMailVerdict(fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff), true, at)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		// Read after the measurement so db stays live across the GC.
		if got := db.TotalIPs(); got != records {
			b.Fatalf("%d records, want %d", got, records)
		}
	}
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/records, "bytes/record")
}
