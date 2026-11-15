package threat

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
)

func TestLookupCarriesSpamScore(t *testing.T) {
	prev := attackdb.Global()
	t.Cleanup(func() { attackdb.SetGlobal(prev) })
	const ip = "198.51.100.40"
	attackdb.SetGlobal(attackdb.NewForTest(map[string]*attackdb.IPRecord{
		ip: {IP: ip, Mail: &attackdb.MailEvidence{Spam: 2, SpamMass: 2, MassAt: time.Now()}},
	}))
	if got := Lookup(ip, t.TempDir()).SpamScore; got != 50 {
		t.Fatalf("Lookup spam score = %d, want 50", got)
	}
	if got := LookupBatch([]string{ip}, t.TempDir())[0].SpamScore; got != 50 {
		t.Fatalf("LookupBatch spam score = %d, want 50", got)
	}
}

func TestLookupIPv6ShowsNetworkSpamScore(t *testing.T) {
	prev := attackdb.Global()
	t.Cleanup(func() { attackdb.SetGlobal(prev) })
	const network = "2001:db8:1:2::/64"
	db := attackdb.NewForTest(nil)
	db.RecordMailVerdict("2001:db8:1:2::1", true, time.Now())
	db.RecordMailVerdict("2001:db8:1:2::2", true, time.Now())
	attackdb.SetGlobal(db)

	intel := Lookup("2001:db8:1:2::9", t.TempDir())
	if intel.SpamScore != 50 || intel.AttackRecord == nil || intel.AttackRecord.SpamNetwork != network {
		t.Fatalf("Lookup spam score = %d, record %+v, want 50 from %s", intel.SpamScore, intel.AttackRecord, network)
	}
	// The top attackers list looks a network record up by its own name.
	row := LookupBatch([]string{network}, t.TempDir())[0]
	if row.SpamScore != 50 || row.AttackRecord == nil || row.AttackRecord.IP != network {
		t.Fatalf("LookupBatch by network: spam score = %d, record %+v", row.SpamScore, row.AttackRecord)
	}
	if got := Lookup("2001:db8:9::1", t.TempDir()); got.SpamScore != 0 || got.AttackRecord != nil {
		t.Fatalf("Lookup outside the network: spam score = %d, record %+v", got.SpamScore, got.AttackRecord)
	}
}
