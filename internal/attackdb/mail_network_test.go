package attackdb

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/netutil"
)

const (
	spamNet      = "2001:db8:1:2::/64"
	otherSpamNet = "2001:db8:1:3::/64"
)

// networkSpamDB holds one /64 record with two spam verdicts from two
// addresses, both at the given time.
func networkSpamDB(at time.Time) *DB {
	db := NewForTest(nil)
	db.RecordMailVerdict("2001:db8:1:2::1", true, at)
	db.RecordMailVerdict("2001:db8:1:2::2", true, at)
	return db
}

func TestMailVerdictIPv6RotationSharesOneRecord(t *testing.T) {
	db := networkSpamDB(mailNow)
	rec := db.records[spamNet]
	if len(db.records) != 1 || rec == nil {
		t.Fatalf("two addresses in one /64 made records %v, want only %s", recordKeys(db), spamNet)
	}
	if rec.IP != spamNet || rec.Mail.Spam != 2 {
		t.Fatalf("network record = %q with %d spam, want %q with 2", rec.IP, rec.Mail.Spam, spamNet)
	}
	if _, spam := db.MapSources(mailNow); !slices.Equal(spam, []string{spamNet}) {
		t.Fatalf("spam sources = %v, want [%s]", spam, spamNet)
	}

	db.RecordMailVerdict("2001:db8:1:3::1", true, mailNow)
	other := db.records[otherSpamNet]
	if len(db.records) != 2 || other == nil || other.IP != otherSpamNet || other.Mail.Spam != 1 {
		t.Fatalf("a second /64 made records %v, want its own %s", recordKeys(db), otherSpamNet)
	}
	if rec.Mail.Spam != 2 {
		t.Fatalf("spam from another /64 changed the first record: %d spam", rec.Mail.Spam)
	}
}

func TestMailVerdictIPv4AndMappedStayPerAddress(t *testing.T) {
	db := NewForTest(nil)
	db.RecordMailVerdict("192.0.2.10", true, mailNow)
	db.RecordMailVerdict("::ffff:192.0.2.10", true, mailNow)
	rec := db.records["192.0.2.10"]
	if len(db.records) != 1 || rec == nil || rec.IP != "192.0.2.10" || rec.Mail.Spam != 2 {
		t.Fatalf("records %v, want one 192.0.2.10 record with 2 spam", recordKeys(db))
	}
}

func TestMailVerdictIPv6HamNeedsExistingNetworkRecord(t *testing.T) {
	db := NewForTest(nil)
	db.RecordMailVerdict("2001:db8:1:2::2", false, mailNow)
	if len(db.records) != 0 {
		t.Fatalf("ham alone made records %v", recordKeys(db))
	}
	db.RecordMailVerdict("2001:db8:1:2::1", true, mailNow)
	db.RecordMailVerdict("2001:db8:1:2::2", false, mailNow)
	rec := db.records[spamNet]
	if len(db.records) != 1 || rec == nil || rec.Mail.Spam != 1 || rec.Mail.Ham != 1 {
		t.Fatalf("records %v, want one %s record with 1 spam and 1 ham", recordKeys(db), spamNet)
	}
}

func TestRecordFindingIPv6StaysPerAddress(t *testing.T) {
	const ip = "2001:db8:1:2::1"
	db := NewForTest(nil)
	db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Timestamp: mailNow, Message: "x"})
	if rec := db.records[ip]; len(db.records) != 1 || rec == nil || rec.IP != ip {
		t.Fatalf("a finding made records %v, want only %s", recordKeys(db), ip)
	}
	if auth, _ := db.MapSources(mailNow); !slices.Equal(auth, []string{ip}) {
		t.Fatalf("auth sources = %v, want [%s]", auth, ip)
	}
}

func TestLookupIPv6ReadsNetworkSpamEvidence(t *testing.T) {
	const ip = "2001:db8:1:2::9"
	now := time.Now()
	db := networkSpamDB(now)
	network := db.records[spamNet]
	if network == nil {
		t.Fatalf("records %v, want %s", recordKeys(db), spamNet)
	}

	got := db.LookupIP(ip)
	if got == nil || got.IP != ip || got.Mail == nil || got.Mail.Spam != 2 || got.SpamNetwork != spamNet {
		t.Fatalf("lookup with only the network record = %+v", got)
	}
	if !got.FirstSeen.Equal(network.FirstSeen) || !got.LastSeen.Equal(network.LastSeen) {
		t.Fatalf("lookup seen times %v to %v, want the network's %v to %v", got.FirstSeen, got.LastSeen, network.FirstSeen, network.LastSeen)
	}
	if byKey := db.LookupIP(spamNet); byKey == nil || byKey.IP != spamNet || byKey.Mail.Spam != 2 || byKey.SpamNetwork != "" {
		t.Fatalf("lookup by the network key = %+v, want the stored record", byKey)
	}
	if other := db.LookupIP("2001:db8:9::1"); other != nil {
		t.Fatalf("lookup outside the network = %+v, want nil", other)
	}

	db.RecordFinding(alert.Finding{Check: "smtp_bruteforce", SourceIP: ip, Timestamp: now, Message: "x"})
	address := db.records[ip]
	got = db.LookupIP(ip)
	if got.IP != ip || got.ThreatScore != address.ThreatScore || got.ThreatScore == 0 || got.EventCount != 1 || got.Mail.AuthAttacks != 1 {
		t.Fatalf("lookup lost the address record: %+v, mail %+v", got, got.Mail)
	}
	if got.Mail.Spam != 2 || got.SpamNetwork != spamNet {
		t.Fatalf("lookup with both records: %d spam, network %q", got.Mail.Spam, got.SpamNetwork)
	}

	got.Mail.Spam, got.Mail.AuthAttacks = 99, 99
	got.AttackCounts[AttackC2] = 99
	if network.Mail.Spam != 2 || address.Mail.Spam != 0 || address.Mail.AuthAttacks != 1 || address.AttackCounts[AttackC2] != 0 {
		t.Fatalf("changing a lookup result changed the DB: network %+v, address %+v", network.Mail, address.Mail)
	}
	if network.SpamNetwork != "" || address.SpamNetwork != "" {
		t.Fatalf("a lookup named its network on a stored record: %q, %q", network.SpamNetwork, address.SpamNetwork)
	}
}

func TestLookupIPv6KeepsStrongerLegacyAddressEvidence(t *testing.T) {
	const ip = "2001:db8:1:2::7"
	now := time.Now()
	spam := func(n int, mass float64) *MailEvidence {
		return &MailEvidence{Spam: n, SpamMass: mass, MassAt: now, LastSpam: now}
	}
	db := NewForTest(map[string]*IPRecord{
		ip:      {IP: ip, Mail: spam(4, 4)},
		spamNet: {IP: spamNet, Mail: spam(1, 1)},
	})
	if got := db.LookupIP(ip); got.Mail.Spam != 4 || got.SpamNetwork != "" {
		t.Fatalf("stronger address evidence: %d spam, network %q, want 4 and none", got.Mail.Spam, got.SpamNetwork)
	}

	// Equal scores: the network's evidence is the one new verdicts add to.
	db = NewForTest(map[string]*IPRecord{
		ip:      {IP: ip, Mail: spam(4, 2)},
		spamNet: {IP: spamNet, Mail: spam(2, 2)},
	})
	if got := db.LookupIP(ip); got.Mail.Spam != 2 || got.SpamNetwork != spamNet {
		t.Fatalf("equal scores: %d spam, network %q, want the network's 2", got.Mail.Spam, got.SpamNetwork)
	}
}

func TestLegacyIPv6AddressRecordStillLists(t *testing.T) {
	const ip = "2001:db8:5::7"
	db := NewForTest(map[string]*IPRecord{
		ip: {IP: ip, Mail: &MailEvidence{Spam: 3, SpamMass: 3, MassAt: mailNow, LastSpam: mailNow}},
	})
	if _, spam := db.MapSources(mailNow); !slices.Equal(spam, []string{ip}) {
		t.Fatalf("spam sources = %v, want [%s]", spam, ip)
	}
	if top := db.TopSpamSenders(10, mailNow); len(top) != 1 || top[0].IP != ip {
		t.Fatalf("top spam senders = %+v, want %s", top, ip)
	}
}

func TestForgetIPDropsCoveringNetworkEvidence(t *testing.T) {
	db := networkSpamDB(mailNow)
	db.RecordMailVerdict("2001:db8:1:3::1", true, mailNow)

	removed := db.ForgetIP(net.ParseIP("2001:db8:1:2::9"))
	if len(removed) != 1 || removed[0].IP != spamNet || removed[0].Mail.Spam != 2 {
		t.Fatalf("removed %+v, want the %s record", removed, spamNet)
	}
	if keys := recordKeys(db); !slices.Equal(keys, []string{otherSpamNet}) {
		t.Fatalf("records left %v, want [%s]", keys, otherSpamNet)
	}
	if _, ok := db.deletedIPs[spamNet]; !ok {
		t.Fatal("the removed network record is not queued for deletion from the store")
	}
	// No address at all must not read as every key that is not an address.
	if removed := db.ForgetIP(nil); len(removed) != 0 || len(db.records) != 1 {
		t.Fatalf("forgetting no address removed %+v", removed)
	}
	if removed := db.ForgetIP(net.ParseIP("192.0.2.10")); len(removed) != 0 || len(db.records) != 1 {
		t.Fatalf("forgetting an unrelated IPv4 address removed %+v", removed)
	}
}

func TestForgetNetworksDropsOverlappingNetworkRecord(t *testing.T) {
	for _, tt := range []struct {
		network string
		want    int
	}{
		{"2001:db8:1::/48", 1},
		{"2001:db8:1:2::5/128", 1},
		{"2001:db8:2::/48", 0},
		{"192.0.2.0/24", 0},
	} {
		t.Run(tt.network, func(t *testing.T) {
			db := networkSpamDB(mailNow)
			nets := []*net.IPNet{netutil.ParseCIDROrIP(tt.network)}
			if nets[0] == nil {
				t.Fatalf("%s did not parse", tt.network)
			}
			if got := db.ForgetNetworks(nets); got != tt.want {
				t.Fatalf("removed %d records, want %d", got, tt.want)
			}
			if _, left := db.records[spamNet]; left == (tt.want == 1) {
				t.Fatalf("records left %v", recordKeys(db))
			}
		})
	}

	// A mask with holes has no prefix length and must not read as every address.
	db := networkSpamDB(mailNow)
	holes := &net.IPNet{IP: net.ParseIP("2001:db8:9::"), Mask: net.IPMask(net.ParseIP("ffff:0:ffff::"))}
	if got := db.ForgetNetworks([]*net.IPNet{holes}); got != 0 {
		t.Fatalf("a malformed network removed %d records", got)
	}
}

func TestMarkBlockedAddressLeavesNetworkRecord(t *testing.T) {
	db := networkSpamDB(mailNow)
	db.MarkBlocked("2001:db8:1:2::1")
	rec := db.records[spamNet]
	if len(db.records) != 1 || rec == nil {
		t.Fatalf("records %v, want only %s", recordKeys(db), spamNet)
	}
	if rec.AutoBlocked || rec.ThreatScore != 0 {
		t.Fatalf("blocking one address marked its network: %+v", rec)
	}
}

func TestNetworkRecordSurvivesStoreRoundTrip(t *testing.T) {
	for _, backend := range []string{"file", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			if backend == "bbolt" {
				_, cleanup := setupBboltStore(t)
				t.Cleanup(cleanup)
			}
			db.RecordMailVerdict("2001:db8:1:2::1", true, mailNow)
			db.RecordMailVerdict("2001:db8:1:2::2", true, mailNow)
			db.RecordMailVerdict("2001:db8:1:2::3", false, mailNow)
			if err := db.Flush(); err != nil {
				t.Fatal(err)
			}

			restored := NewForTest(nil)
			restored.dbPath = db.dbPath
			restored.load()
			rec := restored.records[spamNet]
			if len(restored.records) != 1 || rec == nil || rec.IP != spamNet || rec.Mail == nil {
				t.Fatalf("restored records %v, want only %s", recordKeys(restored), spamNet)
			}
			m := rec.Mail
			if m.Spam != 2 || m.Ham != 1 || m.SpamMass != 2 || m.HamMass != 1 || !m.MassAt.Equal(mailNow) {
				t.Fatalf("restored mail section %+v", m)
			}
		})
	}
}

func recordKeys(db *DB) []string {
	keys := make([]string, 0, len(db.records))
	for key := range db.records {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func TestForgetInvalidIPPreservesNetworkRecords(t *testing.T) {
	for _, ip := range []net.IP{nil, {}, {1, 2, 3}} {
		db := networkSpamDB(mailNow)
		db.RecordMailVerdict("2001:db8:1:3::1", true, mailNow)
		before := db.AllRecords()
		if removed := db.ForgetIP(ip); len(removed) != 0 {
			t.Fatalf("invalid IP %v removed %d records", []byte(ip), len(removed))
		}
		if db.TotalIPs() != len(before) || len(db.deletedIPs) != 0 {
			t.Fatalf("invalid IP %v changed records or queued deletions", []byte(ip))
		}
	}
}
