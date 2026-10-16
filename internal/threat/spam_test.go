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
