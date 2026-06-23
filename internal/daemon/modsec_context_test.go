package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func seedModSecHistory(t *testing.T) (*store.DB, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := "203.0.113.77"
	mk := func(check, domain, uri string, ageMin int) alert.Finding {
		return alert.Finding{
			Check:     check,
			SourceIP:  ip,
			Domain:    domain,
			Details:   "Rule: 900116\nMessage: scanner\nHostname: " + domain + "\nURI: " + uri + "\nRaw: x",
			Timestamp: now.Add(-time.Duration(ageMin) * time.Minute),
		}
	}
	if err := db.AppendHistory([]alert.Finding{
		mk("modsec_block_realtime", "shop.example.ro", "/vendor/phpunit/eval-stdin.php", 6),
		mk("modsec_block_realtime", "shop.example.ro", "/vendor/phpunit/eval-stdin.php", 5),
		mk("modsec_block_realtime", "", "/cgi-bin/.%2e/bin/sh", 4),
		// Escalation finding shares the modsec_ prefix but must be excluded:
		// it carries the raw triggering line, not a per-deny URI to aggregate.
		mk("modsec_block_escalation", "shop.example.ro", "/should-not-count", 3),
		// Different IP -- must not bleed into this IP's context.
		{
			Check: "modsec_block_realtime", SourceIP: "198.51.100.9", Domain: "other.ro",
			Details:   "URI: /other-ip-path",
			Timestamp: now.Add(-2 * time.Minute),
		},
	}); err != nil {
		t.Fatal(err)
	}
	return db, ip
}

func TestAggregateModSecContext(t *testing.T) {
	db, ip := seedModSecHistory(t)
	defer func() { _ = db.Close() }()
	prev := store.Global()
	store.SetGlobal(db)
	defer store.SetGlobal(prev)

	domains, uris := aggregateModSecContext(ip, time.Now().Add(-time.Hour))

	if len(domains) != 1 || domains[0] != "shop.example.ro" {
		t.Errorf("domains = %v, want [shop.example.ro]", domains)
	}
	if len(uris) != 2 || uris[0] != "/vendor/phpunit/eval-stdin.php" || uris[1] != "/cgi-bin/.%2e/bin/sh" {
		t.Errorf("uris = %v, want [/vendor/phpunit/eval-stdin.php /cgi-bin/.%%2e/bin/sh]", uris)
	}
}

func TestAggregateModSecContextNilStore(t *testing.T) {
	prev := store.Global()
	store.SetGlobal(nil)
	defer store.SetGlobal(prev)
	domains, uris := aggregateModSecContext("203.0.113.1", time.Now().Add(-time.Hour))
	if domains != nil || uris != nil {
		t.Errorf("nil store should yield nil context, got domains=%v uris=%v", domains, uris)
	}
}

func TestModSecEnricherUsesEscalationWindow(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	db, ip := seedModSecHistory(t)
	defer func() { _ = db.Close() }()
	prev := store.Global()
	store.SetGlobal(db)
	defer store.SetGlobal(prev)

	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Thresholds.ModSecEscalationWindowMin = 240 // 4h window covers the seeded denies

	enrich := d.modsecEnricher(cfg)
	domains, uris := enrich(ip)
	if len(domains) != 1 || domains[0] != "shop.example.ro" {
		t.Errorf("enricher domains = %v", domains)
	}
	if len(uris) != 2 {
		t.Errorf("enricher uris = %v", uris)
	}
}

func TestModSecEnricherUsesLiveEscalationWindow(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	prev := store.Global()
	store.SetGlobal(db)
	defer store.SetGlobal(prev)

	ip := "203.0.113.88"
	if err := db.AppendHistory([]alert.Finding{{
		Check:     "modsec_block_realtime",
		SourceIP:  ip,
		Domain:    "old-window.example.ro",
		Details:   "Rule: 900116\nMessage: scanner\nHostname: old-window.example.ro\nURI: /late-hit\nRaw: x",
		Timestamp: time.Now().Add(-30 * time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}

	startup := &config.Config{}
	startup.Thresholds.ModSecEscalationWindowMin = 10
	live := &config.Config{}
	live.Thresholds.ModSecEscalationWindowMin = 60

	d := &Daemon{cfg: startup}
	enrich := d.modsecEnricher(startup)
	config.SetActive(live)

	domains, uris := enrich(ip)
	if len(domains) != 1 || domains[0] != "old-window.example.ro" {
		t.Errorf("domains = %v, want live-config window to include old-window.example.ro", domains)
	}
	if len(uris) != 1 || uris[0] != "/late-hit" {
		t.Errorf("uris = %v, want [/late-hit]", uris)
	}
}
