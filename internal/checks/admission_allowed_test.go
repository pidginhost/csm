package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
)

// Admission serves queued work later than the legacy funnel would have
// acted, so it asks again whether the switches that funnel checks still
// allow the response: blocking itself, cPanel login blocks for the checks
// that need them, and each derived entry's own opt-in. Challenges follow
// challenge routing, not the block switches, as legacy does. An unknown
// entry is never allowed.
func TestAutomaticResponseAllowedFollowsTheSwitches(t *testing.T) {
	on := func(mutate func(*config.Config)) *config.Config {
		cfg := &config.Config{}
		cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
		if mutate != nil {
			mutate(cfg)
		}
		return cfg
	}
	block, challenge := admission.KindBlockIP, admission.KindChallenge
	for _, tc := range []struct {
		name  string
		cfg   *config.Config
		kind  admission.Kind
		entry admission.Entry
		check string
		want  bool
	}{
		{"scan block", on(nil), block, admission.EntryScan, "ftp_bruteforce", true},
		{"blocking off", on(func(c *config.Config) { c.AutoResponse.Enabled = false }), block, admission.EntryScan, "ftp_bruteforce", false},
		{"address blocks off", on(func(c *config.Config) { c.AutoResponse.BlockIPs = false }), block, admission.EntryScan, "ftp_bruteforce", false},
		{"cpanel login block off", on(nil), block, admission.EntryScan, "cpanel_multi_ip_login", false},
		{"cpanel login block on", on(func(c *config.Config) { c.AutoResponse.BlockCpanelLogins = true }), block, admission.EntryScan, "cpanel_multi_ip_login", true},
		{"check that never blocks", on(nil), block, admission.EntryScan, "no_such_check", false},
		{"subnet scan entry", on(nil), admission.KindBlockSubnet, admission.EntryScan, "ftp_bruteforce", false},
		{"challenge timeout", on(func(c *config.Config) { c.Challenge.Enabled = true }), block, admission.EntryChallengeTimeout, "ftp_bruteforce", true},
		{"challenge timeout without challenges", on(nil), block, admission.EntryChallengeTimeout, "ftp_bruteforce", false},
		{"incident", on(func(c *config.Config) {
			c.Incidents.AutoBlock.Enabled, c.Incidents.AutoBlock.BlockAtSeverity = true, "High"
		}), block, admission.EntryIncident, "", true},
		{"incident detection only", on(func(c *config.Config) { c.Incidents.AutoBlock.Enabled = true }), block, admission.EntryIncident, "", false},
		{"incident off", on(func(c *config.Config) { c.Incidents.AutoBlock.BlockAtSeverity = "critical" }), block, admission.EntryIncident, "", false},
		{"spray", on(func(c *config.Config) {
			c.Incidents.SpraySuppression.Enabled, c.Incidents.SpraySuppression.BlockAtSeverity = true, "critical"
		}), block, admission.EntryIncidentSpray, "", true},
		{"spray dry run", on(func(c *config.Config) {
			s := &c.Incidents.SpraySuppression
			s.Enabled, s.DryRun, s.BlockAtSeverity = true, true, "critical"
		}), block, admission.EntryIncidentSpray, "", false},
		{"central block", on(func(c *config.Config) {
			c.Reputation.Central.Enabled, c.Reputation.Central.Action = true, "block_if_local_corroborated"
		}), block, admission.EntryCentral, "ftp_bruteforce", true},
		{"central challenges only", on(func(c *config.Config) { c.Reputation.Central.Enabled = true }), block, admission.EntryCentral, "ftp_bruteforce", false},
		{"netblock off", on(nil), admission.KindBlockSubnet, admission.EntryNetblock, "", false},
		{"netblock", on(func(c *config.Config) { c.AutoResponse.NetBlock = true }), admission.KindBlockSubnet, admission.EntryNetblock, "", true},
		{"permblock", on(func(c *config.Config) { c.AutoResponse.PermBlock = true }), admission.KindPromote, admission.EntryPermblock, "", true},
		{"mail subnet", on(nil), admission.KindBlockSubnet, admission.EntryMailSubnet, "", true},
		{"asn crawl blocking off", on(func(c *config.Config) { c.AutoResponse.BlockIPs = false }), admission.KindBlockSubnet, admission.EntryASNCrawl, "", false},
		{"unknown entry", on(nil), block, admission.Entry(0), "ftp_bruteforce", false},
		{"scan challenge with blocking off", on(func(c *config.Config) { c.AutoResponse.Enabled, c.Challenge.Enabled = false, true }), challenge, admission.EntryScan, "http_scanner_profile", true},
		{"scan challenge without challenges", on(nil), challenge, admission.EntryScan, "ftp_bruteforce", false},
		{"scanner challenge changed to block", on(func(c *config.Config) {
			c.Challenge.Enabled, c.AutoResponse.HTTPScannerAction = true, "block"
		}), challenge, admission.EntryScan, "http_scanner_profile", false},
		{"non-challengeable check", on(func(c *config.Config) { c.Challenge.Enabled = true }), challenge, admission.EntryScan, "ftp_bruteforce", false},
		{"unknown challenge check", on(func(c *config.Config) { c.Challenge.Enabled = true }), challenge, admission.EntryScan, "no_such_check", false},
		{"queued block keeps pending-drain semantics", on(func(c *config.Config) {
			c.Challenge.Enabled, c.AutoResponse.HTTPScannerAction = true, "challenge"
		}), block, admission.EntryScan, "http_scanner_profile", true},
		{"cpanel login challenge off", on(func(c *config.Config) { c.Challenge.Enabled = true }), challenge, admission.EntryScan, "cpanel_multi_ip_login", false},
		{"central challenge", on(func(c *config.Config) { c.Challenge.Enabled, c.Reputation.Central.Enabled = true, true }), challenge, admission.EntryCentral, "ftp_bruteforce", true},
		{"central off", on(func(c *config.Config) {
			c.Challenge.Enabled, c.Reputation.Central.Enabled, c.Reputation.Central.Action = true, true, "off"
		}), challenge, admission.EntryCentral, "ftp_bruteforce", false},
		{"no configuration", nil, block, admission.EntryScan, "ftp_bruteforce", false},
	} {
		if got := AutomaticResponseAllowed(tc.cfg, tc.kind, tc.entry, tc.check); got != tc.want {
			t.Errorf("%s: allowed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
