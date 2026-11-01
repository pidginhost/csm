package daemon

import (
	"net/netip"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/netutil"
)

// spamEvidence reads one scan as a verdict about the sender of the scanned
// message (feeds spec 7). never excludes whitelisted and the host's own
// addresses; weight is the CSM_IP score the last written map gives the
// sender, in tenths.
func spamEvidence(s antispam.Scan, as config.AntispamConfig, never func(netip.Addr) bool, weight func(netip.Addr) int) (string, ipmap.Verdict) {
	if !as.Enabled || !ipmap.Recordable(s.IP, nil) || never(s.IP) {
		return "", ipmap.NoVerdict
	}
	return s.IP.String(), ipmap.Judge(s.OK, s.Score, weight(s.IP), as.RejectScore, as.TagScore)
}

// recordSpamEvidence stores one verdict on the sender's attack DB record.
func (d *Daemon) recordSpamEvidence(s antispam.Scan, at time.Time, cfg *config.Config) {
	adb := attackdb.Global()
	if adb == nil {
		return
	}
	weight := func(netip.Addr) int { return 0 }
	w := d.ipmapWriter.Load()
	removed := d.ipMapRemoved()
	if !removed && slices.Contains(cfg.EmailProtection.Antispam.Feeds.Enabled, antispam.FeedCSMIPMap) && (w == nil || w.State().Gen == "") {
		// rspamd can retain a map across daemon restarts. Until its local
		// lookup is rebuilt, treating the unknown contribution as zero
		// would let the map reinforce its own spam evidence.
		return
	}
	if w != nil && !removed {
		weight = w.Weight
	}
	never := func(a netip.Addr) bool { return d.spamSenderExcluded(a, cfg) }
	ip, v := spamEvidence(s, cfg.EmailProtection.Antispam, never, weight)
	if v != ipmap.NoVerdict {
		adb.RecordMailVerdict(ip, v == ipmap.SpamVerdict, at)
	}
}

// spamSenderExcluded reports a sender no spam evidence may name: whitelisted,
// the host's own or an infra_ips address.
func (d *Daemon) spamSenderExcluded(a netip.Addr, cfg *config.Config) bool {
	return notRecordable(a) || isInfraIPDaemon(a.String(), d.antispamInfraIPs(cfg))
}

// notRecordable reports a whitelisted or host-owned address.
func notRecordable(a netip.Addr) bool {
	if tdb := checks.GetThreatDB(); tdb != nil && tdb.IsWhitelisted(a.String()) {
		return true
	}
	return netutil.IsHostAddress(a.String())
}
