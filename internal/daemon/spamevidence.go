package daemon

import (
	"net/netip"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/netutil"
)

// spamEvidence reads one Exim main-log line as a verdict about the sender
// of a scanned message (feeds spec 7). never excludes whitelisted and the
// host's own addresses; weight is the CSM_IP score the last written map
// gives the sender, in tenths.
func spamEvidence(line string, as config.AntispamConfig, never func(netip.Addr) bool, weight func(netip.Addr) int) (string, ipmap.Verdict) {
	if !as.Enabled {
		return "", ipmap.NoVerdict
	}
	s, ok := antispam.ParseScan(line)
	if !ok || !ipmap.Recordable(s.IP, nil) || never(s.IP) {
		return "", ipmap.NoVerdict
	}
	return s.IP.String(), ipmap.Judge(s.OK, s.Score, weight(s.IP), as.RejectScore, as.TagScore)
}

// recordSpamEvidence stores one verdict on the sender's attack DB record.
func (d *Daemon) recordSpamEvidence(line string, at time.Time, cfg *config.Config) {
	adb := attackdb.Global()
	if adb == nil {
		return
	}
	weight := func(netip.Addr) int { return 0 }
	if w := d.ipmapWriter.Load(); w != nil {
		weight = w.Weight
	}
	ip, v := spamEvidence(line, cfg.EmailProtection.Antispam, notRecordable, weight)
	if v != ipmap.NoVerdict {
		adb.RecordMailVerdict(ip, v == ipmap.SpamVerdict, at)
	}
}

// notRecordable reports a whitelisted or host-owned address.
func notRecordable(a netip.Addr) bool {
	if tdb := checks.GetThreatDB(); tdb != nil && tdb.IsWhitelisted(a.String()) {
		return true
	}
	return netutil.IsHostAddress(a.String())
}
