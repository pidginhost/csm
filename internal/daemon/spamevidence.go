package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/netutil"
)

// spamEvidence reads one scan as a verdict about the sender of the scanned
// message. never excludes whitelisted and the host's own
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
		d.recordMailVerdict(adb, ip, v == ipmap.SpamVerdict, at)
	}
}

// recordMailVerdict stores one verdict and warns when it made the attack
// database drop spam evidence. The database hands each report out once, so
// every verdict is recorded through here.
func (d *Daemon) recordMailVerdict(adb *attackdb.DB, ip string, spam bool, at time.Time) {
	ev := adb.RecordMailVerdict(ip, spam, at)
	if ev == nil {
		return
	}
	finding := alert.Finding{
		Severity: alert.Warning,
		Check:    "spam_evidence_evicted",
		Message: fmt.Sprintf("Spam evidence budget reached: dropped %d records, weakest evidence first; the most crowded network, %s, held %d",
			ev.Dropped, ev.Network, ev.NetworkRecords),
		Details:   "Records with attack findings, a block or a recent mail login attack are never dropped. Records with two or more verdicts are dropped only when such records fill nine tenths of the budget. A network holding many of the dropped records is the likely source; a small count means the senders are spread over many networks.",
		Timestamp: at,
	}
	// Logged first: a full alert channel refuses the finding.
	fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", ts(), finding.Check, finding.Message)
	if !alert.TryEnqueue(d.alertCh, finding) {
		atomic.AddInt64(&d.droppedAlerts, 1)
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
