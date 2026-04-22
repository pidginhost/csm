package daemon

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- Cloud-relay compromise detection -----------------------------------
//
// Detects the pattern where a mailbox's SMTP AUTH credentials are being
// abused from a rented botnet of cloud VMs. Characteristic signature:
// multiple authenticated sends in a short window, from several distinct
// cloud-provider IPs (Google Cloud, AWS, Azure, etc.), for the SAME
// mailbox user.
//
// A normal user on a residential/ISP IP never matches (cloud-PTR check).
// A legitimate self-hosted script on a single VPS won't match either
// (requires ≥2 distinct source IPs within the window). Credential abuse
// from a rotating fleet trips the detector within minutes of the first
// distinct IPs showing up.
//
// Action: one Critical finding per user per window, auto-suspend outgoing
// mail for the owning cPanel account, and emit an IP in the finding
// message so autoblock adds it to the nftables blocked_ips set.

// cloudProviderPTRSuffixes is an intentionally-conservative list of
// hostname suffixes that strongly indicate a cloud-VM source. Adding to
// this list increases detection coverage; removing reduces it. Keep
// entries specific enough to avoid catching ISP-transit ASNs.
var cloudProviderPTRSuffixes = []string{
	// Google Cloud Platform
	".googleusercontent.com",
	".gce.internal",
	// AWS EC2 — public PTRs only. `.compute.internal` is intentionally
	// excluded: it is an AWS VPC-internal PTR but also appears on
	// corporate VPN and self-hosted lab networks that have nothing to
	// do with AWS, so matching it would risk suspending mailboxes
	// that just happen to have an internal-looking reverse DNS.
	".compute.amazonaws.com",
	".compute-1.amazonaws.com",
	// Microsoft Azure
	".cloudapp.net",
	".cloudapp.azure.com",
	// Oracle Cloud
	".oraclecloud.com",
	".oraclevcn.com",
	// DigitalOcean
	".digitalocean.com",
	".digitaloceanspaces.com",
	// Linode / Akamai Cloud
	".members.linode.com",
	".linodeusercontent.com",
	// Vultr
	".vultr.com",
	".vultrusercontent.com",
	// Hetzner
	".hetzner.com",
	".your-server.de",
	// OVH / OVHcloud
	".ovh.net",
	".ovhcloud.com",
	".ovh.ca",
	".ovh.us",
	// Contabo
	".contabo.net",
	".contabo.host",
	".contaboserver.net",
}

// isCloudProviderPTR reports whether the given PTR hostname belongs to a
// recognized public-cloud provider. Case-insensitive suffix match.
func isCloudProviderPTR(ptr string) bool {
	if ptr == "" {
		return false
	}
	p := strings.ToLower(ptr)
	for _, suffix := range cloudProviderPTRSuffixes {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

// extractEximHostname parses the H=<hostname> field from an exim log line.
// The field often looks like "H=hostname.example (helo.string) [IP]:port"
// — we want the PTR-derived hostname before the HELO-in-parens.
func extractEximHostname(line string) string {
	idx := strings.Index(line, " H=")
	if idx < 0 {
		return ""
	}
	rest := line[idx+3:]
	// Terminate at first space, tab, or opening paren (HELO string).
	end := len(rest)
	for i, r := range rest {
		if r == ' ' || r == '\t' || r == '(' {
			end = i
			break
		}
	}
	return strings.TrimSpace(rest[:end])
}

// cloudRelayWindow tracks authenticated sends from cloud IPs for one user.
// Bounded so memory can't grow unbounded from a misbehaving log stream.
type cloudRelayWindow struct {
	mu        sync.Mutex
	events    []cloudRelayEvent
	firedAt   time.Time // last Critical emission; dedup guard
	lastEvent time.Time // last append — used to garbage-collect idle entries
}

type cloudRelayEvent struct {
	at  time.Time
	ip  string
	ptr string
}

// cloudRelayWindows tracks per-user cloud-relay activity.
var cloudRelayWindows sync.Map // map[string]*cloudRelayWindow

// Detection thresholds. Two OR-combined signals within the same 60-min
// sliding window:
//
//	A. Multi-IP burst: ≥ cloudRelayMinEvents sends from ≥ cloudRelayMinDistinctIP
//	   distinct cloud IPs. Catches rented-fleet abuse rotating IPs per-send
//	   (the typical credential-stuffing spam pattern).
//
//	B. Volume burst:   ≥ cloudRelayHighVolumeEvents sends regardless of
//	   distinct-IP count. Catches paced attacks that deliberately use one
//	   cloud IP per day to evade signal A. Threshold sits well above any
//	   legitimate SaaS integration seen on production (SmartBill ~2/hr,
//	   Nylas ~2/hr, WP transactional ≤3/hr).
//
// Tuning rationale: these values were chosen from the Apr 2026 incident
// analysis. A single-mailbox user with a legit single-VPS cron averaging
// ≤14 mails/hr stays silent; anything above that is either a compromised
// relay or a SaaS integration that should be added to
// `email_protection.high_volume_senders`.
const (
	cloudRelayWindow_          = 60 * time.Minute
	cloudRelayMinEvents        = 3
	cloudRelayMinDistinctIP    = 2
	cloudRelayHighVolumeEvents = 15
	cloudRelayDedupCooldown    = 60 * time.Minute
	cloudRelayMaxEvents        = 256 // per-user cap; prevents unbounded growth
)

// parseCloudRelayFinding evaluates an exim acceptance line for the
// cloud-relay compromise pattern. Called from parseEximLogLine. Returns
// zero or one finding. Never auto-suspends on its own — emits a finding
// whose Message embeds the source IP; the existing autoblock + suspend
// pipeline picks it up by check name.
func parseCloudRelayFinding(line string, cfg *config.Config) []alert.Finding {
	// Only care about authenticated outbound acceptance lines.
	if !strings.Contains(line, " <= ") || !strings.Contains(line, "A=dovecot_") {
		return nil
	}
	user := extractAuthUser(line)
	if user == "" {
		return nil
	}
	if isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return nil
	}
	ptr := extractEximHostname(line)
	if !isCloudProviderPTR(ptr) {
		return nil
	}
	ip := extractBracketedIP(line)
	if ip == "" {
		// Without an IP we can't dedup distinct sources; bail silently
		// so we don't count half-parsed records toward the threshold.
		return nil
	}

	now := time.Now()
	val, _ := cloudRelayWindows.LoadOrStore(user, &cloudRelayWindow{})
	w := val.(*cloudRelayWindow)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Prune anything older than the window.
	cutoff := now.Add(-cloudRelayWindow_)
	kept := w.events[:0]
	for _, e := range w.events {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	w.events = kept

	// Append this event (with cap).
	if len(w.events) < cloudRelayMaxEvents {
		w.events = append(w.events, cloudRelayEvent{at: now, ip: ip, ptr: ptr})
	}
	w.lastEvent = now

	// Already fired recently for this user? Dedup.
	if !w.firedAt.IsZero() && now.Sub(w.firedAt) < cloudRelayDedupCooldown {
		return nil
	}

	// Evaluate thresholds.
	distinctIPs := make(map[string]struct{}, len(w.events))
	for _, e := range w.events {
		distinctIPs[e.ip] = struct{}{}
	}
	multiIPBurst := len(w.events) >= cloudRelayMinEvents && len(distinctIPs) >= cloudRelayMinDistinctIP
	volumeBurst := len(w.events) >= cloudRelayHighVolumeEvents
	if !multiIPBurst && !volumeBurst {
		return nil
	}

	w.firedAt = now

	// Build an IP list for the details (newest first, deduped).
	seen := make(map[string]struct{}, len(w.events))
	ips := make([]string, 0, len(distinctIPs))
	for i := len(w.events) - 1; i >= 0; i-- {
		e := w.events[i]
		if _, dup := seen[e.ip]; dup {
			continue
		}
		seen[e.ip] = struct{}{}
		ips = append(ips, e.ip)
	}

	// Message format: autoblock's extractIPFromFinding takes the IP after
	// the last " from " token — we put the most recent source IP there.
	message := fmt.Sprintf(
		"Email account %s sent %d authenticated messages from %d cloud-provider IPs in %d minutes - credentials compromised - from %s",
		user, len(w.events), len(distinctIPs), int(cloudRelayWindow_.Minutes()), ips[0],
	)
	details := fmt.Sprintf(
		"Authenticated SMTP submissions for %s in the last %d minutes:\n"+
			"  total sends: %d\n"+
			"  distinct source IPs: %d\n"+
			"  most recent PTR: %s\n"+
			"  recent IPs: %s\n\n"+
			"Legitimate users do not send mail from rented cloud VMs. "+
			"This pattern is characteristic of credential abuse by a bulk "+
			"phishing operator. Outgoing mail has been auto-suspended and "+
			"the source IPs are being firewalled.",
		user,
		int(cloudRelayWindow_.Minutes()),
		len(w.events),
		len(distinctIPs),
		ptr,
		strings.Join(truncateIPList(ips, 8), ", "),
	)

	return []alert.Finding{{
		Severity: alert.Critical,
		Check:    "email_cloud_relay_abuse",
		Message:  message,
		Details:  truncateDaemon(details, 800),
	}}
}

func truncateIPList(ips []string, n int) []string {
	if len(ips) <= n {
		return ips
	}
	return ips[:n]
}
