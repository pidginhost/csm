// HTTP abuse detection.
//
// This file holds the access-log line parser, the per-scan aggregator
// struct (domlogStats), the UA classifier, the bot-classifier interface,
// and the static allowlist classifier that consults embedded bot IP ranges.
// The rDNS verifying classifier arrives in Task 5.
package checks

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/threatintel"
)

// accessLogRecord is the parsed shape of one access-log line. Combined
// Log Format plus the cPanel final-vhost extension:
//
//	IP - - [time] "METHOD URI PROTO" status bytes "referer" "ua" "vhost"
//
// The parser tolerates either the 9-field plain CLF or the 10-field
// cPanel variant. Bad lines return ok=false; callers must skip them.
type accessLogRecord struct {
	RemoteIP  string
	Time      time.Time
	Method    string
	URI       string
	Status    int
	UserAgent string
	XFF       string // optional; only trusted when RemoteIP is a trusted proxy
	Domain    string // vhost the line came from (per-domain domlog); empty for the central log
	Account   string // cPanel account owning Domain; empty when unknown/non-cPanel
}

// uaKind is the User-Agent classification produced by classifyUA and
// consumed by domlogStats.scan and the http_ua_spoof emit logic.
type uaKind int

const (
	uaKindBrowser uaKind = iota
	uaKindClaimedBot
	uaKindClaimedBotNegative
	// uaKindClaimedBotPending is a claimed-bot UA whose rDNS verification has
	// not resolved yet (cache miss, async job in flight). It is neither trusted
	// (would have returned early via IsVerifiedBot) nor a confirmed spoof. Such
	// an IP's flood/scanner abuse is routed to the reversible
	// http_claimed_bot_unverified check instead of a hard block, so a real
	// crawler is not blocked during the verification window.
	uaKindClaimedBotPending
	uaKindKnownScanner
	uaKindWPSpoofPingback
	uaKindScriptingLang
	uaKindHeadless
	uaKindEmpty
)

// botClassifier decides whether the source IP is a known verified bot
// the detector should NOT count or flag. Returns true to skip. The
// real implementation lives in internal/threatintel; tests use the
// nopBotClassifier below.
type botClassifier interface {
	IsVerifiedBot(ip string, ua string) bool
}

type confirmedNegativeBotClassifier interface {
	ConfirmedNegative(ip, ua string) bool
}

type pendingBotVerificationClassifier interface {
	VerificationPending(ip, ua string) bool
}

type nopBotClassifier struct{}

func (nopBotClassifier) IsVerifiedBot(string, string) bool { return false }

// httpSample is one representative request kept per IP for forensic
// display in the finding Details field. First-seen wins; subsequent
// requests increment counters only.
type httpSample struct {
	Method string
	URI    string
	UA     string
}

// domlogStats is the per-scan aggregator. One instance per CheckWPBruteForce
// invocation. Every counter is map[ip] -> int so emit can produce findings
// per source IP without a second pass.
type domlogStats struct {
	wpLogin  map[string]int
	xmlrpc   map[string]int
	userEnum map[string]int
	httpReqs map[string]int
	uaCat    map[string]map[uaKind]int
	samples  map[string]httpSample
	// domains tracks the set of distinct vhosts each IP touched, so the
	// per-IP aggregate findings can report cross-site spread (one IP
	// scanning many vhosts on a shared host). Empty-domain records (the
	// central access log) do not contribute.
	domains map[string]map[string]struct{}
	// abuseDomains tracks the in-window vhosts where each source made the
	// request shape for a specific HTTP-abuse finding. The distributed
	// rollup uses this instead of all in-window touches so an IP that was
	// abusive elsewhere cannot make a normal hit count against a vhost.
	abuseDomains map[string]map[string]map[string]struct{}
	// scannerErr counts in-window non-asset requests per IP whose status
	// matched the configured probe-error set. scannerReqs is the matching
	// denominator, so the two counters must be gated by the same window
	// check and the same display-asset exclusion.
	scannerErr map[string]int
	// scannerReqs is the per-IP scanner-profile denominator: in-window
	// requests excluding static display assets (see isDisplayAssetProbe),
	// so broken images, styles, scripts, and fonts neither dilute the
	// error rate nor pad the volume gate. Separate from httpReqs so the
	// flood detector's denominator is unchanged.
	scannerReqs map[string]int
	// scannerPaths is the distinct error-status path set per IP, query
	// strings stripped, capped at httpScannerMaxTrackedPaths to bound
	// memory under a flood of unique probe URLs.
	scannerPaths map[string]map[string]struct{}
	// scannerSamples keeps the first error-status request per IP for the
	// finding Details field; the generic samples map can hold a 200 hit.
	scannerSamples map[string]httpSample
	// scannerDomainReqs and friends track the scanner profile per vhost so
	// the distributed rollup only attributes a source to domains where the
	// scanner shape actually crossed the detector gates. scannerDomainReqs is
	// flat-keyed by ip+"\x00"+domain so a busy host's tens of thousands of
	// one-off client IPs do not each allocate a nested map that the gates only
	// read for the few IPs with errors.
	scannerDomainReqs map[string]int
	scannerDomainErr  map[string]map[string]int
	scanTime          time.Time

	// asnCrawl accumulates per-(scope, ASN) crawl fingerprints. Populated by
	// observeASNCrawl from scan(); read by emitASNCrawl. Lazily allocated.
	asnCrawl map[string]*asnCrawlScope

	// Scanner thresholds are derived from cfg once per scan -- cfg is stable
	// across a single domlogStats lifetime -- instead of on every parsed record.
	scannerThreshComputed bool
	scannerMinReq         int
	scannerPct            int
	scannerMinPaths       int
	scannerEnabled        bool
}

func newDomlogStats() *domlogStats {
	return newDomlogStatsAt(time.Now())
}

func newDomlogStatsAt(t time.Time) *domlogStats {
	return &domlogStats{
		wpLogin:           make(map[string]int),
		xmlrpc:            make(map[string]int),
		userEnum:          make(map[string]int),
		httpReqs:          make(map[string]int),
		uaCat:             make(map[string]map[uaKind]int),
		samples:           make(map[string]httpSample),
		domains:           make(map[string]map[string]struct{}),
		abuseDomains:      make(map[string]map[string]map[string]struct{}),
		scannerErr:        make(map[string]int),
		scannerReqs:       make(map[string]int),
		scannerPaths:      make(map[string]map[string]struct{}),
		scannerSamples:    make(map[string]httpSample),
		scannerDomainReqs: make(map[string]int),
		scannerDomainErr:  make(map[string]map[string]int),
		scanTime:          t,
	}
}

// scan updates counters for one parsed record. cfg is allowed to be nil
// at Task 1 (parity tests pass nil); later tasks read thresholds from
// it. bot is consulted before any count so a verified Googlebot does
// not contribute to either legacy or new metrics.
func (s *domlogStats) scan(rec accessLogRecord, cfg *config.Config, bot botClassifier) {
	ip := normalizeHTTPClientIP(clientIPForRecord(rec, cfg))
	if ip == "" {
		return
	}
	if cfg != nil && isInfraIP(ip, cfg.InfraIPs) {
		return
	}
	if bot != nil && bot.IsVerifiedBot(ip, rec.UserAgent) {
		removeChallengeIP(ip)
		return
	}

	wpLoginHit := rec.Method == "POST" && strings.Contains(rec.URI, "wp-login.php")
	xmlrpcHit := rec.Method == "POST" && strings.Contains(rec.URI, "xmlrpc.php")
	userEnumHit := false
	if rec.Method == "POST" {
		if wpLoginHit {
			s.wpLogin[ip]++
		}
		if xmlrpcHit {
			s.xmlrpc[ip]++
		}
	}
	if strings.Contains(rec.URI, "?author=") {
		s.userEnum[ip]++
		userEnumHit = true
	} else if strings.Contains(rec.URI, "/wp-json/wp/v2/users") &&
		!strings.Contains(rec.URI, "/users/me") {
		s.userEnum[ip]++
		userEnumHit = true
	}

	// Rate and UA counters only fire for requests that fall inside the
	// flood window. Malformed timestamp lines still feed the legacy POST
	// counters above but not rate or UA findings.
	if withinHTTPFloodWindow(rec.Time, cfg, s.scanTime) {
		if rec.Domain != "" {
			set := s.domains[ip]
			if set == nil {
				set = make(map[string]struct{})
				s.domains[ip] = set
			}
			set[rec.Domain] = struct{}{}
			if wpLoginHit {
				s.recordAbuseDomain("wp_login_bruteforce", ip, rec.Domain)
			}
			if xmlrpcHit {
				s.recordAbuseDomain("xmlrpc_abuse", ip, rec.Domain)
			}
			if userEnumHit {
				s.recordAbuseDomain("wp_user_enumeration", ip, rec.Domain)
			}
			s.recordAbuseDomain("http_request_flood", ip, rec.Domain)
		}
		if _, ok := s.samples[ip]; !ok {
			s.samples[ip] = httpSample{Method: rec.Method, URI: rec.URI, UA: rec.UserAgent}
		}
		s.httpReqs[ip]++

		if asnCrawlWithinWindow(rec.Time, cfg, s.scanTime) {
			s.observeASNCrawl(ip, rec, cfg)
		}

		_, _, _, scannerEnabled := s.scannerThresholds(cfg)
		// Static display assets (images, styles, scripts, fonts, media)
		// are excluded from the scanner profile entirely: a 404 on a
		// browser sub-resource is a broken-asset signal, not URL
		// enumeration. Dropping them from both the numerator (scannerErr)
		// and the denominator (scannerReqs) stops a site with a missing
		// CDN from making ordinary visitors look like scanners, without
		// blinding the profile to real probes in the same window.
		if scannerEnabled && !isDisplayAssetProbe(rec.URI) {
			s.scannerReqs[ip]++
			if rec.Domain != "" {
				s.recordScannerDomainRequest(ip, rec.Domain)
			}
			if isScannerErrorStatus(rec.Status, cfg.Thresholds.HTTPScannerStatusCodes) {
				path := probePath(rec.URI)
				s.scannerErr[ip]++
				if _, ok := s.scannerSamples[ip]; !ok {
					s.scannerSamples[ip] = httpSample{Method: rec.Method, URI: rec.URI, UA: rec.UserAgent}
				}
				paths := s.scannerPaths[ip]
				if paths == nil {
					paths = make(map[string]struct{})
					s.scannerPaths[ip] = paths
				}
				if len(paths) < httpScannerMaxTrackedPaths {
					paths[path] = struct{}{}
				}
				if rec.Domain != "" {
					s.recordScannerDomainError(ip, rec.Domain)
				}
			}
		}

		kind := classifyUA(rec.UserAgent, rec.Method)
		if kind == uaKindClaimedBot {
			// Static allowlist hits returned early through IsVerifiedBot
			// above. For IPs outside the static range, check whether the
			// async rDNS verifier has confirmed a negative result. Only
			// promote to uaKindClaimedBotNegative when the cache has a
			// definitive negative. The reversible pending-bot route is only
			// safe when an active verifier can resolve the cache miss later;
			// static-only/no-verifier paths keep the old flood/scanner
			// behavior instead of softening spoofed bot UAs forever.
			if cv, ok := bot.(confirmedNegativeBotClassifier); ok && cv.ConfirmedNegative(ip, rec.UserAgent) {
				kind = uaKindClaimedBotNegative
			} else if pv, ok := bot.(pendingBotVerificationClassifier); ok && pv.VerificationPending(ip, rec.UserAgent) {
				// Verification still pending: not a confirmed spoof, so do not
				// flag ua_spoof. Tracked separately so a flood/scan crawl from
				// this IP routes to the reversible challenge, not a hard block.
				kind = uaKindClaimedBotPending
			} else {
				kind = uaKindBrowser
			}
		}
		if _, ok := s.uaCat[ip]; !ok {
			s.uaCat[ip] = make(map[uaKind]int)
		}
		s.uaCat[ip][kind]++
		if rec.Domain != "" && kind != uaKindBrowser && kind != uaKindClaimedBotPending {
			s.recordAbuseDomain("http_ua_spoof", ip, rec.Domain)
		}
	}
}

func (s *domlogStats) recordAbuseDomain(check, ip, domain string) {
	byIP := s.abuseDomains[check]
	if byIP == nil {
		byIP = make(map[string]map[string]struct{})
		s.abuseDomains[check] = byIP
	}
	set := byIP[ip]
	if set == nil {
		set = make(map[string]struct{})
		byIP[ip] = set
	}
	set[domain] = struct{}{}
}

// scannerDomainKey joins an IP and a domain into the flat scannerDomainReqs
// key. The NUL separator cannot appear in either part, so distinct (ip,domain)
// pairs never collide.
func scannerDomainKey(ip, domain string) string {
	return ip + "\x00" + domain
}

// scannerThresholds returns the scanner-profile gates derived from cfg, caching
// them on first use. cfg does not change across a single scan, so this avoids
// re-deriving the thresholds on every parsed access-log record.
func (s *domlogStats) scannerThresholds(cfg *config.Config) (minReq, pct, minPaths int, ok bool) {
	if !s.scannerThreshComputed {
		s.scannerMinReq, s.scannerPct, s.scannerMinPaths, s.scannerEnabled = scannerProfileThresholds(cfg)
		s.scannerThreshComputed = true
	}
	return s.scannerMinReq, s.scannerPct, s.scannerMinPaths, s.scannerEnabled
}

func (s *domlogStats) recordScannerDomainRequest(ip, domain string) {
	s.scannerDomainReqs[scannerDomainKey(ip, domain)]++
}

func (s *domlogStats) recordScannerDomainError(ip, domain string) {
	byDomain := s.scannerDomainErr[ip]
	if byDomain == nil {
		byDomain = make(map[string]int)
		s.scannerDomainErr[ip] = byDomain
	}
	byDomain[domain]++
}

// emitLegacy returns the three pre-existing finding kinds. Kept
// separate from the new emit() (Tasks 3/4) so the parity test can
// assert "no new findings yet".
func (s *domlogStats) emitLegacy(_ *config.Config) []alert.Finding {
	var out []alert.Finding
	for ip, count := range s.wpLogin {
		if count >= wpLoginThreshold {
			out = append(out, alert.Finding{
				Severity: alert.Critical,
				Check:    "wp_login_bruteforce",
				SourceIP: ip,
				Message:  formatLegacyMessage("WordPress login brute force", ip, count, "attempts"),
				Details:  "Aggregated across per-vhost access logs",
			})
		}
	}
	for ip, count := range s.xmlrpc {
		if count >= xmlrpcThreshold {
			out = append(out, alert.Finding{
				Severity: alert.Critical,
				Check:    "xmlrpc_abuse",
				SourceIP: ip,
				Message:  formatLegacyMessage("XML-RPC abuse", ip, count, "requests"),
				Details:  "Aggregated across per-vhost access logs",
			})
		}
	}
	for ip, count := range s.userEnum {
		if count >= 5 {
			out = append(out, alert.Finding{
				Severity: alert.High,
				Check:    "wp_user_enumeration",
				SourceIP: ip,
				Message:  formatLegacyMessage("WordPress user enumeration", ip, count, "requests"),
				Details:  "Requests to /wp-json/wp/v2/users or ?author=",
			})
		}
	}
	return out
}

// emit produces all finding kinds from a single populated domlogStats.
// Legacy three kinds come first (so existing callers still get them when
// running through emit), then http_request_flood, then http_ua_spoof.
func (s *domlogStats) emit(cfg *config.Config) []alert.Finding {
	out := s.emitLegacy(cfg)

	if cfg != nil && cfg.Thresholds.HTTPFloodThreshold > 0 {
		for ip, count := range s.httpReqs {
			if count < cfg.Thresholds.HTTPFloodThreshold {
				continue
			}
			if s.isPendingClaimedBot(ip) {
				// Routed to http_claimed_bot_unverified (challenge) below so a
				// real crawler mid-verification is not hard-blocked.
				continue
			}
			sample := s.samples[ip]
			out = append(out, alert.Finding{
				Severity: alert.High,
				Check:    "http_request_flood",
				SourceIP: ip,
				Domain:   s.singleDomain(ip),
				Message:  "HTTP request flood from " + ip + ": " + itoa(count) + " requests" + s.vhostSuffix(ip),
				Details:  "Sample: " + sample.Method + " " + sample.URI + " UA=" + truncate(sample.UA, 120),
			})
		}
	}

	if cfg != nil {
		threshold := cfg.Thresholds.HTTPUASpoofThreshold
		if threshold <= 0 {
			threshold = 30
		}
		for ip, byKind := range s.uaCat {
			if hits, ok := byKind[uaKindClaimedBotNegative]; ok && hits > 0 {
				out = append(out, s.makeUASpoofFinding(ip,
					"claimed search-engine bot failed rDNS verification",
					s.samples[ip], hits))
				continue
			}
			if hits, ok := byKind[uaKindKnownScanner]; ok && hits > 0 {
				out = append(out, s.makeUASpoofFinding(ip, "known scanner UA",
					s.samples[ip], hits))
				continue
			}
			if hits := byKind[uaKindWPSpoofPingback]; hits >= threshold {
				out = append(out, s.makeUASpoofFinding(ip,
					"WordPress/<ver> UA on GET (pingback spoof)",
					s.samples[ip], hits))
				continue
			}
			if cfg.Thresholds.HTTPUAScriptingEnabled {
				if hits := byKind[uaKindScriptingLang]; hits >= threshold {
					out = append(out, s.makeUASpoofFinding(ip,
						"scripting-language UA (curl/python/etc.)",
						s.samples[ip], hits))
					continue
				}
			}
			if cfg.Thresholds.HTTPUAHeadlessEnabled {
				if hits := byKind[uaKindHeadless]; hits >= threshold {
					out = append(out, s.makeUASpoofFinding(ip,
						"headless browser UA", s.samples[ip], hits))
					continue
				}
			}
			if cfg.Thresholds.HTTPUAEmptyEnabled {
				if hits := byKind[uaKindEmpty]; hits >= threshold {
					out = append(out, s.makeUASpoofFinding(ip,
						"empty/dash User-Agent", s.samples[ip], hits))
					continue
				}
			}
		}
	}

	out = append(out, s.emitScannerProfile(cfg)...)
	out = append(out, s.emitClaimedBotUnverified(cfg)...)

	// Distributed attack: many distinct abusive IPs hitting one vhost.
	// Built from the per-IP findings already emitted above, so only IPs
	// that crossed an abuse threshold count -- a popular site's normal
	// visitor spread never trips it.
	out = append(out, s.emitDistributedFlood(cfg, out)...)
	return out
}

// httpScannerMaxTrackedPaths bounds the per-IP distinct probe-path set.
// A scanner cycling unique URLs past the cap keeps incrementing the
// error counter, and any sane min_distinct_paths threshold sits far
// below the cap, so detection quality does not depend on growth beyond it.
const httpScannerMaxTrackedPaths = config.HTTPScannerMaxDistinctPaths

// emitScannerProfile produces http_scanner_profile findings: source IPs
// whose in-window traffic is almost entirely probe-error responses spread
// across many distinct paths -- the shape of URL enumeration for
// downloadable files, exposed backups, and dormant shells. Volume,
// error-rate, and path-breadth gates must all pass so that dead
// bookmarks, broken assets, and site migrations stay out of scope.
func (s *domlogStats) emitScannerProfile(cfg *config.Config) []alert.Finding {
	minReq, pct, minPaths, ok := s.scannerThresholds(cfg)
	if !ok {
		return nil
	}
	var out []alert.Finding
	for ip, errs := range s.scannerErr {
		total := s.scannerReqs[ip]
		paths := len(s.scannerPaths[ip])
		if !scannerProfilePasses(total, errs, paths, minReq, pct, minPaths) {
			continue
		}
		if s.isPendingClaimedBot(ip) {
			// Routed to http_claimed_bot_unverified (challenge) instead of a
			// hard scanner-profile block while verification is pending.
			continue
		}
		for _, domain := range s.scannerProfileDomains(ip, minReq, pct) {
			s.recordAbuseDomain("http_scanner_profile", ip, domain)
		}
		sample := s.scannerSamples[ip]
		out = append(out, alert.Finding{
			Severity: alert.High,
			Check:    "http_scanner_profile",
			SourceIP: ip,
			Domain:   s.singleDomain(ip),
			Message: "URL scanner profile from " + ip + ": " + itoa(errs) + " of " + itoa(total) +
				" requests hit probe-error statuses across " + itoa(paths) + " distinct paths" + s.vhostSuffix(ip),
			Details: "Sample: " + sample.Method + " " + sample.URI + " UA=" + truncate(sample.UA, 120),
		})
	}
	return out
}

// isPendingClaimedBot reports whether ip's in-window traffic is dominated by a
// claimed-bot UA whose rDNS verification has not resolved. The claimed-bot
// requests must be a strict majority so an attacker cannot downgrade a hard
// block to the softer challenge route by mixing in bot-UA requests.
func (s *domlogStats) isPendingClaimedBot(ip string) bool {
	pending := s.uaCat[ip][uaKindClaimedBotPending]
	if pending == 0 {
		return false
	}
	return pending*2 > s.httpReqs[ip]
}

// emitClaimedBotUnverified emits one http_claimed_bot_unverified finding per
// pending-claimed-bot IP whose flood or scanner-profile volume crossed a hard
// threshold. The check is challengeable (routes to the PoW gate when challenge
// is enabled) and blockable (hard-blocked when it is not), so a real crawler
// mid-verification clears itself while a spoofer that cannot solve the
// challenge stays blocked.
func (s *domlogStats) emitClaimedBotUnverified(cfg *config.Config) []alert.Finding {
	if cfg == nil {
		return nil
	}
	minReq, pct, minPaths, scannerOK := s.scannerThresholds(cfg)
	floodThreshold := cfg.Thresholds.HTTPFloodThreshold
	var out []alert.Finding
	for ip := range s.uaCat {
		if !s.isPendingClaimedBot(ip) {
			continue
		}
		total := s.httpReqs[ip]
		flood := floodThreshold > 0 && total >= floodThreshold
		scanner := scannerOK && scannerProfilePasses(s.scannerReqs[ip], s.scannerErr[ip], len(s.scannerPaths[ip]), minReq, pct, minPaths)
		if !flood && !scanner {
			continue
		}
		reason := "request flood"
		sample := s.samples[ip]
		if scanner && !flood {
			reason = "scanner-profile crawl"
			sample = s.scannerSamples[ip]
		}
		s.recordClaimedBotUnverifiedDomains(ip, flood, scanner, minReq, pct)
		out = append(out, alert.Finding{
			Severity: alert.High,
			Check:    "http_claimed_bot_unverified",
			SourceIP: ip,
			Domain:   s.singleDomain(ip),
			Message: "Unverified claimed bot from " + ip + ": " + reason + " (" + itoa(total) +
				" requests, rDNS not yet confirmed)" + s.vhostSuffix(ip),
			Details: "Sample: " + sample.Method + " " + sample.URI + " UA=" + truncate(sample.UA, 120),
		})
	}
	return out
}

func (s *domlogStats) recordClaimedBotUnverifiedDomains(ip string, flood, scanner bool, minReq, pct int) {
	if flood {
		for domain := range s.abuseDomains["http_request_flood"][ip] {
			s.recordAbuseDomain("http_claimed_bot_unverified", ip, domain)
		}
	}
	if scanner {
		for _, domain := range s.scannerProfileDomains(ip, minReq, pct) {
			s.recordAbuseDomain("http_claimed_bot_unverified", ip, domain)
		}
	}
}

func scannerProfileThresholds(cfg *config.Config) (minReq, pct, minPaths int, ok bool) {
	if cfg == nil {
		return 0, 0, 0, false
	}
	minReq = cfg.Thresholds.HTTPScannerMinRequests
	if minReq <= 0 {
		return 0, 0, 0, false
	}
	pct = cfg.Thresholds.HTTPScannerErrorPct
	if pct <= 0 {
		pct = config.DefaultHTTPScannerErrorPct
	}
	if pct > 100 {
		pct = 100
	}
	minPaths = cfg.Thresholds.HTTPScannerMinDistinctPaths
	if minPaths <= 0 {
		minPaths = config.DefaultHTTPScannerMinDistinctPaths
	}
	if minPaths > httpScannerMaxTrackedPaths {
		minPaths = httpScannerMaxTrackedPaths
	}
	return minReq, pct, minPaths, true
}

func scannerProfilePasses(total, errs, paths, minReq, pct, minPaths int) bool {
	if total < minReq {
		return false
	}
	if errs*100 < total*pct {
		return false
	}
	return paths >= minPaths
}

// scannerDomainDefaultMinErrors is the small absolute floor of probe-error
// hits a single vhost must receive before a confirmed per-IP scanner is
// attributed to it for the distributed rollup. The per-IP gates (minReq,
// minPaths) already proved the source is a scanner; per vhost we only require
// a few errors plus the same error-rate gate, so a scanner spread thin across
// many vhosts still feeds the rollup while the default scanner thresholds do
// not attribute a vhost that caught one incidental 404.
const scannerDomainDefaultMinErrors = 3

func scannerDomainErrorFloor(minReq int) int {
	if minReq <= 0 {
		return scannerDomainDefaultMinErrors
	}
	if minReq < scannerDomainDefaultMinErrors {
		return minReq
	}
	return scannerDomainDefaultMinErrors
}

// scannerProfileDomains returns the vhosts a confirmed scanner IP should be
// attributed to in the distributed rollup. The full per-IP minimum-request and
// min-path gates are deliberately NOT reused per vhost: a scanner that sprays a
// few probes across many vhosts trips the per-IP profile in aggregate but lands
// only a handful of hits on each vhost, so requiring the per-IP minimums per
// vhost would drop it from the rollup. Instead each vhost needs a small
// absolute error floor and the same error-rate gate.
func (s *domlogStats) scannerProfileDomains(ip string, minReq, pct int) []string {
	errsByDomain := s.scannerDomainErr[ip]
	if len(errsByDomain) == 0 {
		return nil
	}
	var domains []string
	errorFloor := scannerDomainErrorFloor(minReq)
	for domain, errs := range errsByDomain {
		total := s.scannerDomainReqs[scannerDomainKey(ip, domain)]
		if scannerDomainAttributes(total, errs, pct, errorFloor) {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains
}

func scannerDomainAttributes(total, errs, pct, minErrors int) bool {
	if errs < minErrors {
		return false
	}
	return errs*100 >= total*pct
}

// isScannerErrorStatus reports whether status belongs to the configured
// probe-error set. Linear scan: the set is a handful of entries, so this
// beats building a lookup map on a per-record hot path.
func isScannerErrorStatus(status int, codes []int) bool {
	if status == 0 {
		return false
	}
	if len(codes) == 0 {
		return status == 404 || status == 403
	}
	for _, c := range codes {
		if status == c {
			return true
		}
	}
	return false
}

// probePath strips the query string and fragment so cache-buster style
// queries on one missing endpoint count as a single probe path.
func probePath(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	if uri == "" {
		return "/"
	}
	return uri
}

// displayAssetExts are static, browser-rendered sub-resource extensions.
// A 404 on one of these is a broken-asset signal -- the static-file
// handler looked for a file and did not find it, executing no code and
// disclosing nothing -- not URL enumeration. Excluding them keeps a site
// whose CDN is missing its images, styles, or scripts from making every
// ordinary visitor look like a scanner. Archives, code, configs, dumps,
// and extensionless paths -- the targets a real scanner enumerates -- are
// deliberately absent and keep counting toward the profile.
var displayAssetExts = map[string]struct{}{
	".gif": {}, ".jpg": {}, ".jpeg": {}, ".png": {}, ".webp": {}, ".bmp": {},
	".svg": {}, ".ico": {}, ".avif": {}, ".tif": {}, ".tiff": {},
	".css": {}, ".js": {}, ".mjs": {}, ".cjs": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".otf": {},
	".mp4": {}, ".webm": {}, ".ogg": {}, ".mp3": {}, ".wav": {},
	".m4a": {}, ".mov": {}, ".avi": {}, ".flac": {},
}

// scannerProbeExts are extensions commonly used when probing for code,
// configs, source maps, dumps, archives, and backups. If one appears before a
// final display-asset suffix (for example shell.php.gif), the request still
// has scanner shape and must not be hidden by the asset exclusion.
var scannerProbeExts = map[string]struct{}{
	".php": {}, ".phtml": {}, ".phps": {}, ".php3": {}, ".php4": {}, ".php5": {}, ".php7": {},
	".asp": {}, ".aspx": {}, ".ashx": {}, ".asmx": {}, ".jsp": {}, ".jspx": {}, ".cfm": {},
	".cgi": {}, ".pl": {}, ".py": {}, ".rb": {}, ".sh": {}, ".bash": {}, ".zsh": {},
	".env": {}, ".conf": {}, ".config": {}, ".ini": {}, ".yaml": {}, ".yml": {}, ".json": {}, ".xml": {},
	".sql": {}, ".dump": {}, ".db": {}, ".sqlite": {}, ".sqlite3": {}, ".log": {},
	".zip": {}, ".rar": {}, ".7z": {}, ".tar": {}, ".tgz": {}, ".gz": {}, ".bz2": {}, ".xz": {},
	".bak": {}, ".backup": {}, ".old": {}, ".orig": {}, ".save": {}, ".swp": {}, ".tmp": {},
	".map": {},
}

// isDisplayAssetProbe reports whether uri's final path segment ends in one
// of displayAssetExts. The query string and fragment are stripped first so
// a cache-buster suffix cannot hide the extension.
func isDisplayAssetProbe(uri string) bool {
	path := probePath(uri)
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	if unescaped, err := url.PathUnescape(path); err == nil {
		path = unescaped
	}
	dot := strings.LastIndexByte(path, '.')
	if dot <= 0 {
		return false
	}
	if _, ok := displayAssetExts[strings.ToLower(path[dot:])]; !ok {
		return false
	}
	return !hasEmbeddedScannerProbeExt(path[:dot])
}

func hasEmbeddedScannerProbeExt(pathPrefix string) bool {
	parts := strings.Split(strings.ToLower(pathPrefix), ".")
	for _, part := range parts[1:] {
		if part == "" {
			continue
		}
		if _, ok := scannerProbeExts["."+part]; ok {
			return true
		}
	}
	return false
}

// httpAbuseChecks are the per-IP finding kinds that mark a source IP as
// abusive for the distributed-attack rollup.
var httpAbuseChecks = map[string]struct{}{
	"wp_login_bruteforce":         {},
	"xmlrpc_abuse":                {},
	"wp_user_enumeration":         {},
	"http_request_flood":          {},
	"http_claimed_bot_unverified": {},
	"http_ua_spoof":               {},
	"http_scanner_profile":        {},
}

// emitDistributedFlood rolls the per-IP HTTP-abuse findings up per vhost:
// when at least HTTPDistributedMinIPs distinct abusive IPs hit one vhost
// in this window, it emits a single http_distributed_flood finding for
// that vhost. The per-IP findings still stand; this adds the
// many-IPs-one-target view (botnet / distributed brute-force) that the
// per-IP and per-source-IP-spray paths cannot see. Disabled when the
// threshold is <= 0.
func (s *domlogStats) emitDistributedFlood(cfg *config.Config, prior []alert.Finding) []alert.Finding {
	if cfg == nil {
		return nil
	}
	minIPs := cfg.Thresholds.HTTPDistributedMinIPs
	if minIPs <= 0 {
		return nil
	}
	domainIPs := map[string]map[string]struct{}{}
	for _, f := range prior {
		if _, ok := httpAbuseChecks[f.Check]; !ok || f.SourceIP == "" {
			continue
		}
		for dom := range s.abuseDomains[f.Check][f.SourceIP] {
			if domainIPs[dom] == nil {
				domainIPs[dom] = map[string]struct{}{}
			}
			domainIPs[dom][f.SourceIP] = struct{}{}
		}
	}
	domains := make([]string, 0, len(domainIPs))
	for dom := range domainIPs {
		domains = append(domains, dom)
	}
	sort.Strings(domains)
	var out []alert.Finding
	for _, dom := range domains {
		n := len(domainIPs[dom])
		if n < minIPs {
			continue
		}
		out = append(out, alert.Finding{
			Severity: alert.High,
			Check:    "http_distributed_flood",
			Domain:   dom,
			Message:  fmt.Sprintf("Distributed HTTP attack on %s: %d distinct abusive source IPs", dom, n),
			Details: fmt.Sprintf("%d source IPs each tripped an HTTP-abuse threshold against %s in this window. "+
				"Likely a botnet or distributed brute-force; consider edge rate-limiting or a challenge.", n, dom),
			Timestamp: time.Now(),
		})
	}
	return out
}

func (s *domlogStats) makeUASpoofFinding(ip, reason string, sample httpSample, hits int) alert.Finding {
	return alert.Finding{
		Severity: alert.Critical,
		Check:    "http_ua_spoof",
		SourceIP: ip,
		Domain:   s.singleDomain(ip),
		Message:  "User-Agent spoof from " + ip + ": " + reason + s.vhostSuffix(ip),
		Details: "Hits: " + itoa(hits) + ", Sample: " + sample.Method + " " +
			sample.URI + " UA=" + truncate(sample.UA, 200),
	}
}

// singleDomain returns the one vhost ip touched, or "" when zero or more
// than one (the per-IP aggregate spans several vhosts, so no single domain
// attributes the finding). vhostSuffix renders the cross-site spread for
// the operator-facing message.
func (s *domlogStats) singleDomain(ip string) string {
	set := s.domains[ip]
	if len(set) != 1 {
		return ""
	}
	for d := range set {
		return d
	}
	return ""
}

func (s *domlogStats) vhostSuffix(ip string) string {
	if n := len(s.domains[ip]); n > 1 {
		return " across " + itoa(n) + " vhosts"
	}
	return ""
}

// withinHTTPFloodWindow reports whether a log timestamp falls inside the
// configured flood rate window relative to the scan start time. Timestamps
// in the future (up to one clock-skew minute) are accepted. Zero timestamps
// from malformed lines return false so they do not contribute to rate counts.
func withinHTTPFloodWindow(ts time.Time, cfg *config.Config, now time.Time) bool {
	if ts.IsZero() || cfg == nil {
		return false
	}
	windowMin := cfg.Thresholds.HTTPFloodWindowMin
	if windowMin <= 0 {
		windowMin = 5
	}
	cutoff := now.Add(-time.Duration(windowMin) * time.Minute)
	return !ts.Before(cutoff) && !ts.After(now.Add(time.Minute))
}

func formatLegacyMessage(kind, ip string, n int, unit string) string {
	return kind + " from " + ip + ": " + itoa(n) + " " + unit
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// parseAccessLogRecord parses one Combined Log Format line into an
// accessLogRecord. It does NOT use strings.Fields because quoted
// request/referer/user-agent fields can contain spaces.
//
// Format:
//
//	<ip> <ident> <user> [<time>] "<method> <uri> <proto>" <status> <bytes> "<ref>" "<ua>" ["<vhost>"]
//
// Returns ok=false for any line that cannot be parsed. Never panics.
func parseAccessLogRecord(line string) (accessLogRecord, bool) {
	const maxUALen = 512
	const maxURILen = 4096

	var rec accessLogRecord
	// IP is everything up to the first space.
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return rec, false
	}
	rec.RemoteIP = line[:sp]
	rest := line[sp+1:]

	// Skip ident, user (two single-token fields). Loose: we just need to
	// land at the [time] bracket.
	br := strings.IndexByte(rest, '[')
	if br < 0 {
		return rec, false
	}
	rest = rest[br+1:]
	closeBr := strings.IndexByte(rest, ']')
	if closeBr < 0 {
		return rec, false
	}
	timeStr := rest[:closeBr]
	rest = rest[closeBr+1:]
	// time format: 02/Jan/2006:15:04:05 -0700
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
	if err == nil {
		rec.Time = t
	}

	// Request quoted field.
	q1 := strings.IndexByte(rest, '"')
	if q1 < 0 {
		return rec, false
	}
	rest = rest[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return rec, false
	}
	request := rest[:q2]
	rest = rest[q2+1:]
	parts := strings.SplitN(request, " ", 3)
	if len(parts) >= 1 {
		rec.Method = parts[0]
	}
	if len(parts) >= 2 {
		uri := parts[1]
		if len(uri) > maxURILen {
			uri = uri[:maxURILen]
		}
		rec.URI = uri
	}

	// status (skip leading spaces)
	rest = strings.TrimLeft(rest, " ")
	end := strings.IndexByte(rest, ' ')
	if end > 0 {
		rec.Status = atoiSafe(rest[:end])
		rest = rest[end+1:]
	}

	// bytes field -- skip leading spaces then advance past the token
	rest = strings.TrimLeft(rest, " ")
	end = strings.IndexByte(rest, ' ')
	if end > 0 {
		rest = rest[end+1:]
	} else {
		// no more fields after bytes
		return rec, true
	}

	// referer quoted field (skipped).
	q1 = strings.IndexByte(rest, '"')
	if q1 < 0 {
		return rec, false
	}
	rest = rest[q1+1:]
	q2 = strings.IndexByte(rest, '"')
	if q2 < 0 {
		return rec, false
	}
	rest = rest[q2+1:]

	// UA quoted field.
	q1 = strings.IndexByte(rest, '"')
	if q1 < 0 {
		return rec, true // no UA present is fine
	}
	rest = rest[q1+1:]
	q2 = strings.IndexByte(rest, '"')
	if q2 < 0 {
		return rec, false
	}
	ua := rest[:q2]
	if len(ua) > maxUALen {
		ua = ua[:maxUALen]
	}
	rec.UserAgent = ua
	rest = rest[q2+1:]

	// Optional quoted extensions. cPanel may append a quoted vhost after
	// UA. Custom proxy formats may append an X-Forwarded-For value. Only
	// retain a quoted extension that parses as an IP list; clientIPForRecord
	// still ignores it unless RemoteIP is a configured trusted proxy.
	for {
		q1 = strings.IndexByte(rest, '"')
		if q1 < 0 {
			break
		}
		rest = rest[q1+1:]
		q2 = strings.IndexByte(rest, '"')
		if q2 < 0 {
			return rec, false
		}
		extra := rest[:q2]
		if looksLikeXFF(extra) {
			rec.XFF = extra
		}
		rest = rest[q2+1:]
	}

	return rec, true
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func clientIPForRecord(rec accessLogRecord, cfg *config.Config) string {
	if cfg == nil || len(cfg.WebServer.TrustedProxies) == 0 || rec.XFF == "" {
		return rec.RemoteIP
	}
	if !isTrustedProxy(rec.RemoteIP, cfg.WebServer.TrustedProxies) {
		return rec.RemoteIP
	}
	// A trusted direct proxy appends the peer it observed to the end of
	// X-Forwarded-For. Use that entry only; earlier entries can come from
	// the client.
	parts := strings.Split(rec.XFF, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if net.ParseIP(ip) == nil {
			continue
		}
		return ip
	}
	return rec.RemoteIP
}

func normalizeHTTPClientIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// isTrustedProxy returns true when addr matches any entry in proxies (exact
// IP or CIDR). Entries that fail to parse are skipped.
func isTrustedProxy(addr string, proxies []string) bool {
	addr = strings.TrimSpace(addr)
	parsed := net.ParseIP(addr)
	if parsed == nil {
		return false
	}
	for _, entry := range proxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil && ip.Equal(parsed) {
			return true
		}
	}
	return false
}

func looksLikeXFF(raw string) bool {
	for _, part := range strings.Split(raw, ",") {
		if net.ParseIP(strings.TrimSpace(part)) != nil {
			return true
		}
	}
	return false
}

// classifyUA maps a User-Agent string to a uaKind. Matching is performed
// on a lower-cased copy of the UA because scanner and impersonation tools
// routinely vary case. Precedence order follows spec section 6: scanner
// signatures win over claimed-bot, claimed-bot wins over headless, etc.
func classifyUA(ua, method string) uaKind {
	const maxUALen = 512
	if len(ua) > maxUALen {
		ua = ua[:maxUALen]
	}
	if ua == "" || ua == "-" {
		return uaKindEmpty
	}
	low := strings.ToLower(ua)

	for _, s := range knownScannerSubstrings {
		if strings.Contains(low, s) {
			return uaKindKnownScanner
		}
	}
	// WordPress pingback UA on a GET request is illegal: legitimate
	// pingback clients always POST. A GET with this UA is a content
	// scraper or probe spoofing the pingback agent.
	if method == "GET" && strings.HasPrefix(low, "wordpress/") {
		return uaKindWPSpoofPingback
	}
	for _, s := range claimedBotSubstrings {
		if strings.Contains(low, s) {
			return uaKindClaimedBot
		}
	}
	// Operator-configured bots (reputation.verified_bots) classify as
	// claimed bots too, so an impostor reusing the UA is caught as a spoof.
	if threatintel.OperatorBotFromUA(low) != "" {
		return uaKindClaimedBot
	}
	for _, s := range headlessSubstrings {
		if strings.Contains(low, s) {
			return uaKindHeadless
		}
	}
	for _, s := range scriptingSubstrings {
		if strings.Contains(low, s) {
			return uaKindScriptingLang
		}
	}
	return uaKindBrowser
}

var (
	knownScannerSubstrings = []string{
		"nikto", "sqlmap", "acunetix", "nmap ", "masscan", "wpscan",
		"nuclei", "dirbuster", "gobuster", "feroxbuster",
	}
	claimedBotSubstrings = []string{
		"googlebot", "bingbot", "applebot", "duckduckbot", "yandexbot",
		"baiduspider", "facebookexternalhit", "twitterbot",
		// Appendix A bots plus AI crawlers verified by published ranges.
		"amazonbot", "gptbot", "chatgpt-user", "oai-searchbot",
		"claudebot", "claude-user", "claude-searchbot",
		"perplexitybot", "meta-externalagent", "meta-webindexer", "bravebot",
		"seranking",
	}
	headlessSubstrings = []string{
		"headlesschrome", "phantomjs", "puppeteer", "playwright",
	}
	scriptingSubstrings = []string{
		"python-requests/", "curl/", "go-http-client/", "java/", "wget/",
		"libwww-perl/", "node-fetch/",
	}
)

// staticAllowlistClassifier consults only DNS-free bot verification: embedded
// static IP ranges and operator-configured IP ranges. rDNS verification for
// IPs outside those ranges is handled by verifyingClassifier.
type staticAllowlistClassifier struct{}

func (staticAllowlistClassifier) IsVerifiedBot(ipStr, ua string) bool {
	bot := threatintel.ClaimedBotFromUA(ua)
	if bot == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if threatintel.DefaultRanges().IPInBot(ip, bot) {
		return true
	}
	return threatintel.OperatorBotIPVerified(bot, ip)
}

// verifyingClassifier consults the static allowlist first, then the
// rDNS verify cache. Cache misses enqueue an async job and return
// false (treat as unverified for this scan cycle).
type verifyingClassifier struct {
	async    *threatintel.AsyncBotVerifier
	cacheGet func(net.IP, string) (bool, bool)
}

func newVerifyingClassifier(async *threatintel.AsyncBotVerifier,
	cacheGet func(net.IP, string) (bool, bool)) verifyingClassifier {
	return verifyingClassifier{async: async, cacheGet: cacheGet}
}

func (c verifyingClassifier) IsVerifiedBot(ipStr, ua string) bool {
	bot := threatintel.ClaimedBotFromUA(ua)
	if bot == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Static range is the fast positive path.
	if threatintel.DefaultRanges().IPInBot(ip, bot) {
		return true
	}
	// Operator IP-range bots (AI agents) verify synchronously, no rDNS.
	if threatintel.OperatorBotIPVerified(bot, ip) {
		return true
	}
	// Cache lookup: valid positive -> verified, valid negative -> false
	// (ConfirmedNegative handles it), no entry -> enqueue and fail open.
	if c.cacheGet != nil {
		if verified, valid := c.cacheGet(ip, bot); valid {
			return verified
		}
	}
	// Enqueue async verification only when a later scan can read the result;
	// otherwise there is no bounded pending window to route through challenge.
	if c.async != nil && c.cacheGet != nil {
		c.async.Enqueue(ip, bot)
	}
	return false
}

// ConfirmedNegative reports whether the rDNS cache has a definitive
// negative result for this IP+UA pair. Called from scan() to decide
// whether to promote uaKindClaimedBot to uaKindClaimedBotNegative.
func (c verifyingClassifier) ConfirmedNegative(ipStr, ua string) bool {
	bot := threatintel.ClaimedBotFromUA(ua)
	if bot == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || c.cacheGet == nil {
		return false
	}
	verified, valid := c.cacheGet(ip, bot)
	return valid && !verified
}

func (c verifyingClassifier) VerificationPending(ipStr, ua string) bool {
	bot := threatintel.ClaimedBotFromUA(ua)
	if bot == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || c.async == nil || c.cacheGet == nil {
		return false
	}
	if threatintel.DefaultRanges().IPInBot(ip, bot) || threatintel.OperatorBotIPVerified(bot, ip) {
		return false
	}
	if _, valid := c.cacheGet(ip, bot); valid {
		return false
	}
	return true
}

var (
	globalBotVerifier *threatintel.AsyncBotVerifier
	globalBotGet      func(net.IP, string) (bool, bool)
	botMu             sync.RWMutex
)

// SetBotVerifier installs the daemon-lifetime async verifier and cache
// reader. Called from daemon.go after the store and goroutine are ready.
func SetBotVerifier(v *threatintel.AsyncBotVerifier, get func(net.IP, string) (bool, bool)) {
	botMu.Lock()
	defer botMu.Unlock()
	globalBotVerifier = v
	globalBotGet = get
}

// currentBotClassifier returns the appropriate botClassifier based on
// config. When bot_verify_enabled is false, falls back to the
// static-only classifier so DNS calls are never made.
func currentBotClassifier(cfg *config.Config) botClassifier {
	if cfg == nil || !cfg.BotVerifyEnabled() {
		return staticAllowlistClassifier{}
	}
	botMu.RLock()
	defer botMu.RUnlock()
	return newVerifyingClassifier(globalBotVerifier, globalBotGet)
}
