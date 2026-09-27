package checks

import (
	"slices"
	"time"
)

// Referer classes of a parsed crawl log record, for offline calibration.
const (
	CrawlRefererNone      = "none"
	CrawlRefererMalformed = "malformed"
	CrawlRefererCrossSite = "cross-site"
	CrawlRefererSameSite  = "same-site"
)

// CrawlLogRecord is one domlog line parsed by the crawl detector's record
// parser, for the offline calibration tools. Target and UserAgent carry
// request data: callers derive identities and labels from them and must
// neither store nor print them. The Referer host never leaves this package.
type CrawlLogRecord struct {
	RemoteIP       string
	Time           time.Time
	TimeOK         bool
	Method         string
	Target         string
	TargetOverflow bool
	TargetInvalid  bool
	Status         int
	RefererClass   string
	UserAgent      string
	UAOverflow     bool
	XFF            string
	XFFUnusable    bool
	XFFPartial     bool
}

// ParseCrawlLogLine parses one complete domlog line, its terminal LF or CRLF
// removed, exactly as the crawl detector will. Callers must bound the raw line
// length before parsing. siteHosts contains verified aliases of the line's site:
// lowercase DNS names without a terminal dot, or canonical unmapped IP addresses,
// without ports. An empty list grants no same-site classification.
func ParseCrawlLogLine(line string, siteHosts []string) (CrawlLogRecord, bool) {
	r, ok := parsePatternRecord(line)
	if !ok {
		return CrawlLogRecord{}, false
	}
	out := CrawlLogRecord{
		RemoteIP: r.RemoteIP, Time: r.Time, TimeOK: r.TimeOK, Method: r.Method, Target: r.Target,
		TargetOverflow: r.TargetOverflow, TargetInvalid: r.TargetInvalid, Status: r.Status,
		UserAgent: r.UserAgent, UAOverflow: r.UAOverflow, XFF: r.XFF, XFFUnusable: r.XFFUnusable, XFFPartial: r.XFFPartial,
	}
	// Keep the transient Referer host inside this package, including callbacks.
	switch classifyReferer(r, func(host string) bool { return slices.Contains(siteHosts, host) }) {
	case refClassMalformed:
		out.RefererClass = CrawlRefererMalformed
	case refClassCrossSite:
		out.RefererClass = CrawlRefererCrossSite
	case refClassSameSite:
		out.RefererClass = CrawlRefererSameSite
	default:
		out.RefererClass = CrawlRefererNone
	}
	return out, true
}

// CrawlTargetLimit bounds target bytes after log-escape decoding; a longer
// decoded target is an explicit overflow.
const CrawlTargetLimit = patternMaxTarget
