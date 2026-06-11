// Package intel turns exim_mainlog deferral lines into operator-facing
// reputation signals: which outbound IPs are being throttled, by which mail
// providers, and for what stated reason. It answers "why is the queue backing
// up" without CSM sitting in the mail path -- it only reads the log the MTA
// already writes.
//
// The parser is deliberate about attacker-controlled content: a deferral line
// echoes a remote server's free-text error, so every parsed field is bounded
// and the line is rejected unless it has the exact exim deferral shape.
package intel

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/mailfwd/inventory"
)

// eximTimeLayout is exim_mainlog's default timestamp ("2026-06-07 10:15:23").
const eximTimeLayout = "2006-01-02 15:04:05"

// maxTextLen bounds the stored remote error text so a hostile MTA cannot bloat
// the report with a multi-kilobyte error string.
const (
	maxAddressLen = 254
	maxDomainLen  = 253
	maxHostLen    = 253
	maxIPLen      = 45
	maxTextLen    = 240
)

// Deferral is one parsed exim "==" deferral event.
type Deferral struct {
	Time       time.Time
	Recipient  string
	Domain     string
	Provider   inventory.ProviderClass
	RemoteHost string // the deferring MX (from H=)
	RemoteIP   string // the deferring MX address
	OutboundIP string // this server's sending IP, as echoed in the error, "" if absent
	SMTPCode   string // "421", "" if none
	ReasonCode string // bracketed code (TSS04) or a keyword label (spamhaus, rate_limit)
	Text       string // bounded remote error text
}

var (
	hostBoundaryRe = regexp.MustCompile(`\bH=(\S{1,253})\s+\[([0-9a-fA-F:.]{1,45})\]:\s*`)
	smtpCodeRe     = regexp.MustCompile(`\b([45]\d{2})\b`)
	reasonRe       = regexp.MustCompile(`\[([A-Za-z][A-Za-z0-9]{1,7})\]`)
	ipv4Re         = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	whitespaceR    = regexp.MustCompile(`\s+`)
)

// parseDeferralLine parses one exim_mainlog line. ok is false for anything that
// is not a deferral (delivery "=>", arrival "<=", failure "**", blanks, junk).
func parseDeferralLine(line string) (Deferral, bool) {
	fields := strings.Fields(line)
	// <date> <time> <msgid> == <recipient> ...
	if len(fields) < 5 || fields[3] != "==" {
		return Deferral{}, false
	}

	recipient := strings.Trim(fields[4], "<>")
	if recipient == "" || len(recipient) > maxAddressLen || !strings.Contains(recipient, "@") {
		return Deferral{}, false
	}

	d := Deferral{
		Recipient: recipient,
		Provider:  inventory.ClassifyAddress(recipient),
	}
	if at := strings.LastIndexByte(recipient, '@'); at >= 0 && at < len(recipient)-1 {
		d.Domain = strings.ToLower(recipient[at+1:])
	}
	if d.Domain == "" || len(d.Domain) > maxDomainLen {
		return Deferral{}, false
	}
	if t, err := time.ParseInLocation(eximTimeLayout, fields[0]+" "+fields[1], time.Local); err == nil {
		d.Time = t
	}

	errText := fallbackDeferralText(line)
	canExtractOutboundIP := false
	if m := hostBoundaryRe.FindStringSubmatchIndex(line); m != nil {
		d.RemoteHost = line[m[2]:m[3]]
		d.RemoteIP = parseIPLiteral(line[m[4]:m[5]])
		errText = line[m[1]:]
		canExtractOutboundIP = true
	}

	d.SMTPCode = firstSMTPCode(errText)
	if canExtractOutboundIP {
		d.OutboundIP = firstIPv4(errText)
	}
	d.ReasonCode = classifyReason(errText)
	d.Text = boundText(errText)

	return d, true
}

func fallbackDeferralText(line string) string {
	if i := strings.Index(line, " defer ("); i >= 0 {
		if j := strings.Index(line[i:], "):"); j >= 0 {
			return strings.TrimSpace(line[i+j+2:])
		}
	}
	return line
}

func parseIPLiteral(s string) string {
	if len(s) > maxIPLen {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return s
}

func firstSMTPCode(s string) string {
	for _, m := range smtpCodeRe.FindAllStringSubmatchIndex(s, -1) {
		start, end := m[2], m[3]
		if smtpCodeIsAddressFragment(s, start, end) {
			continue
		}
		return s[start:end]
	}
	return ""
}

func smtpCodeIsAddressFragment(s string, start, end int) bool {
	if start > 0 {
		switch s[start-1] {
		case '.', ':':
			return true
		}
	}
	if end < len(s) {
		switch s[end] {
		case '.', ':':
			return true
		}
	}
	return false
}

// firstIPv4 returns the first syntactically valid IPv4 address in s, or "".
func firstIPv4(s string) string {
	for _, cand := range ipv4Re.FindAllString(s, -1) {
		if ip := net.ParseIP(cand); ip != nil && ip.To4() != nil {
			return cand
		}
	}
	return ""
}

// classifyReason resolves a stable reason token: a bracketed provider code
// (e.g. TSS04) when present, otherwise a keyword label derived from the error
// text. Returns "" when nothing recognizable is found.
func classifyReason(errText string) string {
	for _, m := range reasonRe.FindAllStringSubmatch(errText, -1) {
		if validReasonCode(m[1]) {
			return m[1]
		}
	}
	low := strings.ToLower(errText)
	switch {
	case strings.Contains(low, "spamhaus"):
		return "spamhaus"
	case strings.Contains(low, "unusual rate"), strings.Contains(low, "rate limit"),
		strings.Contains(low, "too many"), strings.Contains(low, "unexpected volume"):
		return "rate_limit"
	case strings.Contains(low, "complaint"):
		return "complaint"
	case strings.Contains(low, "greylist"), strings.Contains(low, "grey-list"),
		strings.Contains(low, "try again later"):
		return "greylist"
	case strings.Contains(low, "blocked"), strings.Contains(low, "blacklist"),
		strings.Contains(low, "listed"):
		return "blocked"
	}
	return ""
}

func validReasonCode(code string) bool {
	upper := strings.ToUpper(code)
	if strings.HasPrefix(upper, "TLS") {
		return false
	}
	trailingDigits := 0
	for i := len(code) - 1; i >= 0; i-- {
		if code[i] < '0' || code[i] > '9' {
			break
		}
		trailingDigits++
	}
	return trailingDigits >= 2
}

func boundText(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.TrimSpace(whitespaceR.ReplaceAllString(s, " "))
	if len(s) <= maxTextLen {
		return s
	}
	// Truncate on a rune boundary: the deferral text is attacker-influenced,
	// so a byte-position cut could split a multi-byte rune and store invalid
	// UTF-8 that JSON would then mangle.
	cut := maxTextLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ReasonCount is a reason token and how often it occurred.
type ReasonCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// ProviderCount is a provider class and how often it appeared.
type ProviderCount struct {
	Provider string `json:"provider"`
	Count    int    `json:"count"`
}

// ProviderRollup aggregates deferrals to one provider class.
type ProviderRollup struct {
	Provider  string        `json:"provider"`
	Deferrals int           `json:"deferrals"`
	Reasons   []ReasonCount `json:"reasons"`
	LastSeen  time.Time     `json:"last_seen"`
	Sample    string        `json:"sample"`
}

// OutboundIPRollup aggregates deferrals affecting one of this server's sending
// IPs -- the reputation picture for that address.
type OutboundIPRollup struct {
	IP        string          `json:"ip"`
	Deferrals int             `json:"deferrals"`
	Providers []ProviderCount `json:"providers"`
	Reasons   []ReasonCount   `json:"reasons"`
	LastSeen  time.Time       `json:"last_seen"`
}

// Report is the aggregated deferral picture over a window of log lines.
type Report struct {
	Deferrals   int                `json:"deferrals"`
	Providers   []ProviderRollup   `json:"providers"`
	OutboundIPs []OutboundIPRollup `json:"outbound_ips"`
}

// emptyReport returns a zero report with non-nil slices so it serializes as []
// rather than null.
func emptyReport() Report {
	return Report{Providers: []ProviderRollup{}, OutboundIPs: []OutboundIPRollup{}}
}

// BuildReport parses every line and aggregates deferrals by provider and by
// outbound IP. Non-deferral lines are ignored.
func BuildReport(lines []string) Report {
	provAgg := map[string]*provAccum{}
	ipAgg := map[string]*ipAccum{}
	deferrals := 0

	for _, line := range lines {
		d, ok := parseDeferralLine(line)
		if !ok {
			continue
		}
		deferrals++

		prov := string(d.Provider)
		pa := provAgg[prov]
		if pa == nil {
			pa = &provAccum{reasons: map[string]int{}}
			provAgg[prov] = pa
		}
		pa.add(d)

		if d.OutboundIP != "" {
			ia := ipAgg[d.OutboundIP]
			if ia == nil {
				ia = &ipAccum{providers: map[string]int{}, reasons: map[string]int{}}
				ipAgg[d.OutboundIP] = ia
			}
			ia.add(d)
		}
	}

	rep := emptyReport()
	rep.Deferrals = deferrals
	for prov, pa := range provAgg {
		rep.Providers = append(rep.Providers, ProviderRollup{
			Provider:  prov,
			Deferrals: pa.count,
			Reasons:   sortedReasons(pa.reasons),
			LastSeen:  pa.lastSeen,
			Sample:    pa.sample,
		})
	}
	for ip, ia := range ipAgg {
		rep.OutboundIPs = append(rep.OutboundIPs, OutboundIPRollup{
			IP:        ip,
			Deferrals: ia.count,
			Providers: sortedProviders(ia.providers),
			Reasons:   sortedReasons(ia.reasons),
			LastSeen:  ia.lastSeen,
		})
	}

	sort.Slice(rep.Providers, func(i, j int) bool {
		if rep.Providers[i].Deferrals != rep.Providers[j].Deferrals {
			return rep.Providers[i].Deferrals > rep.Providers[j].Deferrals
		}
		return rep.Providers[i].Provider < rep.Providers[j].Provider
	})
	sort.Slice(rep.OutboundIPs, func(i, j int) bool {
		if rep.OutboundIPs[i].Deferrals != rep.OutboundIPs[j].Deferrals {
			return rep.OutboundIPs[i].Deferrals > rep.OutboundIPs[j].Deferrals
		}
		return rep.OutboundIPs[i].IP < rep.OutboundIPs[j].IP
	})
	return rep
}

type provAccum struct {
	count    int
	reasons  map[string]int
	lastSeen time.Time
	sample   string
}

func (p *provAccum) add(d Deferral) {
	p.count++
	if d.ReasonCode != "" {
		p.reasons[d.ReasonCode]++
	}
	if d.Time.After(p.lastSeen) {
		p.lastSeen = d.Time
	}
	if p.sample == "" {
		p.sample = d.Text
	}
}

type ipAccum struct {
	count     int
	providers map[string]int
	reasons   map[string]int
	lastSeen  time.Time
}

func (a *ipAccum) add(d Deferral) {
	a.count++
	a.providers[string(d.Provider)]++
	if d.ReasonCode != "" {
		a.reasons[d.ReasonCode]++
	}
	if d.Time.After(a.lastSeen) {
		a.lastSeen = d.Time
	}
}

func sortedReasons(m map[string]int) []ReasonCount {
	out := make([]ReasonCount, 0, len(m))
	for code, n := range m {
		out = append(out, ReasonCount{Code: code, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	return out
}

func sortedProviders(m map[string]int) []ProviderCount {
	out := make([]ProviderCount, 0, len(m))
	for prov, n := range m {
		out = append(out, ProviderCount{Provider: prov, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}
