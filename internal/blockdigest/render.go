package blockdigest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// WebhookPayload renders for Slack/Mattermost (Text) and programmatic
// receivers (CSM) at once.
type WebhookPayload struct {
	Text string     `json:"text"`
	CSM  WebhookCSM `json:"csm"`
}

type WebhookCSM struct {
	Event     string         `json:"event"`
	Host      string         `json:"host"`
	Version   string         `json:"version"`
	Window    string         `json:"window"`
	Countries []string       `json:"countries"`
	Counts    WebhookCounts  `json:"counts"`
	Blocks    []WebhookBlock `json:"blocks"`
	// Summary carries the counts of a daily_summary event, which is written
	// with summaryCSM instead of the block digest fields.
	Summary *Summary `json:"summary,omitempty"`
	// CustomerBlocks carries a customer_block event, written with
	// customerCSM.
	CustomerBlocks []CustomerBlock `json:"-"`
}

type summaryCSM struct {
	Event   string   `json:"event"`
	Host    string   `json:"host"`
	Version string   `json:"version"`
	Summary *Summary `json:"summary"`
}

type customerCSM struct {
	Event   string          `json:"event"`
	Host    string          `json:"host"`
	Version string          `json:"version"`
	Blocks  []CustomerBlock `json:"blocks"`
}

// MarshalJSON writes a daily summary or a customer block alert with only its
// own csm fields. Block events keep the block digest shape.
func (p WebhookPayload) MarshalJSON() ([]byte, error) {
	switch {
	case p.CSM.Summary != nil:
		return json.Marshal(struct {
			Text string     `json:"text"`
			CSM  summaryCSM `json:"csm"`
		}{p.Text, summaryCSM{Event: p.CSM.Event, Host: p.CSM.Host, Version: p.CSM.Version, Summary: p.CSM.Summary}})
	case p.CSM.CustomerBlocks != nil:
		return json.Marshal(struct {
			Text string      `json:"text"`
			CSM  customerCSM `json:"csm"`
		}{p.Text, customerCSM{Event: p.CSM.Event, Host: p.CSM.Host, Version: p.CSM.Version, Blocks: p.CSM.CustomerBlocks}})
	}
	type blockPayload WebhookPayload
	return json.Marshal(blockPayload(p))
}

type WebhookCounts struct {
	Total      int            `json:"total"`
	Customer   int            `json:"customer"`
	Attacker   int            `json:"attacker"`
	ByCountry  map[string]int `json:"by_country"`
	ByReason   map[string]int `json:"by_reason"`
	ByCategory map[string]int `json:"by_category"`
}

type WebhookBlock struct {
	IP       string   `json:"ip"`
	Country  string   `json:"country"`
	Reason   string   `json:"reason"`
	Bucket   string   `json:"bucket"`
	Category string   `json:"category"`
	Domains  []string `json:"domains,omitempty"`
	URIs     []string `json:"uris,omitempty"`
	TS       string   `json:"ts"`
}

const maxAttackerListed = 10

func countriesLabel(countries []string) string {
	if len(countries) == 0 {
		return "all"
	}
	return strings.Join(countries, ",")
}

func (c *Collector) renderSubject(d Digest) string {
	return fmt.Sprintf("[%s] %d watched-country IPs blocked (%d customer-risk) last %s",
		c.opts.Host, d.Total, d.CustomerCount, d.Window)
}

func (c *Collector) renderBody(d Digest) string {
	var b strings.Builder
	fmt.Fprintln(&b, c.renderSubject(d))
	fmt.Fprintf(&b, "Countries: %s\n", countriesLabel(d.Countries))
	fmt.Fprintf(&b, "By country: %s\n", sortedCounts(d.ByCountry))
	fmt.Fprintf(&b, "By category: %s\n", sortedCounts(d.ByCategory))
	fmt.Fprintf(&b, "By reason: %s\n", sortedCounts(d.ByReason))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "LIKELY CUSTOMER (false-positive risk -- review/unblock with: csm firewall remove <ip>):")
	wrote := false
	for _, r := range d.Records {
		if r.Bucket != BucketCustomer {
			continue
		}
		fmt.Fprintf(&b, "  %s | %s | %s\n", r.IP, r.Country, r.Reason)
		wrote = true
	}
	if !wrote {
		fmt.Fprintln(&b, "  (none)")
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Attacker blocks (correctly blocked): %d\n", d.AttackerCount)
	listed := 0
	for _, r := range d.Records {
		if r.Bucket != BucketAttacker {
			continue
		}
		if listed >= maxAttackerListed {
			fmt.Fprintf(&b, "  ... and %d more\n", d.AttackerCount-listed)
			break
		}
		fmt.Fprintf(&b, "  %s | %s | %s\n", r.IP, r.Country, r.Reason)
		listed++
	}
	fmt.Fprintln(&b)
	modsec := d.ByCategory["modsec"]
	fmt.Fprintf(&b, "ModSecurity blocks (WAF escalations): %d\n", modsec)
	listed = 0
	for _, r := range d.Records {
		if r.Category != "modsec" {
			continue
		}
		if listed >= maxAttackerListed {
			fmt.Fprintf(&b, "  ... and %d more\n", modsec-listed)
			break
		}
		fmt.Fprintf(&b, "  %s | %s | %s\n", r.IP, r.Country, r.Reason)
		if len(r.Domains) > 0 {
			fmt.Fprintf(&b, "      targets: %s\n", strings.Join(r.Domains, ", "))
		} else {
			fmt.Fprintln(&b, "      targets: no customer domain recorded")
		}
		if len(r.URIs) > 0 {
			fmt.Fprintf(&b, "      top URIs: %s\n", strings.Join(r.URIs, " | "))
		}
		listed++
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Deep per-IP report (successful-hit counts): run the on-host CSM block report.")
	return b.String()
}

func sortedCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " ")
}

func (c *Collector) buildPayload(event string, d Digest) WebhookPayload {
	blocks := make([]WebhookBlock, 0, len(d.Records))
	for _, r := range d.Records {
		blocks = append(blocks, WebhookBlock{
			IP: r.IP, Country: r.Country, Reason: r.Reason,
			Bucket: string(r.Bucket), Category: r.Category,
			Domains: r.Domains, URIs: r.URIs,
			TS: r.TS.UTC().Format(time.RFC3339),
		})
	}
	return WebhookPayload{
		Text: c.renderBody(d),
		CSM: WebhookCSM{
			Event: event, Host: c.opts.Host, Version: c.opts.Version,
			Window: d.Window.String(), Countries: d.Countries,
			Counts: WebhookCounts{
				Total: d.Total, Customer: d.CustomerCount, Attacker: d.AttackerCount,
				ByCountry: d.ByCountry, ByReason: d.ByReason, ByCategory: d.ByCategory,
			},
			Blocks: blocks,
		},
	}
}

// shouldSend gates the watched-country section of the daily summary: it is
// shown when watching and the folded blocks reach MinBlock.
func (c *Collector) shouldSend(w WatchedBlocks) bool {
	return c.opts.Watch && w.Total >= c.opts.MinBlock
}

func (c *Collector) summarySubject(s Summary) string {
	return fmt.Sprintf("[CSM] %s - daily summary %s", c.opts.Host, s.Since.In(c.opts.Location).Format("2006-01-02"))
}

func (c *Collector) summaryBody(s Summary, until time.Time) string {
	const stamp = "2006-01-02 15:04 MST"
	var b strings.Builder
	fmt.Fprintln(&b, c.summarySubject(s))
	fmt.Fprintf(&b, "Window: %s to %s\n", s.Since.In(c.opts.Location).Format(stamp), until.In(c.opts.Location).Format(stamp))
	fmt.Fprintln(&b, "Attacks CSM handled on its own. They are not alerted one by one; the findings page and history keep every one.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Handled findings: %d\n", s.total())
	fmt.Fprintf(&b, "Muted in alert email: %d\n", s.Muted)
	if s.Blocks > 0 {
		fmt.Fprintf(&b, "Blocks applied: %d (%s)\n", s.Blocks, sortedCounts(s.BlockKinds))
	} else {
		fmt.Fprintln(&b, "Blocks applied: 0")
	}
	fmt.Fprintf(&b, "Challenges: %d\n", s.checkTotal("challenge_route"))
	fmt.Fprintf(&b, "Mail login advisories, observe only: %d\n", s.checkTotal("mail_bruteforce_suspected"))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "By check and severity:")
	checks := make([]string, 0, len(s.Checks))
	for check := range s.Checks {
		checks = append(checks, check)
	}
	sort.Strings(checks)
	for _, check := range checks {
		fmt.Fprintf(&b, "  %s: %s\n", check, sortedCounts(s.Checks[check]))
	}
	if len(checks) == 0 {
		fmt.Fprintln(&b, "  (none)")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Top sources:")
	for _, src := range s.Sources {
		if src.Country != "" {
			fmt.Fprintf(&b, "  %s (%s): %d\n", src.IP, src.Country, src.Count)
		} else {
			fmt.Fprintf(&b, "  %s: %d\n", src.IP, src.Count)
		}
	}
	if len(s.Sources) == 0 {
		fmt.Fprintln(&b, "  (none)")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Known customers a dry-run or observe-mode verdict would have blocked:")
	for _, w := range s.WouldBlock {
		c.writeCustomerBlock(&b, "  ", w)
	}
	switch {
	case len(s.WouldBlock) == 0:
		fmt.Fprintln(&b, "  (none)")
	case s.WouldBlockMore > 0:
		fmt.Fprintf(&b, "  and %d more verdicts\n", s.WouldBlockMore)
	}
	if c.shouldSend(s.Watched) {
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "Watched-country blocks: %d (countries: %s)\n", s.Watched.Total, countriesLabel(c.countriesSnapshot()))
		fmt.Fprintf(&b, "  By country: %s\n", sortedCounts(s.Watched.ByCountry))
		fmt.Fprintf(&b, "  By category: %s\n", sortedCounts(s.Watched.ByCategory))
	}
	return b.String()
}

func (c *Collector) summaryPayload(s Summary, body string) WebhookPayload {
	return WebhookPayload{
		Text: body,
		CSM:  WebhookCSM{Event: "daily_summary", Host: c.opts.Host, Version: c.opts.Version, Summary: &s},
	}
}
