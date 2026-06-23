package blockdigest

import (
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

// shouldSend gates a digest: send_on=any sends when total meets MinBlock;
// send_on=customer sends only when customer-risk blocks meet MinBlock.
func (c *Collector) shouldSend(d Digest) bool {
	if c.opts.SendOn == "customer" {
		return d.CustomerCount >= c.opts.MinBlock
	}
	return d.Total >= c.opts.MinBlock
}
