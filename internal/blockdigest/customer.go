package blockdigest

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// CustomerHit is an address that logged in successfully as a customer: the
// kind of login (cpanel, webmail, smtp, imap, pop, ftp), the account or mailbox
// when the log named one, and when it was seen. IP is the address, or for
// IPv6 its /64.
type CustomerHit struct {
	IP      string    `json:"ip"`
	Kind    string    `json:"kind"`
	Account string    `json:"account,omitempty"`
	At      time.Time `json:"at"`
}

// CustomerBlock is one automatic block, applied or a verdict only, that hit
// known customers. Target is the blocked address or network. Hits are the
// customers it covers, the most recent first; More counts those left out.
type CustomerBlock struct {
	Target string        `json:"target"`
	Reason string        `json:"reason"`
	Check  string        `json:"check,omitempty"`
	Hits   []CustomerHit `json:"customers"`
	More   int           `json:"more,omitempty"`
}

// maxWouldBlock caps each customer block list of one daily summary: the
// would-block verdicts and the applied blocks.
const maxWouldBlock = 50

// AlertCustomerBlocks sends one email and one webhook event naming every
// block in blocks. It is the false-positive signal of automatic blocking, so
// it goes out without Watch, ignores LiveChannel, and has no cap of its own:
// a cap an attacker could fill would hide it. The daily summary lists the
// blocks too, so a failed send still reaches the operator.
func (c *Collector) AlertCustomerBlocks(blocks []CustomerBlock) {
	if len(blocks) == 0 {
		return
	}
	c.mu.Lock()
	for _, b := range blocks {
		c.sum.noteCustomerBlock(b)
	}
	c.mu.Unlock()
	plan := c.beginDelivery(func(channel string) bool {
		return c.opts.DeliveryEnabled == nil || c.opts.DeliveryEnabled("customer_block", channel)
	}, nil)
	defer plan.finish()

	subject := fmt.Sprintf("[CSM] %s - %d automatic blocks hit known customers", c.opts.Host, len(blocks))
	if len(blocks) == 1 {
		subject = fmt.Sprintf("[CSM] %s - automatic block hit a known customer: %s", c.opts.Host, blocks[0].Target)
	}
	var b strings.Builder
	fmt.Fprintln(&b, subject)
	fmt.Fprintln(&b, "These blocks hit addresses that recently logged in successfully as a customer. The blocks stand: a customer address is never exempt. Check each for a false positive.")
	for _, blk := range blocks {
		fmt.Fprintln(&b)
		c.writeCustomerBlock(&b, "", blk)
		writeUnblockHint(&b, "", blk.Target)
	}
	body := b.String()
	payload := WebhookPayload{Text: body, CSM: WebhookCSM{Event: "customer_block", Host: c.opts.Host, Version: c.opts.Version, CustomerBlocks: blocks}}
	c.deliver(plan, subject, body, payload, nil)
}

// noteWouldBlock lists each target once. Past maxWouldBlock targets it only
// counts verdicts, so a repeat of an unlisted target counts again.
func (s *Summary) noteWouldBlock(b CustomerBlock) {
	for _, w := range s.WouldBlock {
		if w.Target == b.Target {
			return
		}
	}
	if len(s.WouldBlock) < maxWouldBlock {
		s.WouldBlock = append(s.WouldBlock, b)
		return
	}
	s.WouldBlockMore++
}

// noteCustomerBlock lists each applied block, since each is a block of its
// own, up to maxWouldBlock, then counts the rest.
func (s *Summary) noteCustomerBlock(b CustomerBlock) {
	if len(s.CustomerBlocks) < maxWouldBlock {
		s.CustomerBlocks = append(s.CustomerBlocks, b)
		return
	}
	s.CustomerBlocksMore++
}

func (c *Collector) writeCustomerBlock(b *strings.Builder, indent string, blk CustomerBlock) {
	fmt.Fprintf(b, "%sBlock: %s\n", indent, blk.Target)
	fmt.Fprintf(b, "%s  Reason: %s\n", indent, blk.Reason)
	if blk.Check != "" {
		fmt.Fprintf(b, "%s  Check: %s\n", indent, blk.Check)
	}
	if len(blk.Hits) == 1 && blk.More == 0 {
		fmt.Fprintf(b, "%s  Known customer: %s\n", indent, c.customerLogin(blk.Hits[0]))
		return
	}
	fmt.Fprintf(b, "%s  %d known customers, the latest %d:\n", indent, len(blk.Hits)+blk.More, len(blk.Hits))
	for _, h := range blk.Hits {
		fmt.Fprintf(b, "%s    %s\n", indent, c.customerLogin(h))
	}
	if blk.More > 0 {
		fmt.Fprintf(b, "%s    and %d more\n", indent, blk.More)
	}
}

// writeUnblockHint names the command that lifts a block of target. An allow
// rule does not pass a blocked network, whose drop comes first, but CSM never
// blocks a range over an allowed address, so it is offered for later blocks.
func writeUnblockHint(b *strings.Builder, indent, target string) {
	if _, err := netip.ParsePrefix(target); err != nil {
		fmt.Fprintf(b, "%s  Unblock: csm firewall remove %s\n", indent, target)
		return
	}
	fmt.Fprintf(b, "%s  Unblock: csm firewall remove-subnet %s\n", indent, target)
	fmt.Fprintf(b, "%s  Keep a customer address out of later range blocks: csm firewall allow <ip>\n", indent)
}

func (c *Collector) customerLogin(h CustomerHit) string {
	login := h.Kind + " login"
	if h.Account != "" {
		login += " as " + h.Account
	}
	return fmt.Sprintf("%s %s at %s", h.IP, login, h.At.In(c.opts.Location).Format("2006-01-02 15:04 MST"))
}
