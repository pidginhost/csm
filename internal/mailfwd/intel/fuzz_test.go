package intel

import (
	"net"
	"testing"
)

// FuzzParseDeferralLine feeds attacker-controlled log content (a deferral line
// echoes a remote server's free-text error) through the parser. It must never
// panic and must keep every bounded-field invariant.
func FuzzParseDeferralLine(f *testing.F) {
	for _, seed := range []string{
		yahooTSS04, gmailRate, spamhausBlock,
		deliveryLine, arrivalLine, failureLine,
		"", "==", "a b c == ",
		"2026-13-99 99:99:99 x == a@b.example [not-an-ip]: 999",
		"2026-06-07 10:00:00 m == \x00@\x00.example []: \x00 421",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		d, ok := parseDeferralLine(line)
		if !ok {
			return
		}
		if len(d.Text) > maxTextLen {
			t.Fatalf("Text exceeds bound: %d", len(d.Text))
		}
		if len(d.Recipient) > maxAddressLen {
			t.Fatalf("Recipient exceeds bound: %d", len(d.Recipient))
		}
		if len(d.Domain) > maxDomainLen {
			t.Fatalf("Domain exceeds bound: %d", len(d.Domain))
		}
		if len(d.RemoteHost) > maxHostLen {
			t.Fatalf("RemoteHost exceeds bound: %d", len(d.RemoteHost))
		}
		if d.OutboundIP != "" && firstIPv4(d.OutboundIP) != d.OutboundIP {
			t.Fatalf("OutboundIP not a valid IPv4: %q", d.OutboundIP)
		}
		if d.RemoteIP != "" && net.ParseIP(d.RemoteIP) == nil {
			t.Fatalf("RemoteIP not a valid IP: %q", d.RemoteIP)
		}
		// A parsed deferral always carries a recipient with a domain.
		if d.Recipient == "" {
			t.Fatal("parsed deferral has empty recipient")
		}
	})
}
