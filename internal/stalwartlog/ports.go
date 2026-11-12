package stalwartlog

import (
	"fmt"
	"strconv"
	"strings"
)

// Protocol is what a Stalwart listener serves, known from its port.
type Protocol string

const (
	ProtoUnknown Protocol = ""
	ProtoSMTP    Protocol = "smtp"
	ProtoIMAP    Protocol = "imap"
	ProtoPOP3    Protocol = "pop3"
	ProtoSieve   Protocol = "sieve"
	ProtoHTTP    Protocol = "http"
)

// Ports maps listener ports to protocols.
type Ports map[uint16]Protocol

// ParsePorts returns Stalwart's standard ports plus overrides written as
// "PORT:PROTOCOL".
func ParsePorts(overrides []string) (Ports, error) {
	p := Ports{
		25: ProtoSMTP, 465: ProtoSMTP, 587: ProtoSMTP,
		143: ProtoIMAP, 993: ProtoIMAP,
		110: ProtoPOP3, 995: ProtoPOP3,
		4190: ProtoSieve,
		80:   ProtoHTTP, 443: ProtoHTTP, 8080: ProtoHTTP,
	}
	for _, entry := range overrides {
		portText, name, ok := strings.Cut(strings.TrimSpace(entry), ":")
		n, err := strconv.ParseUint(portText, 10, 16)
		if !ok || err != nil || n == 0 {
			return nil, fmt.Errorf("port mapping %q: want PORT:PROTOCOL with a port from 1 to 65535", entry)
		}
		proto := Protocol(strings.ToLower(name))
		switch proto {
		case ProtoSMTP, ProtoIMAP, ProtoPOP3, ProtoSieve, ProtoHTTP:
		default:
			return nil, fmt.Errorf("port mapping %q: protocol must be smtp, imap, pop3, sieve or http", entry)
		}
		p[uint16(n)] = proto
	}
	return p, nil
}

// Of returns the protocol served on port, or ProtoUnknown.
func (p Ports) Of(port uint16) Protocol { return p[port] }
