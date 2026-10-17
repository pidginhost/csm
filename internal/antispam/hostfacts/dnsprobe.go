package hostfacts

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"golang.org/x/net/dns/dnsmessage"
)

// probeTimeout bounds one probe query, including a TCP retry.
const probeTimeout = 3 * time.Second

// QueryDNS asks server for A records of an absolute name. Use DNS directly:
// net.Resolver consults host files and can print the DQS key with netdns=2.
func QueryDNS(ctx context.Context, server netip.AddrPort, name string) antispam.ProbeAnswer {
	failed := antispam.ProbeAnswer{Failed: true}
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return failed
	}
	question := dnsmessage.Question{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return failed
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{question},
	}
	packet, err := query.Pack()
	if err != nil {
		return failed
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	for _, network := range []string{"udp", "tcp"} {
		answer, truncated := exchangeProbe(ctx, network, server, packet, query.ID, question)
		if !truncated {
			return answer
		}
	}
	return failed
}

func exchangeProbe(ctx context.Context, network string, server netip.AddrPort, packet []byte, id uint16, question dnsmessage.Question) (antispam.ProbeAnswer, bool) {
	failed := antispam.ProbeAnswer{Failed: true}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return failed, false
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return failed, false
	}
	if network == "tcp" {
		// #nosec G115 -- QueryDNS packs one DNS question, at most 271 bytes.
		packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
	}
	if _, err = conn.Write(packet); err != nil {
		return failed, false
	}
	buf := make([]byte, 65535)
	for {
		var n int
		if network == "tcp" {
			if _, err = io.ReadFull(conn, buf[:2]); err == nil {
				n, err = io.ReadFull(conn, buf[:binary.BigEndian.Uint16(buf[:2])])
			}
		} else {
			n, err = conn.Read(buf)
		}
		if err != nil {
			return failed, false
		}
		reply := parseProbeReply(buf[:n], id, question)
		if reply.matched {
			return reply.answer, reply.truncated
		}
		// Ignore unrelated packets on the connected socket until the deadline.
	}
}

type probeReply struct {
	answer    antispam.ProbeAnswer
	matched   bool
	truncated bool
}

func parseProbeReply(packet []byte, id uint16, question dnsmessage.Question) probeReply {
	var p dnsmessage.Parser
	h, err := p.Start(packet)
	if err != nil || h.ID != id || !h.Response || h.OpCode != 0 {
		return probeReply{}
	}
	q, err := p.Question()
	if err != nil || q.Type != question.Type || q.Class != question.Class || !strings.EqualFold(q.Name.String(), question.Name.String()) {
		return probeReply{}
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return probeReply{}
	}
	reply := probeReply{matched: true, answer: antispam.ProbeAnswer{Failed: true}, truncated: h.Truncated}
	if h.Truncated {
		return reply
	}
	var m dnsmessage.Message
	if m.Unpack(packet) != nil {
		return reply
	}
	switch h.RCode {
	case dnsmessage.RCodeNameError:
		reply.answer = antispam.ProbeAnswer{NXDomain: true}
		return reply
	case dnsmessage.RCodeSuccess:
	default:
		return reply
	}
	// Recursive resolvers include CNAME targets in the answer. Follow only
	// that chain, so unrelated A records cannot turn into listing codes.
	aliases := make(map[string]string)
	for _, rr := range m.Answers {
		if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && rr.Header.Class == dnsmessage.ClassINET {
			from, to := strings.ToLower(rr.Header.Name.String()), strings.ToLower(cname.CNAME.String())
			if previous, ok := aliases[from]; ok && previous != to {
				return reply
			}
			aliases[from] = to
		}
	}
	name := strings.ToLower(question.Name.String())
	seen := make(map[string]bool)
	for aliases[name] != "" {
		if seen[name] {
			return reply
		}
		seen[name] = true
		name = aliases[name]
	}
	reply.answer = antispam.ProbeAnswer{}
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok && rr.Header.Class == dnsmessage.ClassINET && strings.EqualFold(rr.Header.Name.String(), name) {
			reply.answer.Addrs = append(reply.answer.Addrs, netip.AddrFrom4(a.A).String())
		}
	}
	return reply
}
