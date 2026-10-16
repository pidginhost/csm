package hostfacts

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// startDNS serves A records from answers on a local UDP port. Names in
// silent get no reply; other names get NXDOMAIN. AAAA questions for a
// known name get an empty answer.
func startDNS(t *testing.T, answers map[string]string, silent map[string]bool) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			header, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil || silent[q.Name.String()] {
				continue
			}
			reply := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{q},
			}
			addr, known := answers[q.Name.String()]
			switch {
			case !known:
				reply.Header.RCode = dnsmessage.RCodeNameError
			case q.Type == dnsmessage.TypeA:
				ip := netip.MustParseAddr(addr).As4()
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: ip},
				}}
			}
			out, err := reply.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestQueryDNS(t *testing.T) {
	addr := startDNS(t, map[string]string{"2.0.0.127.psbl.surriel.com.": "127.0.0.2"}, map[string]bool{"slow.example.": true})
	ctx := context.Background()
	if a := QueryDNS(ctx, addr, "2.0.0.127.psbl.surriel.com"); a.Failed || a.NXDomain || len(a.Addrs) != 1 || a.Addrs[0] != "127.0.0.2" {
		t.Fatalf("listed = %+v", a)
	}
	if a := QueryDNS(ctx, addr, "1.0.0.127.psbl.surriel.com"); !a.NXDomain {
		t.Fatalf("unlisted = %+v", a)
	}
	start := time.Now()
	if a := QueryDNS(ctx, addr, "slow.example"); !a.Failed || time.Since(start) > 5*time.Second {
		t.Fatalf("silent server = %+v after %v", a, time.Since(start))
	}
}
