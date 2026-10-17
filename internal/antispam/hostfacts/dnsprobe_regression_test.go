package hostfacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"golang.org/x/net/dns/dnsmessage"
)

func serveProbeDNS(t *testing.T, respond func(*dnsmessage.Message)) netip.AddrPort {
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
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			m.Response, m.RecursionAvailable = true, true
			respond(&m)
			out, err := m.Pack()
			if err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestQueryDNSOnlyAsksForA(t *testing.T) {
	var aQueries, otherQueries atomic.Int32
	addr := serveProbeDNS(t, func(m *dnsmessage.Message) {
		if m.Questions[0].Type == dnsmessage.TypeA {
			aQueries.Add(1)
		} else {
			otherQueries.Add(1)
		}
		m.RCode = dnsmessage.RCodeNameError
	})
	got := QueryDNS(context.Background(), addr, "probe.example")
	if !got.NXDomain || got.Failed || len(got.Addrs) != 0 {
		t.Fatalf("NXDOMAIN answer = %+v", got)
	}
	if aQueries.Load() != 1 || otherQueries.Load() != 0 {
		t.Fatalf("queries: A=%d other=%d, want one A only", aQueries.Load(), otherQueries.Load())
	}
}

func TestQueryDNSDistinguishesNoData(t *testing.T) {
	addr := serveProbeDNS(t, func(*dnsmessage.Message) {})
	got := QueryDNS(context.Background(), addr, "probe.example")
	if got.NXDomain || got.Failed || len(got.Addrs) != 0 {
		t.Fatalf("empty successful answer = %+v, want NODATA", got)
	}
}

func TestQueryDNSDoesNotLogQueryWithNetDebug(t *testing.T) {
	if os.Getenv("CSM_DNS_PROBE_HELPER") == "1" {
		addr := netip.MustParseAddrPort(os.Getenv("CSM_TEST_DNS_ENDPOINT"))
		a := QueryDNS(context.Background(), addr, os.Getenv("CSM_TEST_DNS_QUERY"))
		if !a.NXDomain || a.Failed {
			t.Fatal("helper lookup failed")
		}
		return
	}
	var keyBytes [13]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		t.Fatal("cannot generate test key")
	}
	key := hex.EncodeToString(keyBytes[:])
	addr := serveProbeDNS(t, func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError })
	cmd := exec.Command(os.Args[0], "-test.run=^TestQueryDNSDoesNotLogQueryWithNetDebug$")
	cmd.Env = append(os.Environ(), "CSM_DNS_PROBE_HELPER=1", "GODEBUG=netdns=go+2",
		"CSM_TEST_DNS_ENDPOINT="+addr.String(), "CSM_TEST_DNS_QUERY=2.0.0.127."+key+".zen.dq.spamhaus.net")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("DNS debug helper failed")
	}
	if bytes.Contains(output, []byte(key)) {
		t.Fatal("DNS debugging disclosed the query credential")
	}
}

func TestQueryDNSRetriesTruncationOverTCP(t *testing.T) {
	var udpQueries atomic.Int32
	addr := serveProbeDNS(t, func(m *dnsmessage.Message) {
		udpQueries.Add(1)
		m.Truncated = true
	})
	listener, err := net.Listen("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			done <- err
			return
		}
		packet := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err = io.ReadFull(conn, packet); err != nil {
			done <- err
			return
		}
		var m dnsmessage.Message
		if err = m.Unpack(packet); err != nil || len(m.Questions) != 1 {
			done <- errors.New("invalid TCP query")
			return
		}
		m.Response, m.RecursionAvailable = true, true
		m.Answers = []dnsmessage.Resource{probeA(m.Questions[0].Name, "127.0.0.2")}
		packet, err = m.Pack()
		if err == nil {
			packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
			// Split the length prefix and body across writes to exercise framing.
			for _, fragment := range [][]byte{packet[:1], packet[1:2], packet[2:]} {
				if _, err = conn.Write(fragment); err != nil {
					break
				}
			}
		}
		done <- err
	}()
	got := QueryDNS(context.Background(), addr, "probe.example")
	if got.Failed || got.NXDomain || !slices.Equal(got.Addrs, []string{"127.0.0.2"}) || udpQueries.Load() != 1 {
		t.Fatalf("TCP fallback answer = %+v; UDP queries = %d", got, udpQueries.Load())
	}
	if err := <-done; err != nil {
		t.Fatal("TCP responder failed")
	}
}

func probeA(name dnsmessage.Name, addr string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: netip.MustParseAddr(addr).As4()},
	}
}

func TestParseProbeReply(t *testing.T) {
	qname := dnsmessage.MustNewName("probe.example.")
	alias := dnsmessage.MustNewName("alias.example.")
	question := dnsmessage.Question{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	for _, tc := range []struct {
		name      string
		mutate    func(*dnsmessage.Message)
		matched   bool
		failed    bool
		nxdomain  bool
		truncated bool
		addrs     []string
	}{
		{name: "A", matched: true, addrs: []string{"127.0.0.2"}},
		{name: "NODATA", matched: true, mutate: func(m *dnsmessage.Message) { m.Answers = nil }},
		{name: "NXDOMAIN", matched: true, nxdomain: true, mutate: func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError; m.Answers = nil }},
		{name: "SERVFAIL", matched: true, failed: true, mutate: func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeServerFailure }},
		{name: "REFUSED", matched: true, failed: true, mutate: func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeRefused }},
		{name: "truncated", matched: true, failed: true, truncated: true, mutate: func(m *dnsmessage.Message) { m.Truncated = true }},
		{name: "wrong ID", mutate: func(m *dnsmessage.Message) { m.ID++ }},
		{name: "not response", mutate: func(m *dnsmessage.Message) { m.Response = false }},
		{name: "wrong opcode", mutate: func(m *dnsmessage.Message) { m.OpCode = 1 }},
		{name: "wrong question", mutate: func(m *dnsmessage.Message) { m.Questions[0].Name = alias }},
		{name: "wrong type", mutate: func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }},
		{name: "wrong class", mutate: func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }},
		{name: "extra question", mutate: func(m *dnsmessage.Message) { m.Questions = append(m.Questions, question) }},
		{name: "unrelated A", matched: true, mutate: func(m *dnsmessage.Message) { m.Answers[0].Header.Name = alias }},
		{name: "non IN answer", matched: true, mutate: func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassCHAOS }},
		{name: "CNAME", matched: true, addrs: []string{"127.0.0.2"}, mutate: func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{
				{Header: dnsmessage.ResourceHeader{Name: qname, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
				probeA(alias, "127.0.0.2"), probeA(dnsmessage.MustNewName("unrelated.example."), "192.0.2.1"),
			}
		}},
		{name: "CNAME loop", matched: true, failed: true, mutate: func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: qname, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: qname}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, Response: true}, Questions: []dnsmessage.Question{question}, Answers: []dnsmessage.Resource{probeA(qname, "127.0.0.2")}}
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			packet, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			got := parseProbeReply(packet, 42, question)
			if got.matched != tc.matched || got.truncated != tc.truncated || got.answer.Failed != tc.failed || got.answer.NXDomain != tc.nxdomain || !slices.Equal(got.answer.Addrs, tc.addrs) {
				t.Fatalf("parsed reply = %+v", got)
			}
		})
	}
}

func TestQueryDNSCancelsPendingReply(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan antispam.ProbeAnswer, 1)
	go func() { done <- QueryDNS(ctx, netip.MustParseAddrPort(pc.LocalAddr().String()), "probe.example") }()
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case answer := <-done:
		if !answer.Failed || answer.NXDomain || len(answer.Addrs) != 0 {
			t.Fatalf("canceled answer = %+v", answer)
		}
	case <-time.After(time.Second):
		t.Fatal("query did not stop after cancellation")
	}
}
