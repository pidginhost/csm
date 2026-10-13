package txn

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func FuzzListeners(f *testing.F) {
	f.Add("25 : 465 : 587", "<; 0.0.0.0 ; ::0", "465")
	f.Add("25", "<; 192.0.2.10.2525 ; [2001:db8::1]:26", "")
	f.Add("smtp", "127.0.0.1 : ::::1", "25")
	f.Add("smtp : 465", "<; [192.0.2.10] ; [2001:db8::1]:0", "submissions")
	f.Add("0x19 : 025 : 65535", "192.0.2.10", "25")
	f.Add("<\t25\t\t587", "<\n192.0.2.10\n\n2001:db8::1", "<\x7f465\x7f\x7f587")
	f.Fuzz(func(t *testing.T, ports, interfaces, tls string) {
		blocked := map[int]bool{}
		for _, item := range eximList(tls) {
			if n, err := net.LookupPort("tcp", item); err == nil {
				blocked[n] = true
			}
		}
		for _, hostport := range listeners(map[string]string{"daemon_smtp_ports": ports, "local_interfaces": interfaces, "tls_on_connect_ports": tls}) {
			host, port, err := net.SplitHostPort(hostport)
			if err != nil {
				t.Fatalf("%q is not host:port", hostport)
			}
			addr, err := netip.ParseAddr(host)
			n, errP := strconv.Atoi(port)
			if err != nil || addr.IsUnspecified() || errP != nil || n < 1 || n > 65535 || blocked[n] {
				t.Fatalf("listener %q is not a usable plain SMTP address", hostport)
			}
		}
	})
}

func FuzzSMTPReply(f *testing.F) {
	f.Add("220-ready\r\n220 ready\r\n", false)
	f.Add("221\r\n", true)
	f.Add("2200 private-banner\r\n", false)
	f.Add("220 private-banner\n", false)
	f.Add("220-first\r\n221 wrong code\r\n", false)
	valid := map[string]*regexp.Regexp{}
	for _, code := range []string{"220", "221"} {
		valid[code] = regexp.MustCompile(`^(?:` + code + `-[^\n]*\r\n)*(?:` + code + `(?: [^\n]*)?\r\n)`)
	}
	f.Fuzz(func(t *testing.T, reply string, quit bool) {
		code := "220"
		if quit {
			code = "221"
		}
		prefix := valid[code].FindStringIndex(reply)
		want := prefix != nil && prefix[1] <= maxGreeting
		err := readReply(bufio.NewReader(io.LimitReader(strings.NewReader(reply), maxGreeting)), code)
		if (err == nil) != want {
			t.Fatalf("reply accepted %v, want %v", err == nil, want)
		}
	})
}
