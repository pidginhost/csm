package txn

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func FuzzListeners(f *testing.F) {
	f.Add("25 : 465 : 587", "<; 0.0.0.0 ; ::0", "465")
	f.Add("25", "<; 192.0.2.10.2525 ; [2001:db8::1]:26", "")
	f.Add("smtp", "127.0.0.1 : ::::1", "25")
	f.Fuzz(func(t *testing.T, ports, interfaces, tls string) {
		blocked := map[int]bool{}
		for _, item := range eximList(tls) {
			if n, err := strconv.Atoi(item); err == nil {
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
