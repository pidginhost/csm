package txn

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// listeners returns the local addresses where Exim's daemon greets in
// plain text, from daemon_smtp_ports, local_interfaces and
// tls_on_connect_ports. Wildcard interfaces map to loopback. Named
// services are skipped: cPanel configures numeric ports.
func listeners(settings map[string]string) []string {
	tls := map[int]bool{}
	for _, item := range eximList(settings["tls_on_connect_ports"]) {
		if port, err := strconv.Atoi(item); err == nil {
			tls[port] = true
		}
	}
	var ports []int
	for _, item := range eximList(settings["daemon_smtp_ports"]) {
		if port, err := strconv.Atoi(item); err == nil && port > 0 && port < 65536 && !tls[port] {
			ports = append(ports, port)
		}
	}
	interfaces := eximList(settings["local_interfaces"])
	if len(interfaces) == 0 {
		interfaces = []string{"0.0.0.0", "::"}
	}
	var out []string
	add := func(addr netip.Addr, port int) {
		switch {
		case addr.IsUnspecified() && addr.Is4():
			addr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		case addr.IsUnspecified():
			addr = netip.IPv6Loopback()
		}
		hostport := net.JoinHostPort(addr.String(), strconv.Itoa(port))
		if !tls[port] && !slices.Contains(out, hostport) {
			out = append(out, hostport)
		}
	}
	for _, item := range interfaces {
		addr, port, ok := splitInterface(item)
		switch {
		case !ok:
		case port != 0:
			add(addr, port)
		default:
			for _, p := range ports {
				add(addr, p)
			}
		}
	}
	return out
}

// eximList splits an Exim list: ':' separates items unless the list starts
// with '<' and another separator, and a doubled separator is literal.
func eximList(raw string) []string {
	raw = strings.TrimSpace(raw)
	sep := byte(':')
	if len(raw) > 1 && raw[0] == '<' && raw[1] != ' ' && raw[1] != '\t' {
		sep, raw = raw[1], raw[2:]
	}
	var out []string
	var item strings.Builder
	flush := func() {
		if s := strings.TrimSpace(item.String()); s != "" {
			out = append(out, s)
		}
		item.Reset()
	}
	for i := 0; i < len(raw); i++ {
		switch {
		case raw[i] != sep:
			item.WriteByte(raw[i])
		case i+1 < len(raw) && raw[i+1] == sep:
			item.WriteByte(sep)
			i++
		default:
			flush()
		}
	}
	flush()
	return out
}

// splitInterface reads one local_interfaces item: an address, optionally
// followed by a dot and a port, or [address]:port.
func splitInterface(item string) (netip.Addr, int, bool) {
	if strings.HasPrefix(item, "[") {
		host, port, err := net.SplitHostPort(item)
		addr, errA := netip.ParseAddr(host)
		n, errP := strconv.Atoi(port)
		return addr, n, err == nil && errA == nil && errP == nil && n > 0 && n < 65536
	}
	if addr, err := netip.ParseAddr(item); err == nil {
		return addr, 0, true
	}
	i := strings.LastIndexByte(item, '.')
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	addr, errA := netip.ParseAddr(item[:i])
	n, errP := strconv.Atoi(item[i+1:])
	return addr, n, errA == nil && errP == nil && n > 0 && n < 65536
}

// maxGreeting bounds what the probe reads from one SMTP session.
const maxGreeting = 4 << 10

// smtpGreeting reads Exim's complete 220 greeting from addr and ends the
// session with QUIT, so the probe never counts as a dropped connection.
// Errors never repeat the server's text.
func smtpGreeting(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	r := bufio.NewReader(io.LimitReader(conn, maxGreeting))
	if err := readReply(r, "220"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "QUIT\r\n"); err != nil {
		return err
	}
	return readReply(r, "221")
}

func readReply(r *bufio.Reader, code string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return errors.New("incomplete SMTP reply")
		}
		if len(line) < 4 || line[:3] != code {
			return errors.New("SMTP reply is not " + code)
		}
		if line[3] != '-' {
			return nil
		}
	}
}

// retry calls probe until it succeeds or window ends, pausing between
// attempts. Each attempt gets the time left.
func retry(ctx context.Context, window time.Duration, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	for {
		err := probe(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(200 * time.Millisecond):
		}
	}
}
