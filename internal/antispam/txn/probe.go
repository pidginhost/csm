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
// tls_on_connect_ports. Wildcard interfaces map to loopback. Service
// names resolve through the host's TCP service database, as in Exim.
func listeners(settings map[string]string) []string {
	tls := map[int]bool{}
	for _, item := range eximList(settings["tls_on_connect_ports"]) {
		if port, ok := eximPort(item, 10); ok {
			tls[port] = true
		}
	}
	var ports []int
	for _, item := range eximList(settings["daemon_smtp_ports"]) {
		if port, ok := eximPort(item, 0); ok && !tls[port] {
			ports = append(ports, port)
		}
	}
	interfaces := eximList(settings["local_interfaces"])
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

// Exim uses base zero for numeric daemon ports and decimal for TLS ports.
// Non-numeric items are TCP service names. eximList omits empty items.
func eximPort(item string, base int) (int, bool) {
	if item[0] >= '0' && item[0] <= '9' {
		port, err := strconv.ParseInt(item, base, 32)
		return int(port), err == nil && port > 0 && port < 65536
	}
	port, err := net.LookupPort("tcp", item)
	return port, err == nil && port > 0
}

// eximList splits an Exim list: ':' separates items unless the list starts
// with '<' and a punctuation or control separator. Doubled punctuation
// separators are literal; doubled control separators separate empty items.
func eximList(raw string) []string {
	raw = strings.TrimSpace(raw)
	sep := byte(':')
	if len(raw) > 1 && raw[0] == '<' && (raw[1] < ' ' || raw[1] == 127 ||
		strings.ContainsRune("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", rune(raw[1]))) {
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
		case sep >= ' ' && sep != 127 && i+1 < len(raw) && raw[i+1] == sep:
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
// followed by a dot and a port, or [address] with an optional :port.
func splitInterface(item string) (netip.Addr, int, bool) {
	if strings.HasPrefix(item, "[") {
		if strings.HasSuffix(item, "]") {
			addr, err := netip.ParseAddr(item[1 : len(item)-1])
			return addr, 0, err == nil
		}
		host, port, err := net.SplitHostPort(item)
		addr, errA := netip.ParseAddr(host)
		n, errP := strconv.Atoi(port)
		return addr, n, err == nil && errA == nil && errP == nil && n >= 0 && n < 65536
	}
	// Exim's first-dot rule also applies to IPv6 scope identifiers, so try
	// the port before ParseAddr accepts it as part of a zone.
	i := strings.LastIndexByte(item, '.')
	if strings.Contains(item, ":") {
		i = strings.IndexByte(item, '.')
	}
	if i >= 0 {
		addr, errA := netip.ParseAddr(item[:i])
		n, errP := strconv.Atoi(item[i+1:])
		if errA == nil && errP == nil && n >= 0 && n < 65536 {
			return addr, n, true
		}
	}
	if addr, err := netip.ParseAddr(item); err == nil {
		return addr, 0, true
	}
	return netip.Addr{}, 0, false
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
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
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
		if !strings.HasSuffix(line, "\r\n") {
			return errors.New("malformed SMTP reply")
		}
		line = strings.TrimSuffix(line, "\r\n")
		if len(line) < 3 || line[:3] != code {
			return errors.New("SMTP reply is not " + code)
		}
		if len(line) == 3 || line[3] == ' ' {
			return nil
		}
		if line[3] != '-' {
			return errors.New("malformed SMTP reply")
		}
	}
}

// retry calls probe until it succeeds or window ends, pausing between
// attempts. Each attempt gets the time left.
func retry(ctx context.Context, window time.Duration, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := probe(ctx)
		if err == nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(200 * time.Millisecond):
		}
	}
}
