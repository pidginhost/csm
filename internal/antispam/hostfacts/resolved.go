package hostfacts

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/antispam"
)

type resolvedServer struct {
	link int
	addr netip.Addr
}

// resolvedDNS uses the live inventory because the generated resolv.conf
// omits route-only DNS servers and servers using nonstandard ports.
func (c collector) resolvedDNS(ctx context.Context) ([]netip.Addr, error) {
	read := func(property string) ([]resolvedServer, error) {
		result := c.resolvedProperty(ctx, "", property)
		if result.Err != nil {
			return nil, result.Err
		}
		return parseResolvedDNS(result.Stdout)
	}
	servers, err := read("DNS")
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	links := make(map[int]bool)
	defaultRoute := false
	for _, server := range servers {
		out = append(out, server.addr)
		if server.link == 0 {
			defaultRoute = true
		} else {
			links[server.link] = true
		}
	}
	var routeErr error
	for _, link := range slices.Sorted(maps.Keys(links)) {
		if defaultRoute {
			break
		}
		result := c.resolvedProperty(ctx, resolvedLinkPath(link), "DefaultRoute")
		if result.Err != nil {
			routeErr = errors.Join(routeErr, result.Err)
			continue
		}
		switch strings.TrimSpace(result.Stdout) {
		case "b true":
			defaultRoute = true
		case "b false":
		default:
			routeErr = errors.Join(routeErr, errors.New("unreadable systemd-resolved default route"))
		}
	}
	if !defaultRoute {
		if routeErr != nil {
			return nil, routeErr
		}
		fallback, err := read("FallbackDNS")
		if err != nil {
			return nil, err
		}
		for _, server := range fallback {
			out = append(out, server.addr)
		}
	}
	return out, nil
}

// resolvedLinkPath is systemd's bus label for a link: a leading digit is
// escaped as _ and its hex code, so link 2 is /link/_32. Link indexes here
// are positive, so the first character is always a digit from 1 to 9.
func resolvedLinkPath(link int) string {
	return "/link/_3" + strconv.Itoa(link)
}

func (c collector) resolvedProperty(ctx context.Context, link, property string) antispam.CommandResult {
	iface := "org.freedesktop.resolve1.Manager"
	if link != "" {
		iface = "org.freedesktop.resolve1.Link"
	}
	return c.run(ctx, "busctl", "--system", "--auto-start=no", "--no-pager", "get-property",
		"org.freedesktop.resolve1", "/org/freedesktop/resolve1"+link, iface, property)
}

// parseResolvedDNS reads busctl's typed a(iiay) output. DNS includes all
// server addresses even when their ports cannot be written to resolv.conf.
func parseResolvedDNS(output string) ([]resolvedServer, error) {
	invalid := errors.New("unreadable systemd-resolved DNS inventory")
	fields := strings.Fields(output)
	if len(fields) < 2 || fields[0] != "a(iiay)" {
		return nil, invalid
	}
	count, err := strconv.ParseUint(fields[1], 10, 32)
	fields = fields[2:]
	if err != nil || count > uint64(len(fields)/7) {
		return nil, invalid
	}
	var out []resolvedServer
	for range count {
		if len(fields) < 3 {
			return nil, invalid
		}
		link, err := strconv.ParseInt(fields[0], 10, 32)
		if err != nil || link < 0 {
			return nil, invalid
		}
		// These are Linux's wire address families, independent of the
		// platform compiling this parser.
		size := 0
		switch fields[1] {
		case "2":
			size = 4
		case "10":
			size = 16
		default:
			return nil, invalid
		}
		if fields[2] != strconv.Itoa(size) || len(fields) < 3+size {
			return nil, invalid
		}
		var bytes [16]byte
		for i, field := range fields[3 : 3+size] {
			value, err := strconv.ParseUint(field, 10, 8)
			if err != nil {
				return nil, invalid
			}
			bytes[i] = byte(value)
		}
		addr, _ := netip.AddrFromSlice(bytes[:size])
		out = append(out, resolvedServer{link: int(link), addr: addr})
		fields = fields[3+size:]
	}
	if len(fields) != 0 {
		return nil, invalid
	}
	return out, nil
}
