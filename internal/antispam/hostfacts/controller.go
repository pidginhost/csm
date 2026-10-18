package hostfacts

import (
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/antispam"
)

// maxAccountFileBytes bounds /etc/group and /etc/passwd reads.
const maxAccountFileBytes = 8 << 20

func readAccountFile(p string) ([]byte, error) {
	content, err := readRegularContent(p, maxAccountFileBytes)
	return []byte(content), err
}

// controllerFacts parses the loaded controller from the full configdump the
// collector already read and gathers what exposure needs: host addresses,
// each Unix controller socket and the members of the groups owning them.
func (c collector) controllerFacts(f *antispam.HostFacts) {
	h := antispam.ControllerHostFacts{
		Sockets:      map[string]antispam.SocketFacts{},
		GroupMembers: map[int][]string{},
		RspamdUID:    f.Socket.RspamdUID,
		RspamdGID:    f.RspamdGID,
	}
	if props := antispam.ParseUnitShow(f.RspamdService.Stdout); f.RspamdService.Err == nil && h.RspamdUID >= 0 {
		h.RspamdUser = props["User"]
	}
	defer func() { f.ControllerHost = h }()
	if f.RspamdConfig.Err != nil {
		f.ControllerErr = errors.New("rspamadm configdump failed; controller exposure is unknown")
		return
	}
	cfg, err := antispam.ParseControllerConfig([]byte(f.RspamdConfig.Stdout))
	if err != nil {
		f.ControllerErr = err
		return
	}
	f.Controller = cfg
	if addrs, err := c.interfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ip = ip.Unmap()
					h.Addrs = append(h.Addrs, netip.PrefixFrom(ip, ip.BitLen()))
				}
			}
		}
	}
	gids := map[int]bool{}
	for _, l := range cfg.Listeners {
		if !l.Unix {
			continue
		}
		s := unixSocketFacts(l.Path)
		h.Sockets[l.Path] = s
		if s.Err == nil && !s.Missing {
			gids[s.Socket.GID] = true
		}
	}
	if len(gids) > 0 {
		h.GroupMembers = c.groupMembers(gids)
	}
}

// unixSocketFacts lstats a Unix socket and every directory its path walks
// through, without probing it.
func unixSocketFacts(p string) antispam.SocketFacts {
	s := antispam.SocketFacts{Socket: antispam.PathFacts{Path: p}, RspamdUID: -1, PeerUID: -1, EximUID: -1, EximGID: -1}
	final, dirs, walkErr := resolve(p)
	for _, d := range dirs {
		facts, err := pathFacts(d)
		if err != nil {
			s.Err = err
			return s
		}
		s.Parents = append(s.Parents, facts)
	}
	switch {
	case errors.Is(walkErr, fs.ErrNotExist):
		s.Missing = true
		return s
	case walkErr != nil:
		s.Err = walkErr
		return s
	}
	s.Socket, s.Err = pathFacts(final)
	return s
}

// groupMembers lists, for each wanted gid, the names in its /etc/group
// entry plus every user whose primary group it is. A gid that cannot be
// read is left out, which exposure treats as possibly holding a tenant.
func (c collector) groupMembers(want map[int]bool) map[int][]string {
	out := map[int][]string{}
	groups, err := c.readGroup()
	if err != nil {
		return out
	}
	passwd, err := c.readPasswd()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(groups), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil || !want[gid] {
			continue
		}
		// Several group names can share a gid; keep every list.
		if _, listed := out[gid]; !listed {
			out[gid] = []string{}
		}
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				out[gid] = append(out[gid], m)
			}
		}
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil || !want[gid] {
			continue
		}
		if _, listed := out[gid]; !listed {
			out[gid] = []string{}
		}
		out[gid] = append(out[gid], fields[0])
	}
	return out
}
