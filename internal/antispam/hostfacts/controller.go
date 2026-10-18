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
		if _, err := strconv.Atoi(h.RspamdUser); err == nil {
			h.RspamdUser, _ = c.userName(strconv.Itoa(h.RspamdUID))
		}
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
	f.ControllerErr = nil
	gids := map[int]bool{}
	hasTCP := false
	for _, l := range cfg.Listeners {
		if !l.Unix {
			hasTCP = true
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
	if hasTCP {
		addrs, err := c.interfaceAddrs()
		if err != nil {
			f.ControllerErr = errors.New("host interface addresses unavailable; controller exposure is unknown")
			return
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ip = ip.Unmap()
					h.Addrs = append(h.Addrs, netip.PrefixFrom(ip, ip.BitLen()))
				}
			}
		}
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
	if s.Err == nil && s.Socket.Mode.Type() != fs.ModeSocket {
		s.Err = errors.New("controller path is not a Unix socket")
	}
	return s
}

// groupMembers lists, for each wanted gid, the names in its /etc/group
// entry plus every user whose primary group it is. A gid that cannot be
// read is left out, which exposure treats as possibly holding a tenant.
func (c collector) groupMembers(want map[int]bool) map[int][]string {
	groups, err := c.readGroup()
	if err != nil {
		return nil
	}
	passwd, err := c.readPasswd()
	if err != nil {
		return nil
	}
	return parseGroupMembers(string(groups), string(passwd), want)
}

// A malformed record may hide a member, so no group is known complete
// unless both account files parse in full. Split lazily to bound temporary
// allocations even when a file is mostly delimiters.
func parseGroupMembers(groups, passwd string, want map[int]bool) map[int][]string {
	out := map[int][]string{}
	for line := range strings.SplitSeq(groups, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 5)
		if len(fields) != 4 || !accountName(fields[0]) {
			return nil
		}
		gid, ok := accountID(fields[2])
		if !ok {
			return nil
		}
		// Several group names can share a gid; keep every list.
		if _, listed := out[gid]; want[gid] && !listed {
			out[gid] = []string{}
		}
		if fields[3] == "" {
			continue
		}
		for m := range strings.SplitSeq(fields[3], ",") {
			if !accountName(m) {
				return nil
			}
			if want[gid] {
				out[gid] = append(out[gid], m)
			}
		}
	}
	for line := range strings.SplitSeq(passwd, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 8)
		if len(fields) != 7 || !accountName(fields[0]) {
			return nil
		}
		if _, ok := accountID(fields[2]); !ok {
			return nil
		}
		gid, ok := accountID(fields[3])
		if !ok {
			return nil
		}
		if want[gid] {
			out[gid] = append(out[gid], fields[0])
		}
	}
	return out
}

func accountName(name string) bool {
	return name != "" && !strings.ContainsAny(name, ":,\x00 \t\r\n\v\f")
}

func accountID(raw string) (int, bool) {
	if _, err := strconv.ParseUint(raw, 10, 32); err != nil {
		return 0, false
	}
	id, err := strconv.Atoi(raw)
	return id, err == nil
}
