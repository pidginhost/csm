package hostfacts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/antispam"
)

// Learning fact sources on a live cPanel host.
const (
	procNetUDP        = "/proc/net/udp"
	cageFSSkeletonLog = "/usr/share/cagefs-skeleton/var/log/rspamd"
	roundcubeConfig   = "/usr/local/cpanel/base/3rdparty/roundcube/config/config.inc.php"
	cpanelPHP         = "/usr/local/cpanel/3rdparty/bin/php"
	cpanelUsers       = "/var/cpanel/users"
	// roundcubeIncludeGlob is the line cPanel's Roundcube configuration uses
	// to load inc.d (spike S10).
	roundcubeIncludeGlob = `glob("/usr/local/cpanel/base/3rdparty/roundcube/config/inc.d/*.php")`
	// fuzzyListenAddr is 127.0.0.1:11335 as /proc/net/udp prints it.
	fuzzyListenAddr = "0100007F:2C47"
)

// CollectLearning adds the learning prerequisites to f, which must already
// hold the core facts (full rspamd dump, options and targets).
func CollectLearning(ctx context.Context, f *antispam.HostFacts) {
	live().learningFacts(ctx, f)
}

func (c collector) learningFacts(ctx context.Context, f *antispam.HostFacts) {
	c.learningDumps(ctx, f)
	c.controlSocket(f)
	c.controlSocketGroup(f)
	f.FuzzyListening, f.FuzzyListenErr = c.fuzzyListening()
	f.CageFS = c.cageFS(ctx)
	f.Roundcube = c.roundcube(*f)
	f.AccountNames, f.AccountNamesErr = c.accountNames()
	f.Redis = c.redis(ctx, *f)
}

// learningDumps reads the rspamd sections learning verifies. Any failure is
// one error; a partial set is never judged.
func (c collector) learningDumps(ctx context.Context, f *antispam.HostFacts) {
	var d antispam.LearningDumps
	var errs []error
	read := func(section string) []byte {
		r := c.run(ctx, "rspamadm", "configdump", "-j", section)
		if r.Err != nil {
			errs = append(errs, errors.New("rspamadm configdump -j "+section+" failed"))
			return nil
		}
		if !readableDump(r.Stdout, section == "group") {
			errs = append(errs, errors.New("rspamadm configdump -j "+section+" is not readable"))
		}
		return []byte(r.Stdout)
	}
	d.FuzzyCheck = read("fuzzy_check")
	d.Group = read("group")
	d.Redis = read("redis")
	root, parseErr := antispam.ParseRspamdDumpObject([]byte(f.RspamdConfig.Stdout))
	switch {
	case f.RspamdConfig.Err != nil:
		errs = append(errs, errors.New("rspamadm configdump -j failed"))
	case parseErr != nil:
		errs = append(errs, errors.New("rspamadm configdump -j is not readable"))
	default:
		d.Worker = root["worker"]
		if _, err := workerEntries(d.Worker); err != nil {
			errs = append(errs, err)
		}
	}
	d.Err = errors.Join(errs...)
	f.LearningDumps = d
}

// The group command emits a stream of objects, not a JSON array. Validate
// the envelopes without rewriting bytes or interpreting module settings.
func readableDump(data string, stream bool) bool {
	d := json.NewDecoder(strings.NewReader(data))
	count := 0
	for {
		var object json.RawMessage
		err := d.Decode(&object)
		if errors.Is(err, io.EOF) {
			return count > 0
		}
		if err != nil || (!stream && count > 0) {
			return false
		}
		if _, err := antispam.ParseRspamdDumpObject(object); err != nil {
			return false
		}
		count++
	}
}

// controlSocket reads options.control_socket, without its mode option.
func (c collector) controlSocket(f *antispam.HostFacts) {
	f.ControlSocket = antispam.SocketFacts{}
	opts, parseErr := antispam.ParseRspamdDumpObject([]byte(f.RspamdOptions.Stdout))
	var value string
	switch {
	case f.RspamdOptions.Err != nil:
		f.ControlSocket.Err = errors.New("rspamadm configdump -j options failed")
	case parseErr != nil:
		f.ControlSocket.Err = errors.New("rspamd's options are not readable")
	case opts["control_socket"] == nil:
		f.ControlSocket.Err = errors.New("rspamd reports no control_socket")
	case json.Unmarshal(opts["control_socket"], &value) != nil:
		f.ControlSocket.Err = errors.New("control_socket is not a string")
	default:
		fields := strings.Fields(value)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
			f.ControlSocket.Err = errors.New("control_socket is not a Unix socket path")
			return
		}
		f.ControlSocket = unixSocketFacts(fields[0])
	}
}

// controlSocketGroup adds the control socket's group members to the
// controller facts, so one exposure check judges both sockets.
func (c collector) controlSocketGroup(f *antispam.HostFacts) {
	if f.ControlSocket.Err != nil || f.ControlSocket.Missing {
		return
	}
	gid := f.ControlSocket.Socket.GID
	if _, known := f.ControllerHost.GroupMembers[gid]; known {
		return
	}
	members, ok := c.groupMembers(map[int]bool{gid: true})[gid]
	if !ok {
		return
	}
	if f.ControllerHost.GroupMembers == nil {
		f.ControllerHost.GroupMembers = map[int][]string{}
	}
	f.ControllerHost.GroupMembers[gid] = members
}

// fuzzyListening reports whether a UDP socket is bound to 127.0.0.1:11335.
// rspamd does not respawn a fuzzy worker that exited (spike S4).
func (c collector) fuzzyListening() (bool, error) {
	data, err := readText(c.layout.ProcNetUDP)
	if err != nil {
		return false, errors.New("cannot read the UDP socket table")
	}
	return parseFuzzyListening(data)
}

func parseFuzzyListening(data string) (bool, error) {
	lines := strings.Split(data, "\n")
	header := strings.Fields(lines[0])
	bad := errors.New("the UDP socket table is not readable")
	if len(header) < 4 || strings.Join(header[:4], " ") != "sl local_address rem_address st" {
		return false, bad
	}
	found := false
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") ||
			!udpAddress(fields[1]) || !udpAddress(fields[2]) || len(fields[3]) != 2 {
			return false, bad
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 10, 64); err != nil {
			return false, bad
		}
		if _, err := strconv.ParseUint(fields[3], 16, 8); err != nil {
			return false, bad
		}
		if fields[1] == fuzzyListenAddr && fields[3] == "07" {
			found = true
		}
	}
	return found, nil
}

func udpAddress(value string) bool {
	if len(value) != 13 || value[8] != ':' {
		return false
	}
	_, addrErr := strconv.ParseUint(value[:8], 16, 32)
	_, portErr := strconv.ParseUint(value[9:], 16, 16)
	return addrErr == nil && portErr == nil
}

// cageFS reads whether CageFS confines every account: enabled, in Enable
// All mode, and how many accounts are excluded. A disabled-list line that is
// not an account name is an error: CSM cannot count it.
func (c collector) cageFS(ctx context.Context) antispam.CageFSFacts {
	var out antispam.CageFSFacts
	if _, err := os.Lstat(c.layout.CageFSSkeletonLog); err == nil {
		out.SkeletonHasRspamdLog = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		out.Err = errors.New("cannot check the CageFS skeleton")
		return out
	}
	status := c.run(ctx, "cagefsctl", "--cagefs-status")
	if status.Err != nil {
		out.Err = errors.New("cagefsctl --cagefs-status failed")
		return out
	}
	switch strings.TrimSpace(status.Stdout) {
	case "Disabled":
		return out
	case "Enabled":
	default:
		out.Err = errors.New("cagefsctl --cagefs-status is not readable")
		return out
	}
	mode := c.run(ctx, "cagefsctl", "--display-user-mode")
	if mode.Err != nil {
		out.Err = errors.New("cagefsctl --display-user-mode failed")
		return out
	}
	switch strings.TrimSpace(mode.Stdout) {
	case "Mode: Disable All":
		return out
	case "Mode: Enable All":
	default:
		out.Err = errors.New("cagefsctl --display-user-mode is not readable")
		return out
	}
	disabled := c.run(ctx, "cagefsctl", "--list-disabled")
	if disabled.Err != nil {
		out.Err = errors.New("cagefsctl --list-disabled failed")
		return out
	}
	for _, line := range strings.Split(disabled.Stdout, "\n") {
		switch name := strings.TrimSpace(line); {
		case name == "":
		case admission.ValidAccountName(name):
			out.DisabledUsers++
		default:
			out.Err = errors.New("cagefsctl --list-disabled printed a line CSM cannot read")
			return out
		}
	}
	out.Enabled = true
	return out
}

// roundcube reads whether cPanel's Roundcube loads inc.d and whether
// cPanel's PHP can verify the include.
func (c collector) roundcube(f antispam.HostFacts) antispam.RoundcubeFacts {
	var out antispam.RoundcubeFacts
	for _, t := range f.Targets {
		if t.Path == antispam.RoundcubeIncludePath {
			out.Include = t
		}
	}
	if out.Include.Path == "" {
		out.Err = errors.New("the Roundcube include was not checked")
	}
	conf, err := readText(c.layout.RoundcubeConfig)
	if err != nil {
		out.Err = errors.New("cannot read cPanel's Roundcube configuration")
	} else {
		out.IncludeMechanism = strings.Contains(conf, roundcubeIncludeGlob)
	}
	info, err := os.Stat(c.layout.CPanelPHP)
	switch {
	case err == nil:
		out.PHP = info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
	case !errors.Is(err, fs.ErrNotExist):
		out.Err = errors.Join(out.Err, errors.New("cannot check cPanel's PHP executable"))
	}
	return out
}

// accountNames lists the cPanel accounts by their user files.
func (c collector) accountNames() (map[string]bool, error) {
	entries, err := os.ReadDir(c.layout.CPanelUsers)
	if err != nil {
		return nil, errors.New("cannot list cPanel accounts")
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		if admission.ValidAccountName(e.Name()) {
			out[e.Name()] = true
		}
	}
	return out, nil
}

// redis identifies the fuzzy worker's Redis backend and probes it. CSM
// sends the password only to a Unix socket nobody but its owner or root could
// have put there, owned by a pinned service user; a TCP endpoint is never
// probed, it fails isolation anyway.
func (c collector) redis(ctx context.Context, f antispam.HostFacts) antispam.RedisFacts {
	if f.LearningDumps.Err != nil {
		return antispam.RedisFacts{ServiceUID: -1, Err: errors.New("rspamd's redis settings were not read")}
	}
	endpoint, unix, password, err := redisEndpoint(f.LearningDumps, []byte(f.RspamdConfig.Stdout))
	if err != nil {
		return antispam.RedisFacts{ServiceUID: -1, Err: err}
	}
	r := antispam.RedisFacts{Endpoint: endpoint, Unix: unix, ServiceUID: -1}
	if !unix {
		return r
	}
	r.Socket = unixSocketFacts(endpoint)
	if r.Socket.Err != nil || r.Socket.Missing {
		r.Err = errors.New("redis socket cannot be checked")
		return r
	}
	owner := r.Socket.Socket.UID
	gid := r.Socket.Socket.GID
	r.GroupMembers = c.groupMembers(map[int]bool{gid: true})[gid]
	if !c.trustedRedisOwner(owner, f) || !protectedRedisPath(endpoint, owner, pathFacts) {
		r.Unprotected = true
		r.Err = errors.New("redis socket is not protected; CSM sends it no password")
		return r
	}
	probed := c.redisProbe(ctx, endpoint, password, owner)
	probed.Endpoint, probed.Unix, probed.Socket, probed.GroupMembers = endpoint, unix, r.Socket, r.GroupMembers
	return probed
}

// trustedRedisOwner reports whether uid may serve the Redis socket: root,
// rspamd's service user or the system user named redis, and no cPanel
// account shares the uid. Any other owner, including shared users such as
// nobody that can run tenant code, gets no password.
func (c collector) trustedRedisOwner(uid int, f antispam.HostFacts) bool {
	if uid == 0 {
		return true
	}
	// A cPanel account can carry the name redis on a host without the
	// service user, and a uid can have several names; such a uid is a tenant.
	if f.AccountNamesErr != nil || f.AccountNames["redis"] {
		return false
	}
	for account := range f.AccountNames {
		if accountUID, err := c.uid(account); err != nil || accountUID == uid {
			return false
		}
	}
	if f.Socket.RspamdUID >= 0 && uid == f.Socket.RspamdUID {
		return true
	}
	redisUID, err := c.uid("redis")
	return err == nil && redisUID >= 0 && uid == redisUID
}

// protectedRedisPath verifies each lookup, including symlinks and repeated
// visits to a directory. Sticky protection depends on the entry being
// looked up, not the directory or socket it eventually resolves to.
func protectedRedisPath(endpoint string, owner int, stat func(string) (antispam.PathFacts, error)) bool {
	trusted := func(uid int) bool { return uid == 0 || uid == owner }
	unsafe := errors.New("redis socket path is not protected")
	_, _, err := resolveChecked(endpoint, func(dir, next string) error {
		p, err := stat(dir)
		if err != nil || !p.Mode.IsDir() || p.ExtACL || !trusted(p.UID) {
			return unsafe
		}
		if p.Mode.Perm()&0o022 == 0 {
			return nil
		}
		entry, err := stat(next)
		if err != nil || p.Mode&fs.ModeSticky == 0 || !trusted(entry.UID) {
			return unsafe
		}
		return nil
	})
	return err == nil
}
