package hostfacts

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
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
		return []byte(r.Stdout)
	}
	d.FuzzyCheck = read("fuzzy_check")
	d.Group = read("group")
	d.Redis = read("redis")
	var root map[string]json.RawMessage
	switch {
	case f.RspamdConfig.Err != nil:
		errs = append(errs, errors.New("rspamadm configdump -j failed"))
	case json.Unmarshal([]byte(f.RspamdConfig.Stdout), &root) != nil:
		errs = append(errs, errors.New("rspamadm configdump -j is not readable"))
	default:
		d.Worker = root["worker"]
	}
	d.Err = errors.Join(errs...)
	f.LearningDumps = d
}

// controlSocket reads options.control_socket, without its mode option.
func (c collector) controlSocket(f *antispam.HostFacts) {
	var opts map[string]json.RawMessage
	var value string
	switch {
	case f.RspamdOptions.Err != nil:
		f.ControlSocket.Err = errors.New("rspamadm configdump -j options failed")
	case json.Unmarshal([]byte(f.RspamdOptions.Stdout), &opts) != nil:
		f.ControlSocket.Err = errors.New("rspamd's options are not readable")
	case opts["control_socket"] == nil:
		f.ControlSocket.Err = errors.New("rspamd reports no control_socket")
	case json.Unmarshal(opts["control_socket"], &value) != nil:
		f.ControlSocket.Err = errors.New("control_socket is not a string")
	default:
		path, _, _ := strings.Cut(strings.TrimSpace(value), " ")
		if !strings.HasPrefix(path, "/") {
			f.ControlSocket.Err = errors.New("control_socket is not a Unix socket path")
			return
		}
		f.ControlSocket = unixSocketFacts(path)
	}
}

// fuzzyListening reports whether a UDP socket is bound to 127.0.0.1:11335.
// rspamd does not respawn a fuzzy worker that exited (spike S4).
func (c collector) fuzzyListening() (bool, error) {
	data, err := os.ReadFile(c.layout.ProcNetUDP)
	if err != nil {
		return false, errors.New("cannot read the UDP socket table")
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) > 3 && fields[1] == fuzzyListenAddr && fields[3] == "07" {
			return true, nil
		}
	}
	return false, nil
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
	if status.Err != nil || strings.TrimSpace(status.Stdout) != "Enabled" {
		return out
	}
	mode := c.run(ctx, "cagefsctl", "--display-user-mode")
	if mode.Err != nil || strings.TrimSpace(mode.Stdout) != "Mode: Enable All" {
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
	if info, err := os.Stat(c.layout.CPanelPHP); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		out.PHP = true
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

// redis identifies the fuzzy worker's Redis backend and probes it. A Unix
// socket's facts and group members feed the isolation check.
func (c collector) redis(ctx context.Context, f antispam.HostFacts) antispam.RedisFacts {
	if f.LearningDumps.Err != nil {
		return antispam.RedisFacts{ServiceUID: -1, Err: errors.New("rspamd's redis settings were not read")}
	}
	endpoint, unix, password, err := redisEndpoint(f.LearningDumps, []byte(f.RspamdConfig.Stdout))
	if err != nil {
		return antispam.RedisFacts{ServiceUID: -1, Err: err}
	}
	r := c.redisProbe(ctx, endpoint, password)
	r.Endpoint, r.Unix = endpoint, unix
	if unix {
		r.Socket = unixSocketFacts(endpoint)
		if r.Socket.Err == nil && !r.Socket.Missing {
			gid := r.Socket.Socket.GID
			r.GroupMembers = c.groupMembers(map[int]bool{gid: true})[gid]
		}
	}
	return r
}
