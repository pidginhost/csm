package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

// OptionalUsable reports why CSM cannot write optional target t, or nil:
// its directory must exist, every parent and the file must be protected
// root-owned objects, and an existing file must be CSM's. The daemon leaves
// out the feed or redirect that needs t; the worker refuses to write it.
func OptionalUsable(t TargetFacts) error {
	if t.Err != nil {
		if errors.Is(t.Err, fs.ErrNotExist) {
			return fmt.Errorf("the directory %s is missing", path.Dir(t.Path))
		}
		return fmt.Errorf("cannot check %s; check file access", t.Path)
	}
	if len(t.Parents) == 0 {
		return fmt.Errorf("the parent directories of %s were not checked", t.Path)
	}
	for _, p := range t.Parents {
		if !p.Mode.IsDir() {
			return fmt.Errorf("%s is not a directory", p.Path)
		}
		if problem := unprotected(p); problem != "" {
			return fmt.Errorf("%s %s", p.Path, problem)
		}
	}
	if t.Missing {
		return nil
	}
	if !t.File.Mode.IsRegular() {
		return fmt.Errorf("%s is not a regular file", t.Path)
	}
	if problem := unprotected(t.File); problem != "" {
		return fmt.Errorf("%s %s", t.Path, problem)
	}
	if !ManagedFor(t.Kind, t.Content) {
		return fmt.Errorf("%s is not managed by CSM", t.Path)
	}
	return nil
}

// SecretFileMode is the mode of a file holding a secret, such as
// override.d/rbl.conf with the DQS key: rspamd reads it through its group,
// nobody else can.
const SecretFileMode fs.FileMode = 0o640

// SecretPaths lists every file that can hold a secret: the DQS key in the
// rbl override, the learning keys in the fuzzy rules and worker.
func SecretPaths() []string {
	return []string{FeedRBLPath, LearningCheckPath, LearningWorkerPath}
}

// SecretTargets lists the SecretPaths that hold a secret under s.
func (s Settings) SecretTargets() []string {
	var out []string
	if s.HasFeed(FeedSpamhausDQS) {
		out = append(out, FeedRBLPath)
	}
	if s.Learning {
		out = append(out, LearningCheckPath, LearningWorkerPath)
	}
	return out
}

// secretFileOK reports whether secret file p is root-owned, in rspamd's
// group and exactly mode SecretFileMode, without set-id or sticky bits.
func secretFileOK(f HostFacts, p string) bool {
	for _, t := range f.Targets {
		if t.Path == p {
			return t.Err == nil && !t.Missing && t.File.UID == 0 && f.RspamdGID >= 0 &&
				t.File.GID == f.RspamdGID && t.File.Mode == SecretFileMode
		}
	}
	return false
}

var errNoSystemNameserver = errors.New("rspamd has no nameserver in /etc/resolv.conf")

// Nameservers returns the resolvers rspamd uses: options.dns.nameserver
// (or its aliases) when set, else the nameserver lines of resolv.conf. An
// entry CSM cannot parse is an error, never proof of a private resolver.
func Nameservers(options []byte, resolvConf string) ([]netip.AddrPort, error) {
	opts, err := dumpObjectAs[json.RawMessage](options, "options")
	if err != nil {
		return nil, errors.New("rspamd's options are not readable")
	}
	var settings []json.RawMessage
	if raw, ok := opts["dns_nameserver"]; ok {
		settings = append(settings, raw)
	}
	if raw, ok := opts["dns"]; ok {
		dns, err := dumpObjectAs[json.RawMessage](raw, "dns")
		if err != nil {
			return nil, errors.New("rspamd's DNS options are not readable")
		}
		for _, name := range []string{"nameserver", "server"} {
			if raw, ok := dns[name]; ok {
				settings = append(settings, raw)
			}
		}
	}
	// configdump omits UCL priorities, so competing aliases cannot establish
	// which resolver rspamd selected.
	if len(settings) > 1 {
		return nil, errors.New("rspamd has multiple nameserver settings; use only dns.nameserver")
	}
	var entries []string
	if len(settings) == 1 {
		raw := settings[0]
		var one string
		if err := json.Unmarshal(raw, &one); err == nil {
			entries = []string{one}
		} else if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, errors.New("rspamd's dns.nameserver is neither a string nor a list of strings")
		}
	} else {
		for _, line := range strings.Split(resolvConf, "\n") {
			line, _, _ = strings.Cut(line, "#")
			if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
				entries = append(entries, fields[1])
			}
		}
		if len(entries) == 0 {
			return nil, errNoSystemNameserver
		}
	}
	var out []netip.AddrPort
	for _, entry := range entries {
		// rspamd compares rotation names without case.
		for _, prefix := range []string{"master-slave:", "round-robin:", "random:", "hash:"} {
			if len(entry) >= len(prefix) && strings.EqualFold(entry[:len(prefix)], prefix) {
				entry = entry[len(prefix):]
				break
			}
		}
		parts := strings.FieldsFunc(entry, func(r rune) bool { return strings.ContainsRune(";, \n\r\t", r) })
		if len(parts) == 0 {
			return nil, errors.New("rspamd has an empty nameserver entry")
		}
		for _, part := range parts {
			addr, err := nameserverEndpoint(part)
			if err != nil {
				return nil, err
			}
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("rspamd has no nameserver")
	}
	return out, nil
}

// nameserverEndpoint reads one rspamd nameserver entry: an address, optionally
// with a port and a weight (host:port:weight), IPv6 in brackets when a port
// follows. Keep the port and IPv6 scope so probes reach the same resolver.
func nameserverEndpoint(s string) (netip.AddrPort, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(addr, 53), nil
	}
	invalid := errors.New("rspamd has an invalid nameserver; use an IP address with an optional numeric port and weight")
	host, suffix := s, ""
	port := uint16(53)
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return netip.AddrPort{}, invalid
		}
		host, suffix = s[1:end], s[end+1:]
	} else if i := strings.Index(s, ":"); i > 0 {
		host, suffix = s[:i], s[i:]
	}
	if suffix != "" {
		if suffix[0] != ':' {
			return netip.AddrPort{}, invalid
		}
		parts := strings.Split(suffix[1:], ":")
		if len(parts) > 2 {
			return netip.AddrPort{}, invalid
		}
		value, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return netip.AddrPort{}, invalid
		}
		port = uint16(value)
		if len(parts) == 2 {
			// rspamd weights are unsigned integers.
			if _, err := strconv.ParseUint(parts[1], 10, 32); err != nil {
				return netip.AddrPort{}, invalid
			}
		}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, invalid
	}
	return netip.AddrPortFrom(addr, port), nil
}

// localResolver reports whether rspamd's queries stay on this host or a
// private network. Lists refuse public resolvers (feeds spec 4.4).
func localResolver(a netip.Addr) bool { return a.IsLoopback() || a.IsPrivate() }

const resolverFix = "DNS blocklists refuse queries from public resolvers. Run a local recursive resolver and add dns { nameserver = ['127.0.0.1']; } to /etc/rspamd/local.d/options.inc"

// ResolveFeeds returns the settings this host can take. Map redirects whose
// file CSM cannot own are skipped; DNS feeds go off when their files cannot
// be written or rspamd's resolver is not local; spamhaus_dqs goes off when
// its key file or rspamd's group is unusable. Each is a Warning: a feed
// problem never blocks core (feeds spec section 8.1).
func ResolveFeeds(s Settings, f HostFacts) (Settings, []Problem) {
	// Dropping a temporarily unusable feed must not alter the desired settings
	// that callers retain for the next pass.
	s.Feeds = slices.Clone(s.Feeds)
	if ok, why := FeedsSupported(f.RspamdVersion); !ok {
		return withoutFeeds(s, why)
	}
	var problems []Problem
	targets := make(map[string]TargetFacts, len(f.Targets))
	for _, t := range f.Targets {
		targets[t.Path] = t
	}
	usable := func(p string) error {
		t, ok := targets[p]
		if !ok {
			return fmt.Errorf("%s was not checked", p)
		}
		return OptionalUsable(t)
	}
	s.SkipMaps = nil
	if s.Redirects() {
		for _, name := range MapRedirectNames() {
			if err := usable(RedirectPath(name)); err != nil {
				s.SkipMaps = append(s.SkipMaps, name)
				problems = append(problems, Problem{Code: CodeFeed, Severity: Warning, Key: FeedRspamdMaps,
					Detail: fmt.Sprintf("%v, so rspamd keeps fetching that map from rspamd.com; remove or rename it so CSM can point it at a local copy", err)})
			}
		}
	}
	drop := func(feeds []string, detail string) {
		for _, name := range feeds {
			problems = append(problems, Problem{Code: CodeFeed, Severity: Warning, Key: name,
				Detail: "feed " + name + " is off: " + detail})
		}
		s.Feeds = slices.DeleteFunc(s.Feeds, func(n string) bool { return slices.Contains(feeds, n) })
	}
	var dns []string
	for _, feed := range s.DNSFeeds() {
		dns = append(dns, feed.Name)
	}
	if len(dns) > 0 {
		reason := ""
		for _, p := range []string{FeedRBLPath, FeedRBLGroupPath} {
			if err := usable(p); err != nil && reason == "" {
				reason = err.Error()
			}
		}
		if reason == "" {
			servers, err := Nameservers([]byte(f.RspamdOptions.Stdout), f.ResolvConf)
			switch {
			case f.RspamdOptions.Err != nil:
				reason = "CSM cannot read which nameservers rspamd uses. " + resolverFix
			case errors.Is(err, errNoSystemNameserver) && f.ResolvConfErr != nil:
				reason = "CSM cannot read /etc/resolv.conf, which rspamd uses without dns.nameserver. " + resolverFix
			case err != nil:
				reason = err.Error() + ". " + resolverFix
			case slices.ContainsFunc(servers, func(a netip.AddrPort) bool { return !localResolver(a.Addr()) }):
				reason = "rspamd uses a public nameserver. " + resolverFix
			}
		}
		if reason != "" {
			drop(dns, reason)
		}
	}
	if s.HasFeed(FeedCSMIPMap) {
		if err := usable(RedirectPath(RedirectMultimap)); err != nil {
			drop([]string{FeedCSMIPMap}, err.Error())
		} else if err := f.IPMap.UsableByRspamd(f.RspamdGID); err != nil {
			drop([]string{FeedCSMIPMap}, err.Error())
		}
	}
	if s.HasFeed(FeedSpamhausDQS) {
		key, err := LoadDQSKey(f.DQSKey)
		exposed, why := f.RspamdLog.Exposed(f.Socket.RspamdUID, f.RspamdGID)
		switch {
		case err != nil:
			drop([]string{FeedSpamhausDQS}, err.Error())
		case exposed:
			drop([]string{FeedSpamhausDQS}, why+", and rspamd writes failed DQS lookups, which contain the key, to it; "+
				"use a private file log owned by root or rspamd, with only root or rspamd group access and no extra ACLs")
		case f.RspamdGID < 0:
			drop([]string{FeedSpamhausDQS}, "rspamd's group is unknown, so CSM cannot make the key file readable by rspamd only")
		default:
			s.DQSKey = key
		}
	}
	if !s.HasFeed(FeedSpamhausDQS) {
		s.DQSKey = Secret{}
	}
	return s, problems
}

// FileFacts is one file as the collector found it; File is set unless
// Missing or Err.
type FileFacts struct {
	Missing bool
	File    PathFacts
	Parents []PathFacts
	Err     error
}

// UsableByRspamd checks the IP map's private, root-owned file contract.
// Both resolution and the worker check it because the file can change
// while a request waits to apply.
func (f FileFacts) UsableByRspamd(gid int) error {
	switch {
	case gid < 0:
		return errors.New("rspamd's group is unknown, so CSM cannot make the IP map readable by rspamd only")
	case f.Missing:
		return errors.New("CSM has not written the IP map yet")
	case f.Err != nil || f.File.Path == "":
		return errors.New("CSM cannot check the IP map; check file access")
	case f.File.Mode != 0o640 || f.File.UID != 0 || f.File.GID != gid || f.File.ExtACL:
		return errors.New("the IP map must be a regular root-owned file, mode 0640, in rspamd's group, with no extra ACLs")
	}
	if len(f.Parents) == 0 {
		return errors.New("the IP map's parent directories were not checked")
	}
	for _, p := range f.Parents {
		if !p.Mode.IsDir() {
			return fmt.Errorf("IP map parent %s is not a directory", p.Path)
		}
		if why := unprotected(p); why != "" {
			return fmt.Errorf("IP map parent %s %s", p.Path, why)
		}
		search := fs.FileMode(0o001)
		if p.GID == gid {
			search = 0o010
		}
		if p.Mode&search == 0 {
			return fmt.Errorf("rspamd cannot traverse IP map parent %s", p.Path)
		}
	}
	return nil
}

// LogFacts is rspamd's log destination as the collector found it. Type is
// rspamd's logging.type; for a file, File and Parents describe the log
// file (unset when Missing) and its directories.
type LogFacts struct {
	Type    string
	Path    string
	Missing bool
	File    PathFacts
	Parents []PathFacts
	Err     error
}

// Exposed reports whether users other than root and rspamd may read
// rspamd's log: rspamd writes every failed lookup name there, and DQS
// lookup names hold the key. A log CSM cannot check counts as exposed; a
// file rspamd has yet to create counts as readable unless a private parent
// protects it. Console and syslog routing cannot establish file privacy.
func (l LogFacts) Exposed(uid, gid int) (bool, string) {
	unknown := "CSM cannot check who can read rspamd's log"
	switch {
	case l.Err != nil:
		return true, unknown
	case l.Type != "file" || !path.IsAbs(l.Path) || len(l.Parents) == 0:
		return true, unknown
	case path.Clean(l.Path) != l.Path:
		// Cleaned parent facts can omit a symlink traversed before "..".
		return true, unknown
	}
	trustedGroup := func(id int) bool { return id == 0 || gid >= 0 && id == gid }
	protected := func(p PathFacts) bool {
		return (p.UID == 0 || uid >= 0 && p.UID == uid) && !p.ExtACL &&
			p.Mode.Perm()&0o002 == 0 && (p.Mode.Perm()&0o020 == 0 || trustedGroup(p.GID))
	}
	private := func(p PathFacts, other, group fs.FileMode) bool {
		return p.Mode.Perm()&other == 0 && (p.Mode.Perm()&group == 0 || trustedGroup(p.GID))
	}
	closed := false
	for _, p := range l.Parents {
		if !p.Mode.IsDir() || !protected(p) {
			return true, unknown
		}
		closed = closed || private(p, 0o001, 0o010)
	}
	if !l.Missing && (!l.File.Mode.IsRegular() || !protected(l.File)) {
		return true, unknown
	}
	if !closed && (l.Missing || !private(l.File, 0o004, 0o040)) {
		return true, "rspamd's log " + l.Path + " is readable by other users"
	}
	return false, ""
}

// minFeedsRspamdMajor is the rspamd release CSM's feed files and map
// redirects were verified on.
const minFeedsRspamdMajor = 4

// FeedsSupported reports whether rspamd is recent enough for feed files
// and map redirects, and why not.
func FeedsSupported(version CommandResult) (bool, string) {
	if version.Err != nil {
		return false, "rspamd's version is unknown"
	}
	v, major, err := ParseRspamdVersion(version.Stdout)
	switch {
	case err != nil:
		return false, "rspamd's version is unknown"
	case major < minFeedsRspamdMajor:
		return false, "rspamd " + v + " is older than 4"
	}
	return true, ""
}

// withoutFeeds leaves rspamd's own lists and maps alone, as rspamd_maps
// does, rather than risk files rspamd rejects, which would block core.
func withoutFeeds(s Settings, why string) (Settings, []Problem) {
	var problems []Problem
	for _, feed := range s.DNSFeeds() {
		problems = append(problems, Problem{Code: CodeFeed, Severity: Warning, Key: feed.Name,
			Detail: "feed " + feed.Name + " is off: " + why + "; CSM's feed rules need rspamd 4 or later"})
	}
	if s.HasFeed(FeedCSMIPMap) {
		problems = append(problems, Problem{Code: CodeFeed, Severity: Warning, Key: FeedCSMIPMap,
			Detail: "feed " + FeedCSMIPMap + " is off: " + why + "; CSM's feed rules need rspamd 4 or later"})
	}
	if s.Redirects() {
		problems = append(problems, Problem{Code: CodeFeed, Severity: Warning, Key: FeedRspamdMaps,
			Detail: why + ", so CSM leaves rspamd's own maps alone and they keep downloading from rspamd.com; upgrade rspamd to 4 or later"})
	}
	s.Feeds = slices.DeleteFunc(slices.Clone(s.Feeds), func(name string) bool {
		f, _ := FeedByName(name)
		return f.DNS() || name == FeedCSMIPMap
	})
	if !s.HasFeed(FeedRspamdMaps) {
		s.Feeds = append(s.Feeds, FeedRspamdMaps)
	}
	s.SkipMaps, s.DQSKey = nil, Secret{}
	return s, problems
}
