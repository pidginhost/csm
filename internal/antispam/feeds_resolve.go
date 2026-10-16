package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"slices"
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
	if !IsManaged(t.Content) {
		return fmt.Errorf("%s is not managed by CSM", t.Path)
	}
	return nil
}

// SecretFileMode is the mode of override.d/rbl.conf while it holds the DQS
// key: rspamd reads it through its group, nobody else can.
const SecretFileMode fs.FileMode = 0o640

// secretFileOK reports whether override.d/rbl.conf is root-owned, in
// rspamd's group and mode SecretFileMode.
func secretFileOK(f HostFacts) bool {
	for _, t := range f.Targets {
		if t.Path == FeedRBLPath {
			return t.Err == nil && !t.Missing && t.File.UID == 0 && f.RspamdGID >= 0 &&
				t.File.GID == f.RspamdGID && t.File.Mode.Perm() == SecretFileMode
		}
	}
	return false
}

// Nameservers returns the resolvers rspamd uses: options.dns.nameserver
// when set, else the nameserver lines of resolv.conf. An entry CSM cannot
// parse is an error, so an unreadable setting never passes as private.
func Nameservers(options []byte, resolvConf string) ([]netip.Addr, error) {
	var opts struct {
		DNS struct {
			Nameserver json.RawMessage `json:"nameserver"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, errors.New("rspamd's options are not readable")
	}
	var entries []string
	if raw := opts.DNS.Nameserver; len(raw) > 0 {
		var one string
		if err := json.Unmarshal(raw, &one); err == nil {
			entries = []string{one}
		} else if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, errors.New("rspamd's dns.nameserver is neither a string nor a list of strings")
		}
	} else {
		for _, line := range strings.Split(resolvConf, "\n") {
			if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
				entries = append(entries, fields[1])
			}
		}
	}
	var out []netip.Addr
	for _, entry := range entries {
		for _, prefix := range []string{"master-slave:", "round-robin:", "random:"} {
			entry = strings.TrimPrefix(entry, prefix)
		}
		for _, part := range strings.Split(entry, ",") {
			addr, err := nameserverAddr(strings.TrimSpace(part))
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

// nameserverAddr reads one rspamd nameserver entry: an address, optionally
// with a port and a weight (host:port:weight), IPv6 in brackets when a port
// follows. A zone suffix (fe80::1%eth0) is dropped.
func nameserverAddr(s string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.WithZone(""), nil
	}
	host := s
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			host = s[1:end]
		}
	} else if i := strings.Index(s, ":"); i > 0 {
		host = s[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("rspamd nameserver %q is not an IP address", s)
	}
	return addr.WithZone(""), nil
}

// localResolver reports whether rspamd's queries stay on this host or a
// private network. Lists refuse public resolvers (feeds spec 4.4).
func localResolver(a netip.Addr) bool { return a.IsLoopback() || a.IsPrivate() }

const resolverFix = "DNS blocklists refuse queries from public resolvers. Run a local recursive resolver and add dns { nameserver = [\"127.0.0.1\"]; } to /etc/rspamd/local.d/options.inc"

// ResolveFeeds returns the settings this host can take. Map redirects whose
// file CSM cannot own are skipped; DNS feeds go off when their files cannot
// be written or rspamd's resolver is not local; spamhaus_dqs goes off when
// its key file or rspamd's group is unusable. Each is a Warning: a feed
// problem never blocks core (feeds spec section 8.1).
func ResolveFeeds(s Settings, f HostFacts) (Settings, []Problem) {
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
			case err != nil:
				reason = err.Error() + ". " + resolverFix
			case slices.ContainsFunc(servers, func(a netip.Addr) bool { return !localResolver(a) }):
				reason = "rspamd uses a public nameserver. " + resolverFix
			}
		}
		if reason != "" {
			drop(dns, reason)
		}
	}
	if s.HasFeed(FeedSpamhausDQS) {
		key, err := LoadDQSKey(f.DQSKey)
		switch {
		case err != nil:
			drop([]string{FeedSpamhausDQS}, err.Error())
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
