package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Postconf is what CSM reads from postfix's main.cf.
type Postconf struct {
	// Milters are smtpd_milters as postfix names them, such as
	// inet:127.0.0.1:11332, without per-milter settings.
	Milters       []string
	DefaultAction string
	// SizeLimit is message_size_limit; 0 means no limit.
	SizeLimit      int64
	QueueDirectory string
	Version        string
}

// PostconfNames are the parameters the collector reads with one
// `postconf -x -h`, which prints one value per line in this order.
func PostconfNames() []string {
	return []string{"smtpd_milters", "milter_default_action", "message_size_limit", "queue_directory", "mail_version"}
}

// ParsePostconf reads `postconf -x -h` for PostconfNames.
func ParsePostconf(out string) (Postconf, error) {
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(PostconfNames()) {
		return Postconf{}, errors.New("postconf did not print one line per parameter")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[2]), 10, 64)
	if err != nil || size < 0 {
		return Postconf{}, errors.New("postconf message_size_limit is not a byte count")
	}
	queue := strings.TrimSpace(lines[3])
	if !strings.HasPrefix(queue, "/") {
		return Postconf{}, errors.New("postconf queue_directory is not an absolute path")
	}
	p := Postconf{DefaultAction: strings.TrimSpace(lines[1]), SizeLimit: size, QueueDirectory: queue, Version: strings.TrimSpace(lines[4])}
	// Postfix separates list items with whitespace or commas; braces group
	// a milter with its name=value settings.
	for _, item := range strings.FieldsFunc(lines[0], func(r rune) bool { return strings.ContainsRune(", \t\r{}", r) }) {
		if !strings.Contains(item, "=") {
			p.Milters = append(p.Milters, item)
		}
	}
	return p, nil
}

// SmtpdChrootFields are the master.cf fields the collector reads with
// `postconf -F`: which program serves port 25, and the chroot flag of that
// smtpd, or of the one postscreen passes connections to.
func SmtpdChrootFields() []string {
	return []string{"smtp/inet/command", "smtp/inet/chroot", "smtpd/pass/chroot"}
}

// SmtpdChroot reads `postconf -F` for SmtpdChrootFields and reports whether
// the smtpd that receives port-25 mail runs chrooted. version is
// mail_version: "-" selects the default, which became n in Postfix 3.0.
func SmtpdChroot(out, version string) (bool, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	command := strings.Fields(fields["smtp/inet/command"])
	if len(command) == 0 {
		return false, errors.New("postconf -F did not report the port 25 service")
	}
	var flag string
	switch path.Base(command[0]) {
	case "smtpd":
		flag = "smtp/inet/chroot"
	case "postscreen":
		flag = "smtpd/pass/chroot"
	default:
		return false, errors.New("port 25 is served by neither smtpd nor postscreen")
	}
	switch fields[flag] {
	case "y":
		return true, nil
	case "n":
		return false, nil
	case "-":
		major, _, _ := strings.Cut(version, ".")
		if n, err := strconv.Atoi(major); err == nil {
			return n < 3, nil
		}
		return false, errors.New("postfix mail_version is not readable")
	}
	return false, errors.New("postconf -F did not report a readable chroot flag")
}

// MilterAddrs returns the address CSM, which runs outside postfix's chroot,
// reaches each milter at: inet: milters as written, unix: paths under
// queue_directory when smtpd reads them there. Postfix daemons run in the
// queue directory, so a relative path always is; an absolute path is when
// smtpd runs chrooted, which master, `postconf -F` for SmtpdChrootFields,
// shows. When it does not, absolute unix: milters are left out and complete
// is false. Milters of other transports are left out.
func (p Postconf) MilterAddrs(master CommandResult) (addrs []string, complete bool) {
	complete = true
	queue := strings.TrimRight(p.QueueDirectory, "/")
	for _, m := range p.Milters {
		if strings.HasPrefix(m, "inet:") {
			addrs = append(addrs, m)
			continue
		}
		sock, ok := strings.CutPrefix(m, "unix:")
		if !ok || sock == "" {
			continue
		}
		if strings.HasPrefix(sock, "/") {
			chroot, err := SmtpdChroot(master.Stdout, p.Version)
			if master.Err != nil || err != nil {
				complete = false
				continue
			}
			if !chroot {
				addrs = append(addrs, m)
				continue
			}
		}
		// The kernel resolves the joined path; cleaning it could change
		// its target where a symlink precedes "..".
		addrs = append(addrs, "unix:"+queue+"/"+strings.TrimPrefix(sock, "/"))
	}
	return addrs, complete
}

// ProxyMilterAddrs reads `rspamadm configdump -j worker`, which prints one
// object per worker, and returns the bind addresses of the running
// rspamd_proxy workers that speak the milter protocol. The dump also holds
// the controller password, so errors never quote it.
func ProxyMilterAddrs(workerDump []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(workerDump))
	var addrs []string
	for n := 0; ; n++ {
		var entry json.RawMessage
		if err := dec.Decode(&entry); errors.Is(err, io.EOF) && n > 0 {
			return addrs, nil
		} else if err != nil {
			return nil, errors.New("configdump worker: invalid JSON")
		}
		proxy, err := workerOfKind(entry, "rspamd_proxy")
		if err != nil {
			return nil, err
		}
		if proxy == nil {
			continue
		}
		binds, err := milterBinds(proxy)
		if err != nil {
			return nil, errors.New("configdump worker rspamd_proxy: settings are not readable")
		}
		addrs = append(addrs, binds...)
	}
}

// milterBinds returns a proxy worker's bind addresses when rspamd runs it
// as a milter.
func milterBinds(proxy json.RawMessage) ([]string, error) {
	fields, err := dumpObjectAs[json.RawMessage](proxy, "worker rspamd_proxy")
	if err != nil {
		return nil, err
	}
	disabled, err := disabledWorker(fields)
	if err != nil || disabled {
		return nil, err
	}
	milter, err := workerBool(fields, "milter", false)
	if err != nil || !milter {
		return nil, err
	}
	return workerBinds(fields)
}

var errNotWired = errors.New("postfix does not pass mail to rspamd's proxy worker")

// RspamdMilters returns the postfix milters that reach rspamd's proxy
// worker, as MilterAddrs resolves them and as smtpd_milters names them.
// Errors quote no command output.
func RspamdMilters(f HostFacts) (addrs, names []string, err error) {
	pc, err := ParsePostconf(f.Postconf.Stdout)
	if f.Postconf.Err != nil || err != nil {
		return nil, nil, errors.New("postconf did not report postfix's milters")
	}
	binds, err := ProxyMilterAddrs([]byte(f.RspamdWorkers.Stdout))
	if f.RspamdWorkers.Err != nil || err != nil {
		return nil, nil, errors.New("rspamadm configdump did not report rspamd's proxy worker")
	}
	for _, m := range pc.Milters {
		one := pc
		one.Milters = []string{m}
		resolved, _ := one.MilterAddrs(f.PostfixMaster)
		if MilterWired(resolved, binds) {
			addrs, names = append(addrs, resolved...), append(names, m)
		}
	}
	if len(addrs) == 0 {
		return nil, nil, errNotWired
	}
	return addrs, names, nil
}

// ScanSource is where CSM reads a Postfix host's scan records (spec section
// 5.2): Log is the rspamd log file, "" when rspamd logs elsewhere, and
// Milters are the milters that reach rspamd as smtpd_milters names them,
// the way postfix's warnings name a milter that failed. MilterAction is
// milter_default_action, what postfix does with mail while a milter fails.
// Stack is StackPostfix; the zero ScanSource stands for any other host.
type ScanSource struct {
	Stack        MailStack
	Log          string
	Milters      []string
	MilterAction string
}

// PostfixScanSource reads the ScanSource of a Postfix host. ok is false
// when rspamd's logging settings, postconf or rspamd's worker dump could
// not be read.
func PostfixScanSource(f HostFacts) (src ScanSource, ok bool) {
	switch {
	case f.RspamdLog.Type == "":
		return ScanSource{}, false
	// A log CSM could not inspect is still the file rspamd writes.
	case f.RspamdLog.Type == "file" && path.IsAbs(f.RspamdLog.Path):
		src.Log = f.RspamdLog.Path
	}
	_, names, err := RspamdMilters(f)
	if err != nil && !errors.Is(err, errNotWired) {
		return ScanSource{}, false
	}
	// RspamdMilters has read postconf.
	pc, _ := ParsePostconf(f.Postconf.Stdout)
	src.Stack, src.Milters, src.MilterAction = StackPostfix, names, pc.DefaultAction
	return src, true
}

// MilterWired reports whether any postfix milter reaches one of the proxy
// worker's bind addresses.
func MilterWired(milters, proxyAddrs []string) bool {
	for _, m := range milters {
		for _, b := range proxyAddrs {
			if milterReaches(m, b) {
				return true
			}
		}
	}
	return false
}

// milterReaches matches a unix: milter to the same socket path, and an
// inet: milter to a listener on the same port that accepts its address.
func milterReaches(milter, bind string) bool {
	// rspamd puts socket options after the address, split by spaces or commas.
	fields := strings.FieldsFunc(bind, func(r rune) bool { return r == ' ' || r == ',' })
	if len(fields) == 0 {
		return false
	}
	if sock, ok := strings.CutPrefix(milter, "unix:"); ok {
		return strings.HasPrefix(fields[0], "/") && sock == fields[0]
	}
	hostPort, ok := strings.CutPrefix(milter, "inet:")
	if !ok {
		return false
	}
	mh, mp, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	bh, bp, err := net.SplitHostPort(fields[0])
	if err != nil || mp != bp {
		return false
	}
	if strings.EqualFold(mh, bh) {
		return true
	}
	for _, a := range hostAddrs(mh) {
		if slices.Contains(hostAddrs(bh), a) {
			return true
		}
		// A wildcard listener here says nothing about another host's
		// rspamd, so only loopback milters match one.
		if a.IsLoopback() && anyAddress(bh, a) {
			return true
		}
	}
	return false
}

// hostAddrs returns the addresses host stands for: itself, or localhost's
// loopback addresses. Other names are not resolved.
func hostAddrs(host string) []netip.Addr {
	if strings.EqualFold(host, "localhost") {
		return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}
	}
	return nil
}

// anyAddress reports whether a listener bound to host accepts every address
// of a's family: rspamd's *, *v4 and *v6, or an unspecified address.
func anyAddress(host string, a netip.Addr) bool {
	switch host {
	case "*":
		return true
	case "*v4":
		return a.Is4()
	case "*v6":
		return a.Is6()
	}
	b, err := netip.ParseAddr(host)
	return err == nil && b.IsUnspecified() && b.Unmap().Is4() == a.Is4()
}
