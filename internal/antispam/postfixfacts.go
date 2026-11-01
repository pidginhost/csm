package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParsePostconf reads `postconf -x -h smtpd_milters milter_default_action
// message_size_limit`: one value per line, in that order. Milters come back
// as postfix names them, such as inet:127.0.0.1:11332, without per-milter
// settings. A message_size_limit of 0 means no limit.
func ParsePostconf(out string) (milters []string, defaultAction string, sizeLimit int64, err error) {
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 {
		return nil, "", 0, errors.New("postconf did not print three values")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[2]), 10, 64)
	if err != nil || size < 0 {
		return nil, "", 0, errors.New("postconf message_size_limit is not a byte count")
	}
	// Postfix separates list items with whitespace or commas; braces group
	// a milter with its name=value settings.
	for _, item := range strings.FieldsFunc(lines[0], func(r rune) bool { return strings.ContainsRune(", \t\r{}", r) }) {
		if !strings.Contains(item, "=") {
			milters = append(milters, item)
		}
	}
	return milters, strings.TrimSpace(lines[1]), size, nil
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
// inet: milter to the same host and port. A loopback milter also reaches
// rspamd's wildcard and localhost listeners; a milter on another host
// reaches another rspamd, whatever this one listens on.
func milterReaches(milter, bind string) bool {
	// rspamd puts socket options after the address, split by spaces or commas.
	fields := strings.FieldsFunc(bind, func(r rune) bool { return r == ' ' || r == ',' })
	if len(fields) == 0 {
		return false
	}
	if path, ok := strings.CutPrefix(milter, "unix:"); ok {
		return strings.HasPrefix(fields[0], "/") && path == fields[0]
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
	switch {
	case err != nil || mp != bp:
		return false
	case strings.EqualFold(mh, bh):
		return true
	case !loopback(mh):
		return false
	}
	return bh == "*" || loopback(bh) && (strings.EqualFold(mh, "localhost") || strings.EqualFold(bh, "localhost"))
}

// loopback reports whether host names this machine's loopback interface.
func loopback(host string) bool {
	a, err := netip.ParseAddr(host)
	return strings.EqualFold(host, "localhost") || err == nil && a.IsLoopback()
}
