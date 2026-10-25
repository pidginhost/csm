package emailspool

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// maxSourcePreamble bounds how much of an -H file ReadSource reads. The
// options preamble is a few hundred bytes; ACL values can make it larger.
const maxSourcePreamble = 64 << 10

// maxSourceKey bounds the length of a source key.
const maxSourceKey = 255

// ReadSource returns the key of the party that sent a message, read from the
// options preamble of its Exim -H file: "auth:<id>" for an authenticated
// client, else "ip:<addr>" for a remote host (an IPv6 host as its /64), else
// "uid:<n>" for the local user that submitted it. It reads at most
// maxSourcePreamble bytes and errors only when no key can be found.
func ReadSource(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, maxSourcePreamble))
	var uid, auth, host string
	for lineNo := 1; ; lineNo++ {
		line, err := br.ReadString('\n')
		// A partial identity at EOF or the read limit is not a source key.
		// Otherwise padding could split one sender across several gates.
		if err != nil {
			break
		}
		line = strings.TrimSuffix(line, "\n")
		if lineNo <= 4 {
			if lineNo == 2 {
				uid = sourceUID(line)
			}
			continue
		}
		name, value, ok := sourceOption(line)
		if !ok {
			break
		}
		if name == "acl" || name == "aclc" || name == "aclm" {
			// The value follows on the next lines and may hold newlines, so
			// skip it by its length, plus the newline after it.
			n, perr := strconv.Atoi(lastSourceField(value))
			if perr != nil || n < 0 || n >= maxSourcePreamble {
				break
			}
			if _, cerr := io.CopyN(io.Discard, br, int64(n)+1); cerr != nil {
				break
			}
			continue
		}
		switch name {
		case "auth_id":
			if auth == "" {
				auth = sourceAuth(value)
			}
		case "host_address":
			if host == "" {
				host = sourceHost(value)
			}
		}
	}
	switch {
	case auth != "":
		return auth, nil
	case host != "":
		return host, nil
	case uid != "":
		return uid, nil
	}
	return "", errors.New("emailspool: no message source in header")
}

// sourceOption splits an options line into its name and value. Exim marks a
// tainted value with a second dash and may name its quoter in parentheses.
func sourceOption(line string) (name, value string, ok bool) {
	rest, ok := strings.CutPrefix(line, "-")
	if !ok {
		return "", "", false
	}
	rest = strings.TrimPrefix(rest, "-")
	if strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return "", "", false
		}
		rest = rest[end+1:]
	}
	name, value, _ = strings.Cut(rest, " ")
	return name, value, name != ""
}

func lastSourceField(s string) string {
	s = strings.TrimRight(s, " ")
	if i := strings.LastIndexByte(s, ' '); i >= 0 {
		return s[i+1:]
	}
	return s
}

// sourceUID reads the uid from line 2, "<login> <uid> <gid>".
func sourceUID(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	n, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return ""
	}
	return "uid:" + strconv.FormatUint(n, 10)
}

// sourceAuth accepts only printable ASCII ids that fit the key.
func sourceAuth(id string) string {
	if id == "" || len("auth:")+len(id) > maxSourceKey {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7e {
			return ""
		}
	}
	return "auth:" + strings.ToLower(id)
}

// sourceHost parses "<addr>.<port>". One IPv6 customer gets a /64, so an
// IPv6 host is keyed by its /64.
func sourceHost(value string) string {
	i := strings.LastIndexByte(value, '.')
	if i < 0 {
		return ""
	}
	if _, err := strconv.ParseUint(value[i+1:], 10, 16); err != nil {
		return ""
	}
	addr, err := netip.ParseAddr(value[:i])
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return "ip:" + addr.String()
	}
	return "ip:" + netip.PrefixFrom(addr, 64).Masked().String()
}
