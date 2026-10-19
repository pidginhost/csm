package learnwatch

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/safepath"
)

// Mailbox list bounds (spec 7.1): one ~/etc/<domain>/passwd file is read
// up to MaxMailboxListBytes and yields at most MaxMailboxes names; at most
// MaxMailboxes entries of ~/etc are considered.
const (
	MaxMailboxListBytes = 1 << 20
	MaxMailboxes        = 10000
)

// Mailbox discovery skip reasons. Skips carry no tenant-supplied names.
const (
	SkipUnsupportedName     = "unsupported_name"
	SkipMailboxListTooLarge = "mailbox_list_too_large"
	SkipMailboxLimit        = "mailbox_limit"
	SkipUnsafePath          = "unsafe_path"
)

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ValidDomain accepts ASCII DNS names of at most 253 bytes with at least two
// nonempty labels of at most 63 letters, digits or hyphens, no edge hyphens.
// Single-label names such as the virtual namespace are not domains.
func ValidDomain(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if !alnum(l[i]) && l[i] != '-' {
				return false
			}
		}
	}
	return true
}

// atextSpecials is RFC 5322 atext punctuation without the slash.
const atextSpecials = "!#$%&'*+-=?^_`{|}~"

// ValidMailbox accepts ASCII dot-atoms of at most 64 bytes with no leading,
// trailing or repeated dot. Quoted local parts, whitespace, controls,
// slashes, backslashes and non-ASCII bytes are refused.
func ValidMailbox(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !alnum(c) && c != '.' && strings.IndexByte(atextSpecials, c) < 0 {
			return false
		}
	}
	return true
}

// ParseMailboxPasswd returns the sorted distinct valid names of a cPanel
// mailbox passwd file, at most limit of them.
func ParseMailboxPasswd(data []byte, limit int) ([]string, []Skip) {
	seen := map[string]bool{}
	var names []string
	var skips []Skip
	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		raw, _, _ := bytes.Cut(line, []byte{':'})
		name := string(raw)
		switch {
		case !ValidMailbox(name):
			skips = append(skips, Skip{Reason: SkipUnsupportedName})
			continue
		case seen[name]:
			continue
		case len(names) >= limit:
			skips = append(skips, Skip{Reason: SkipMailboxLimit})
			sort.Strings(names)
			return names, skips
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names, skips
}

// unsafeErr: a component was a symlink or not a directory.
func unsafeErr(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENXIO)
}

// Mailboxes lists the main mailbox and every valid mailbox of every valid
// domain directory under ~/etc. It never lists ~/mail, so the virtual
// namespace is never followed. Unsafe or unsupported entries are skipped;
// a transient failure is an error.
func (h *Home) Mailboxes() ([]Mailbox, []Skip, error) {
	out := []Mailbox{{}}
	etc, err := h.dir.Walk("etc")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return out, nil, nil
	case unsafeErr(err):
		return out, []Skip{{Reason: SkipUnsafePath}}, nil
	case err != nil:
		return out, nil, err
	}
	defer func() { _ = etc.Close() }()
	domains, skips, err := domainDirs(etc)
	if err != nil {
		return out, skips, err
	}
	for _, d := range domains {
		boxes, s, err := readMailboxList(etc, d)
		skips = append(skips, s...)
		if err != nil {
			return out, skips, err
		}
		for _, b := range boxes {
			out = append(out, Mailbox{Domain: d, Box: b})
		}
	}
	return out, skips, nil
}

func domainDirs(etc *safepath.Dir) ([]string, []Skip, error) {
	var domains []string
	var skips []Skip
	for seen := 0; ; {
		entries, err := etc.ReadDirN(512)
		for _, e := range entries {
			if seen++; seen > MaxMailboxes {
				sort.Strings(domains)
				return domains, append(skips, Skip{Reason: SkipMailboxLimit}), nil
			}
			name, typ := e.Name(), e.Type()
			switch {
			case strings.HasPrefix(name, "."):
			case !ValidDomain(name):
				if typ.IsDir() {
					skips = append(skips, Skip{Reason: SkipUnsupportedName})
				}
			case typ&fs.ModeSymlink != 0:
				skips = append(skips, Skip{Reason: SkipUnsafePath})
			case typ.IsDir():
				domains = append(domains, name)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, skips, err
		}
	}
	sort.Strings(domains)
	return domains, skips, nil
}

// readMailboxList reads ~/etc/<domain>/passwd without following links.
func readMailboxList(etc *safepath.Dir, domain string) ([]string, []Skip, error) {
	dir, err := etc.Walk(domain)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil
	case unsafeErr(err):
		return nil, []Skip{{Reason: SkipUnsafePath}}, nil
	case err != nil:
		return nil, nil, err
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.OpenFile("passwd", os.O_RDONLY|syscall.O_NOCTTY, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil
	case unsafeErr(err):
		return nil, []Skip{{Reason: SkipUnsafePath}}, nil
	case err != nil:
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, []Skip{{Reason: SkipUnsafePath}}, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxMailboxListBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxMailboxListBytes {
		return nil, []Skip{{Reason: SkipMailboxListTooLarge}}, nil
	}
	names, skips := ParseMailboxPasswd(data, MaxMailboxes)
	return names, skips, nil
}
