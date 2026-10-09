package antispam

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// EximVersion is the release and content-scanning support from `exim -bV`.
type EximVersion struct {
	Major, Minor, Patch int
	ContentScanning     bool
}

var eximVersionRe = regexp.MustCompile(`^Exim version (\d{1,4})\.(\d{1,4})(?:\.(\d{1,4}))?\b`)

// ParseEximVersion reads `exim -bV` output.
func ParseEximVersion(out string) (EximVersion, error) {
	var v EximVersion
	found := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := eximVersionRe.FindStringSubmatch(line); m != nil && !found {
			v.Major, _ = strconv.Atoi(m[1])
			v.Minor, _ = strconv.Atoi(m[2])
			if m[3] != "" {
				v.Patch, _ = strconv.Atoi(m[3])
			}
			found = true
			continue
		}
		if rest, ok := strings.CutPrefix(line, "Support for:"); ok {
			for _, feature := range strings.Fields(rest) {
				if feature == "Content_Scanning" {
					v.ContentScanning = true
				}
			}
		}
	}
	if !found {
		return EximVersion{}, errors.New("exim -bV printed no version line")
	}
	return v, nil
}

// AtLeast compares numerically, so 4.100 is newer than 4.97.
func (v EximVersion) AtLeast(major, minor int) bool {
	return v.Major > major || v.Major == major && v.Minor >= minor
}

// NamedListProbes are the `exim -be` expressions proving every named list the
// hooks reference is defined. Each must print exactly "y" or "n".
func NamedListProbes() []string {
	return []string{
		"${if match_domain{example.invalid}{+local_domains}{y}{n}}",
		"${if match_ip{192.0.2.1}{+trustedmailhosts}{y}{n}}",
		"${if match_ip{2001:db8::1}{+cpanel_mail_netblocks}{y}{n}}",
	}
}

// ParseBeResult checks one `exim -be` probe. Exim exits 0 even when a list is
// undefined, so only the printed text separates success from failure.
func ParseBeResult(stdout, stderr string) error {
	if strings.TrimSpace(stderr) == "" && (stdout == "y\n" || stdout == "n\n") {
		return nil
	}
	msg := firstLine(stdout)
	if msg == "" {
		msg = firstLine(stderr)
	}
	return fmt.Errorf("named list check failed: %s", msg)
}

// ParseEximOptions reads `exim -bP name...` output. A "name = value" line maps
// to value, "no_name" to "false" and a bare "name" to "true".
func ParseEximOptions(out string) map[string]string {
	opts := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if name, value, ok := strings.Cut(line, "="); ok {
			opts[strings.TrimSpace(name)] = strings.TrimSpace(value)
			continue
		}
		if name, ok := strings.CutPrefix(line, "no_"); ok {
			opts[name] = "false"
			continue
		}
		opts[line] = "true"
	}
	return opts
}

// cpanelChunkingOff is the documentation address cPanel puts in
// chunking_advertise_hosts so that no real client is offered CHUNKING.
const cpanelChunkingOff = "198.51.100.1"

// ChunkingOff reports whether Exim offers CHUNKING to no real client.
func ChunkingOff(hosts string) bool {
	h := strings.TrimSpace(hosts)
	return h == "" || h == cpanelChunkingOff
}

var aclVerbs = map[string]bool{
	"accept": true, "defer": true, "deny": true, "discard": true,
	"drop": true, "require": true, "warn": true,
}

var (
	aclNameRe   = regexp.MustCompile(`^[A-Za-z0-9_]+:$`)
	spamCondRe  = regexp.MustCompile(`^!?\s*spam\s*=`)
	spamdAddrRe = regexp.MustCompile(`^spamd_address\s*=`)
)

// UngatedSpamUses returns the 1-based line numbers of ACL statements, outside
// CSM blocks, that run a spam scan or read $spam_* without cPanel's
// ${perl{spamd_is_available}} gate. cPanel's spam-score deny, ratelimit and
// forwarding options generate such statements; they would act on CSM's scan
// with their own threshold and ignore an account's opt-out.
func UngatedSpamUses(conf string) []int {
	var out []int
	inACL, inCSM := false, false
	stmt, uses, gated := 0, false, false
	flush := func() {
		if stmt != 0 && uses && !gated {
			out = append(out, stmt)
		}
		stmt, uses, gated = 0, false, false
	}
	for i, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "begin "):
			flush()
			inACL = line == "begin acl"
			continue
		case line == MarkerBegin:
			flush()
			inCSM = true
			continue
		case line == MarkerEnd:
			inCSM = false
			continue
		}
		if !inACL || inCSM || line == "" || line[0] == '#' || line[0] == '.' {
			continue
		}
		if aclNameRe.MatchString(line) {
			flush()
			continue
		}
		if word, rest, _ := strings.Cut(line, " "); aclVerbs[word] {
			flush()
			stmt = i + 1
			line = strings.TrimSpace(rest)
		}
		if stmt == 0 {
			continue
		}
		if spamCondRe.MatchString(line) || strings.Contains(line, "$spam_") || strings.Contains(line, "${spam_") {
			uses = true
		}
		if strings.Contains(line, "${perl{spamd_is_available}}") {
			gated = true
		}
	}
	flush()
	return out
}

// HasCutthrough reports whether a generated exim.conf enables cutthrough
// delivery anywhere outside a comment.
func HasCutthrough(conf string) bool {
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line != "" && line[0] != '#' && strings.Contains(line, "cutthrough_delivery") {
			return true
		}
	}
	return false
}

// ForeignSpamdAddress reports whether /etc/exim.conf.local sets spamd_address
// outside CSM's own block.
func ForeignSpamdAddress(local string) bool {
	inCSM := false
	for _, raw := range strings.Split(local, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == MarkerBegin:
			inCSM = true
		case line == MarkerEnd:
			inCSM = false
		case !inCSM && spamdAddrRe.MatchString(line):
			return true
		}
	}
	return false
}

// Placement is one CSM block found in an Exim config file.
type Placement struct {
	// ACL is the ACL holding the block, or "" outside the ACL section.
	ACL   string
	Begin int // 1-based line of the BEGIN marker
	End   int // 1-based line of the END marker
}

// LocateBlocks finds every CSM block and the ACL that holds it. Nested,
// unpaired or section-crossing markers are an error: CSM never edits a file
// whose blocks it cannot identify.
func LocateBlocks(conf string) ([]Placement, error) {
	var out []Placement
	inACL, acl, open := false, "", 0
	for i, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "begin "):
			if open != 0 {
				return nil, fmt.Errorf("line %d: section starts inside a CSM block", i+1)
			}
			inACL, acl = line == "begin acl", ""
		case inACL && open == 0 && aclNameRe.MatchString(line):
			acl = strings.TrimSuffix(line, ":")
		case line == MarkerBegin:
			if open != 0 {
				return nil, fmt.Errorf("line %d: nested %s", i+1, MarkerBegin)
			}
			open = i + 1
		case line == MarkerEnd:
			if open == 0 {
				return nil, fmt.Errorf("line %d: %s without %s", i+1, MarkerEnd, MarkerBegin)
			}
			name := ""
			if inACL {
				name = acl
			}
			out = append(out, Placement{ACL: name, Begin: open, End: i + 1})
			open = 0
		}
	}
	if open != 0 {
		return nil, fmt.Errorf("line %d: %s without %s", open, MarkerBegin, MarkerEnd)
	}
	return out, nil
}

// CheckPlacement verifies a generated exim.conf holds exactly one scanner
// block outside the ACL section, one hook in the RCPT ACL and two (scan, then
// decision) in the DATA ACL. rcptACL and dataACL come from
// `exim -bP acl_smtp_rcpt acl_smtp_data`.
func CheckPlacement(blocks []Placement, rcptACL, dataACL string) error {
	var main, rcpt, data int
	for _, b := range blocks {
		switch b.ACL {
		case "":
			main++
		case rcptACL:
			rcpt++
		case dataACL:
			data++
		default:
			return fmt.Errorf("CSM block at line %d is in unexpected ACL %q", b.Begin, b.ACL)
		}
	}
	if main != 1 || rcpt != 1 || data != 2 {
		return fmt.Errorf("found %d config, %d RCPT and %d DATA CSM blocks; want 1, 1 and 2", main, rcpt, data)
	}
	return nil
}

// firstLine returns the first line of s, trimmed and cut to 200 bytes so a
// command's output cannot flood a finding.
func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	return strings.TrimSpace(line)
}
