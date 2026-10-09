package antispam

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
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

// ErrUndefinedList is the probe result for a named list that does not exist.
// Exim 4.100.1 exits 0 for it, prints "Failed: ..." and logs "unknown named
// <kind> list" on stderr.
var ErrUndefinedList = errors.New("named list is undefined")

// errBeUnexpected covers any other output, such as a warning on stderr.
var errBeUnexpected = errors.New("exim -be printed an unexpected result")

var undefinedListRe = regexp.MustCompile(`unknown named (?:domain|host|address|local part) list "\+`)

// ParseBeResult checks one `exim -be` probe. Exim exits 0 even when a list is
// undefined, so only the printed text separates success from failure. Errors
// never repeat the output: a list's lookup text can hold credentials.
func ParseBeResult(stdout, stderr string) error {
	switch {
	case strings.TrimSpace(stderr) == "" && (stdout == "y\n" || stdout == "n\n"):
		return nil
	case strings.HasPrefix(stdout, "Failed: ") && undefinedListRe.MatchString(stderr):
		return ErrUndefinedList
	default:
		return errBeUnexpected
	}
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
	aclNameRe    = regexp.MustCompile(`^[A-Za-z0-9_]+\s*:$`)
	spamCondRe   = regexp.MustCompile(`^!?\s*spam\s*=`)
	spamdAddrRe  = regexp.MustCompile(`^(?:hide\s+)?spamd_address\s*=`)
	sectionRe    = regexp.MustCompile(`(?i)^begin\s+([a-z_]+)$`)
	cutthroughRe = regexp.MustCompile(`\bcutthrough_delivery\b`)
	macroNameRe  = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]*$`)
)

// ErrUnverifiable marks an Exim configuration CSM cannot check: an included
// file it does not follow, or macros that expand past its parsing bounds.
var ErrUnverifiable = errors.New("exim configuration cannot be verified")

const (
	// maxMacroVariants bounds the lines one configuration line expands to.
	// Each conditional redefinition adds a variant, so they multiply.
	maxMacroVariants = 64
	// maxExpandedLine bounds one expanded line, so a macro redefined in terms
	// of itself cannot double without limit.
	maxExpandedLine = 64 << 10
)

type eximLine struct {
	number    int
	text      string
	continued bool
}

// Exim joins continuations without adding spaces and ignores intervening
// comments. Keep comments and physical line numbers for the ownership markers.
// An .include makes the file unverifiable: CSM does not follow it.
func eximLines(conf string) ([]eximLine, error) {
	var out []eximLine
	var text strings.Builder
	current := -1
	for i, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			out = append(out, eximLine{number: i + 1, text: line, continued: current != -1})
			continue
		}
		if current == -1 {
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, ".include") {
				return nil, fmt.Errorf("line %d: %w: .include is not followed", i+1, ErrUnverifiable)
			}
			current = len(out)
			out = append(out, eximLine{number: i + 1})
		}
		part, continued := strings.CutSuffix(line, `\`)
		text.WriteString(part)
		if !continued {
			out[current].text = strings.TrimSpace(text.String())
			text.Reset()
			current = -1
		}
	}
	if current != -1 {
		out[current].text = strings.TrimSpace(text.String())
	}
	return out, nil
}

func eximSection(line string) (string, bool) {
	m := sectionRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	section := strings.ToLower(m[1])
	if section == "acls" {
		section = "acl"
	}
	return section, true
}

func splitACLVerb(line string) (string, string) {
	word, rest := line, ""
	if i := strings.IndexAny(line, " \t\r\n\f\v"); i >= 0 {
		word, rest = line[:i], strings.TrimSpace(line[i:])
	}
	if aclVerbs[word] {
		return word, rest
	}
	return "", line
}

// UngatedSpamUses returns the 1-based line numbers, outside CSM blocks, of ACL
// statements that run a spam scan or read $spam_* without cPanel's
// ${perl{spamd_is_available}} gate, and of any other line that reads $spam_*.
// cPanel's spam-score deny, ratelimit and forwarding options generate such
// statements and routers; they would act on CSM's scan with their own
// threshold and ignore an account's opt-out.
func UngatedSpamUses(conf string) ([]int, error) {
	var out []int
	var macros []eximMacro
	inACL, inCSM := false, false
	stmt, unsafe, verb := 0, false, ""
	depth, gateDepth := 0, -1
	flush := func() {
		if stmt != 0 && unsafe {
			out = append(out, stmt)
		}
		stmt, unsafe, verb, gateDepth = 0, false, "", -1
	}
	parsed, err := eximLines(conf)
	if err != nil {
		return nil, err
	}
	for _, raw := range parsed {
		line := raw.text
		if ok, err := recordEximMacro(line, depth, &macros); err != nil {
			return nil, fmt.Errorf("line %d: %w", raw.number, err)
		} else if ok {
			flush()
			continue
		}
		switch line {
		case MarkerBegin:
			flush()
			inCSM = true
			continue
		case MarkerEnd:
			inCSM = false
			continue
		}
		if inCSM || line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '.' {
			// A gate in an optional branch cannot protect uses after that
			// branch, but an enclosing gate still protects nested branches.
			switch strings.Fields(line)[0] {
			case ".if", ".ifdef", ".ifndef":
				depth++
			case ".else", ".elifdef", ".elifndef", ".endif":
				if gateDepth >= depth {
					gateDepth = -1
				}
				if strings.HasPrefix(line, ".endif") {
					depth--
				}
			}
			continue
		}
		lines, err := expandEximMacros(line, macros)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", raw.number, err)
		}
		sectionFound, aclSection := false, false
		for _, expanded := range lines {
			if section, ok := eximSection(expanded); ok {
				sectionFound = true
				aclSection = aclSection || section == "acl"
			}
		}
		if sectionFound {
			flush()
			inACL = aclSection
			continue
		}
		if !inACL {
			// Nothing gates a router, transport or main option, so any spam
			// read there acts on CSM's score for every account.
			for _, expanded := range lines {
				if readsSpamVariable(expanded) {
					out = append(out, raw.number)
					break
				}
			}
			continue
		}
		newVerb, uses, gate := "", false, true
		boundary := false
		for _, expanded := range lines {
			if aclNameRe.MatchString(expanded) {
				boundary = true
			}
			word, rest := splitACLVerb(expanded)
			if word != "" && (newVerb == "" || word == "require") {
				newVerb = word
			}
			uses = uses || spamCondRe.MatchString(rest) || readsSpamVariable(rest)
			name, value, ok := strings.Cut(rest, "=")
			gate = gate && ok && strings.TrimSpace(name) == "condition" && strings.TrimSpace(value) == "${perl{spamd_is_available}}"
		}
		if boundary {
			flush()
			continue
		}
		if newVerb != "" {
			flush()
			stmt, verb = raw.number, newVerb
		}
		if stmt == 0 {
			continue
		}
		if uses && (gateDepth == -1 || verb == "require") {
			unsafe = true
		}
		if gate && gateDepth == -1 {
			gateDepth = depth
		}
	}
	flush()
	sort.Ints(out)
	return out, nil
}

// FilterSpamUses returns the 1-based lines of an Exim system filter that read
// $spam_*. The filter runs at delivery, after CSM's scan, for every account.
// A header test such as $h_x-spam-score: is not a read of CSM's score.
func FilterSpamUses(filter string) []int {
	var out []int
	for i, raw := range strings.Split(filter, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		if readsSpamVariable(line) {
			out = append(out, i+1)
		}
	}
	return out
}

func readsSpamVariable(s string) bool {
	return strings.Contains(s, "$spam_") || strings.Contains(s, "${spam_")
}

// HasCutthrough reports whether a generated exim.conf enables cutthrough
// delivery anywhere outside a comment.
func HasCutthrough(conf string) (bool, error) {
	var macros []eximMacro
	depth := 0
	parsed, err := eximLines(conf)
	if err != nil {
		return false, err
	}
	for _, raw := range parsed {
		line := raw.text
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '.' {
			switch strings.Fields(line)[0] {
			case ".if", ".ifdef", ".ifndef":
				depth++
			case ".endif":
				depth--
			}
			continue
		}
		if ok, err := recordEximMacro(line, depth, &macros); err != nil {
			return false, fmt.Errorf("line %d: %w", raw.number, err)
		} else if ok {
			continue
		}
		lines, err := expandEximMacros(line, macros)
		if err != nil {
			return false, fmt.Errorf("line %d: %w", raw.number, err)
		}
		for _, expanded := range lines {
			_, condition := splitACLVerb(expanded)
			if name, value, ok := strings.Cut(condition, "="); ok && strings.TrimSpace(name) == "control" && cutthroughRe.MatchString(value) {
				return true, nil
			}
		}
	}
	return false, nil
}

type eximMacro struct {
	name   string
	values []string
}

func recordEximMacro(line string, depth int, macros *[]eximMacro) (bool, error) {
	name, value, ok := strings.Cut(line, "=")
	name = strings.TrimSpace(name)
	if !ok || !macroNameRe.MatchString(name) {
		return false, nil
	}
	value = strings.TrimSpace(strings.TrimPrefix(value, "="))
	values, err := expandEximMacros(value, *macros)
	if err != nil {
		return false, err
	}
	for i := range *macros {
		if (*macros)[i].name == name {
			if depth == 0 {
				(*macros)[i].values = values
			} else {
				// Host-dependent conditionals can select any definition.
				(*macros)[i].values = append((*macros)[i].values, values...)
			}
			if len((*macros)[i].values) > maxMacroVariants {
				return false, fmt.Errorf("%w: a macro has more than %d definitions", ErrUnverifiable, maxMacroVariants)
			}
			return true, nil
		}
	}
	*macros = append(*macros, eximMacro{name: name, values: values})
	return true, nil
}

func eximConditionalDepth(line string, depth int) int {
	if strings.HasPrefix(line, ".") {
		switch strings.Fields(line)[0] {
		case ".if", ".ifdef", ".ifndef":
			return depth + 1
		case ".endif":
			return depth - 1
		}
	}
	return depth
}

func expandEximMacros(line string, macros []eximMacro) ([]string, error) {
	lines := []string{line}
	for _, macro := range macros {
		var expanded []string
		for _, line := range lines {
			n := strings.Count(line, macro.name)
			if n == 0 {
				expanded = append(expanded, line)
				continue
			}
			for _, value := range macro.values {
				if len(line)+n*(len(value)-len(macro.name)) > maxExpandedLine {
					return nil, fmt.Errorf("%w: a macro expands one line past %d bytes", ErrUnverifiable, maxExpandedLine)
				}
				expanded = append(expanded, strings.ReplaceAll(line, macro.name, value))
			}
			if len(expanded) > maxMacroVariants {
				return nil, fmt.Errorf("%w: macros expand one line into more than %d variants", ErrUnverifiable, maxMacroVariants)
			}
		}
		lines = expanded
	}
	return lines, nil
}

// ForeignSpamdAddress reports whether /etc/exim.conf.local sets spamd_address
// outside CSM's own block.
func ForeignSpamdAddress(local string) (bool, error) {
	inCSM := false
	var macros []eximMacro
	depth := 0
	parsed, err := eximLines(local)
	if err != nil {
		return false, err
	}
	for _, raw := range parsed {
		line := raw.text
		depth = eximConditionalDepth(line, depth)
		if ok, err := recordEximMacro(line, depth, &macros); err != nil {
			return false, fmt.Errorf("line %d: %w", raw.number, err)
		} else if ok {
			continue
		}
		switch line {
		case MarkerBegin:
			inCSM = true
		case MarkerEnd:
			inCSM = false
		default:
			if inCSM {
				continue
			}
			lines, err := expandEximMacros(line, macros)
			if err != nil {
				return false, fmt.Errorf("line %d: %w", raw.number, err)
			}
			for _, expanded := range lines {
				if spamdAddrRe.MatchString(expanded) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Placement is one CSM block found in an Exim config file.
type Placement struct {
	// ACL is the ACL holding the block, or "" in the main configuration.
	ACL   string
	Begin int // 1-based line of the BEGIN marker
	End   int // 1-based line of the END marker
}

// LocateBlocks finds every CSM block and the ACL that holds it. Nested,
// unpaired or boundary-crossing markers are an error: CSM never edits a file
// whose blocks it cannot identify.
func LocateBlocks(conf string) ([]Placement, error) {
	var out []Placement
	var macros []eximMacro
	depth := 0
	section, acl, open := "", "", 0
	// afterEnd is set when a block closed inside an ACL: the next line must
	// start something new, or Exim would join it to CSM's last statement.
	afterEnd := false
	parsed, err := eximLines(conf)
	if err != nil {
		return nil, err
	}
	for _, raw := range parsed {
		line, number := raw.text, raw.number
		if raw.continued && (line == MarkerBegin || line == MarkerEnd) {
			return nil, fmt.Errorf("line %d: CSM marker splits a continued configuration line", number)
		}
		depth = eximConditionalDepth(line, depth)
		if afterEnd && line != "" && line[0] != '#' && line[0] != '.' {
			if err := startsStatement(line, macros); err != nil {
				return nil, fmt.Errorf("line %d: %w", number, err)
			}
			afterEnd = false
		}
		if ok, err := recordEximMacro(line, depth, &macros); err != nil {
			return nil, fmt.Errorf("line %d: %w", number, err)
		} else if ok {
			if section == "acl" {
				if open != 0 {
					return nil, fmt.Errorf("line %d: macro ends an ACL inside a CSM block", number)
				}
				acl = ""
			}
			continue
		}
		boundary := ""
		lines, err := expandEximMacros(line, macros)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", number, err)
		}
		boundaries := 0
		for _, expanded := range lines {
			if name, ok := eximSection(expanded); ok {
				boundaries++
				if open != 0 {
					return nil, fmt.Errorf("line %d: section starts inside a CSM block", number)
				}
				if boundary != "" && boundary != "section:"+name {
					return nil, fmt.Errorf("line %d: ambiguous section", number)
				}
				boundary = "section:" + name
				section, acl = name, ""
			} else if section == "acl" && aclNameRe.MatchString(expanded) {
				boundaries++
				if open != 0 {
					return nil, fmt.Errorf("line %d: ACL starts inside a CSM block", number)
				}
				name := strings.TrimSpace(strings.TrimSuffix(expanded, ":"))
				if boundary != "" && boundary != "acl:"+name {
					return nil, fmt.Errorf("line %d: ambiguous ACL", number)
				}
				boundary, acl = "acl:"+name, name
			}
		}
		if boundaries != 0 && boundaries != len(lines) {
			return nil, fmt.Errorf("line %d: optional section or ACL boundary", number)
		}
		switch line {
		case MarkerBegin:
			if open != 0 {
				return nil, fmt.Errorf("line %d: nested %s", number, MarkerBegin)
			}
			if section != "" && (section != "acl" || acl == "") {
				return nil, fmt.Errorf("line %d: CSM block is outside the main configuration or a named ACL", number)
			}
			open = number
		case MarkerEnd:
			if open == 0 {
				return nil, fmt.Errorf("line %d: %s without %s", number, MarkerEnd, MarkerBegin)
			}
			out = append(out, Placement{ACL: acl, Begin: open, End: number})
			open = 0
			afterEnd = acl != ""
		}
	}
	if open != 0 {
		return nil, fmt.Errorf("line %d: %s without %s", open, MarkerBegin, MarkerEnd)
	}
	return out, nil
}

// errContinuesBlock is a line after a CSM block in an ACL that would extend
// the block's last statement.
var errContinuesBlock = errors.New("a line after the CSM block continues its last statement")

// startsStatement accepts a line after a CSM block that begins something new:
// an ACL verb, an ACL name, a section, a macro or another CSM block.
func startsStatement(line string, macros []eximMacro) error {
	if line == MarkerBegin {
		return nil
	}
	if name, _, ok := strings.Cut(line, "="); ok && macroNameRe.MatchString(strings.TrimSpace(name)) {
		return nil
	}
	lines, err := expandEximMacros(line, macros)
	if err != nil {
		return err
	}
	for _, expanded := range lines {
		word, _ := splitACLVerb(expanded)
		_, section := eximSection(expanded)
		if word == "" && !section && !aclNameRe.MatchString(expanded) {
			return errContinuesBlock
		}
	}
	return nil
}

// CheckPlacement verifies a generated exim.conf holds exactly one scanner
// block in the main configuration, one hook in the RCPT ACL and two hooks in
// the DATA ACL. rcptACL and dataACL come from
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
