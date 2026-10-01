package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// pamFailureHookArg makes pam_csm.so report the authentication attempt as
// failed. The module cannot see the verdict of the modules before it, so the
// line has to sit where only a failed attempt arrives: directly before the
// terminal pam_deny.so of the shared auth stack.
const pamFailureHookArg = "authfail"

const pamFailureHookLine = "auth     optional   pam_csm.so " + pamFailureHookArg + " " + pamMarker

var (
	errPAMNoDenyLine        = errors.New("no required or requisite pam_deny.so auth line")
	errPAMSeveralDenyLines  = errors.New("more than one required or requisite pam_deny.so auth line")
	errPAMJumpAcrossInclude = errors.New("a jump crosses an included stack, so its target cannot be counted")
	errPAMLineContinuation  = errors.New("the file uses line continuations")
	errPAMMalformedLine     = errors.New("the file has a line this editor cannot parse")
	errPAMSymlinkedStack    = errors.New("the file is a symlink; authselect-managed stacks are rewritten by authselect and need a custom profile")
	errPAMNoSharedStack     = errors.New("no shared auth stack found")
)

// pamStackRefusals are the reasons the failure hook is not placed. The file
// is left untouched in every case.
var pamStackRefusals = []error{
	errPAMNoDenyLine,
	errPAMSeveralDenyLines,
	errPAMJumpAcrossInclude,
	errPAMLineContinuation,
	errPAMMalformedLine,
	errPAMSymlinkedStack,
}

func pamStackRefusal(err error) bool {
	for _, refusal := range pamStackRefusals {
		if errors.Is(err, refusal) {
			return true
		}
	}
	return false
}

var pamTypes = map[string]bool{"auth": true, "account": true, "password": true, "session": true}

// pamLine is one active directive of a PAM configuration file.
type pamLine struct {
	// kind is the PAM type without the "-" prefix. Empty for @include,
	// which pulls in every type.
	kind string
	// opaque marks include, substack and @include: they stand for a number
	// of modules that cannot be counted from this file.
	opaque  bool
	control string
	// ctlStart and ctlEnd bound the contents of a bracketed control in the
	// raw line; ctlStart is -1 for a simple control.
	ctlStart int
	ctlEnd   int
	module   string
	args     []string
}

func (l *pamLine) hasArg(arg string) bool {
	for _, a := range l.args {
		if a == arg {
			return true
		}
	}
	return false
}

// parsePAMLine parses one line. It returns nil for blank and comment lines.
// libpam drops everything after '#', so a trailing comment such as the
// managed-by marker is not part of the directive.
func parsePAMLine(raw string) (*pamLine, error) {
	text := raw
	if i := strings.IndexByte(text, '#'); i >= 0 {
		text = text[:i]
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil, nil
	}
	if fields[0] == "@include" {
		if len(fields) != 2 {
			return nil, errPAMMalformedLine
		}
		return &pamLine{opaque: true, ctlStart: -1}, nil
	}
	kind := strings.ToLower(strings.TrimPrefix(fields[0], "-"))
	if !pamTypes[kind] {
		return nil, errPAMMalformedLine
	}
	line := &pamLine{kind: kind, ctlStart: -1}
	typeEnd := strings.Index(text, fields[0]) + len(fields[0])
	rest := strings.TrimLeft(text[typeEnd:], " \t")
	restStart := len(text) - len(rest)
	var tail string
	if strings.HasPrefix(rest, "[") {
		closeAt := strings.IndexByte(rest, ']')
		if closeAt < 0 {
			return nil, errPAMMalformedLine
		}
		line.ctlStart = restStart + 1
		line.ctlEnd = restStart + closeAt
		line.control = text[line.ctlStart:line.ctlEnd]
		tail = rest[closeAt+1:]
	} else {
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return nil, errPAMMalformedLine
		}
		line.control = parts[0]
		tail = strings.TrimLeft(rest, " \t")[len(parts[0]):]
	}
	operands := strings.Fields(tail)
	if len(operands) == 0 {
		return nil, errPAMMalformedLine
	}
	line.module = operands[0]
	line.args = operands[1:]
	if control := strings.ToLower(line.control); line.ctlStart < 0 && (control == "include" || control == "substack") {
		line.opaque = true
	}
	return line, nil
}

// pamStack is a PAM file split into lines, with each line's directive.
type pamStack struct {
	raw    []string
	parsed []*pamLine
	// trailingNewline records whether the file ended with a newline, so an
	// edit writes the rest of the file back byte for byte.
	trailingNewline bool
}

func parsePAMStack(data []byte) (*pamStack, error) {
	text := string(data)
	stack := &pamStack{trailingNewline: strings.HasSuffix(text, "\n")}
	text = strings.TrimSuffix(text, "\n")
	for _, raw := range strings.Split(text, "\n") {
		if strings.HasSuffix(strings.TrimRight(raw, " \t"), `\`) {
			return nil, errPAMLineContinuation
		}
		line, err := parsePAMLine(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", err, raw)
		}
		stack.raw = append(stack.raw, raw)
		stack.parsed = append(stack.parsed, line)
	}
	return stack, nil
}

func (s *pamStack) bytes() []byte {
	out := strings.Join(s.raw, "\n")
	if s.trailingNewline {
		out += "\n"
	}
	return []byte(out)
}

// jumpOutcome reports where a jump of n modules from line from lands relative
// to line pivot: whether pivot is among the skipped modules, and whether the
// jump then runs past the last module of the stack.
func (s *pamStack) jumpOutcome(kind string, from, n, pivot int) (skipsPivot, pastEnd bool, err error) {
	for x := from + 1; x < len(s.parsed); x++ {
		line := s.parsed[x]
		// @include has no type of its own and pulls in every type.
		if line == nil || (line.kind != kind && line.kind != "") {
			continue
		}
		if n == 0 {
			return skipsPivot, false, nil
		}
		if line.opaque {
			return false, false, errPAMJumpAcrossInclude
		}
		if x == pivot {
			skipsPivot = true
		}
		n--
	}
	return skipsPivot, true, nil
}

var pamJumpAction = regexp.MustCompile(`([A-Za-z_]+)=([0-9]+)`)

// shiftJumps adds delta to every jump of line i that skips line pivot. On
// removal (delta -1) a jump that runs past the end of the stack is left
// alone: it lands past the end with or without the removed line.
func (s *pamStack) shiftJumps(i, pivot, delta int) error {
	line := s.parsed[i]
	if line == nil || line.ctlStart < 0 {
		return nil
	}
	var shiftErr error
	control := pamJumpAction.ReplaceAllStringFunc(line.control, func(action string) string {
		parts := pamJumpAction.FindStringSubmatch(action)
		n, err := strconv.Atoi(parts[2])
		if err != nil {
			shiftErr = errPAMMalformedLine
			return action
		}
		skips, pastEnd, err := s.jumpOutcome(line.kind, i, n, pivot)
		if err != nil {
			shiftErr = err
			return action
		}
		if !skips || (delta < 0 && pastEnd) {
			return action
		}
		return parts[1] + "=" + strconv.Itoa(n+delta)
	})
	if shiftErr != nil {
		return shiftErr
	}
	raw := s.raw[i][:line.ctlStart] + control + s.raw[i][line.ctlEnd:]
	parsed, err := parsePAMLine(raw)
	if err != nil {
		return err
	}
	s.raw[i], s.parsed[i] = raw, parsed
	return nil
}

// pamInsertFailureHook places the failure hook directly before the shared
// stack's terminal pam_deny.so. Every path that reaches pam_deny.so fails the
// login, and every success path either returns before it or jumps over it;
// widening the jumps over it by one keeps successes off the hook.
func pamInsertFailureHook(data []byte) ([]byte, error) {
	stack, err := parsePAMStack(data)
	if err != nil {
		return nil, err
	}
	deny := -1
	for i, line := range stack.parsed {
		if line == nil || line.kind != "auth" || line.opaque || filepath.Base(line.module) != "pam_deny.so" {
			continue
		}
		if control := strings.ToLower(line.control); control != "required" && control != "requisite" {
			continue
		}
		if deny >= 0 {
			return nil, errPAMSeveralDenyLines
		}
		deny = i
	}
	if deny < 0 {
		return nil, errPAMNoDenyLine
	}
	for i := 0; i < deny; i++ {
		if err = stack.shiftJumps(i, deny, 1); err != nil {
			return nil, err
		}
	}
	hook, err := parsePAMLine(pamFailureHookLine)
	if err != nil {
		return nil, err
	}
	stack.raw = append(stack.raw[:deny], append([]string{pamFailureHookLine}, stack.raw[deny:]...)...)
	stack.parsed = append(stack.parsed[:deny], append([]*pamLine{hook}, stack.parsed[deny:]...)...)
	return stack.bytes(), nil
}

// pamRemoveManagedLines drops every line install wrote and narrows the jumps
// that skipped them, so uninstall restores the stack's original control flow.
func pamRemoveManagedLines(data []byte) ([]byte, int, error) {
	stack, err := parsePAMStack(data)
	if err != nil {
		return nil, 0, err
	}
	removed := 0
	for {
		managed := -1
		for i, raw := range stack.raw {
			if pamManagedLine(raw) {
				managed = i
				break
			}
		}
		if managed < 0 {
			return stack.bytes(), removed, nil
		}
		for i := 0; i < managed; i++ {
			if err := stack.shiftJumps(i, managed, -1); err != nil {
				return nil, 0, err
			}
		}
		stack.raw = append(stack.raw[:managed], stack.raw[managed+1:]...)
		stack.parsed = append(stack.parsed[:managed], stack.parsed[managed+1:]...)
		removed++
	}
}

// pamHasFailureHook reports an active auth line that already runs pam_csm.so
// in failure mode, whoever wrote it. A second one would report every failed
// login twice.
func pamHasFailureHook(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line, err := parsePAMLine(raw)
		if err == nil && line != nil && line.kind == "auth" &&
			filepath.Base(line.module) == "pam_csm.so" && line.hasArg(pamFailureHookArg) {
			return true
		}
	}
	return false
}

// pamEnsureFailureHook adds the failure hook to a shared auth stack. A refusal
// leaves the file untouched.
func pamEnsureFailureHook(path string, dryRun bool) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errPAMSymlinkedStack
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is one of pamSharedAuthStacks.
	if err != nil {
		return false, err
	}
	if pamHasFailureHook(data) {
		return false, nil
	}
	out, err := pamInsertFailureHook(data)
	if err != nil {
		return false, err
	}
	if dryRun {
		return true, nil
	}
	backup, err := writePAMBackup(path, data)
	if err != nil {
		return false, err
	}
	// #nosec G306 -- /etc/pam.d files are standard 0644; see pamEnsureLines.
	if err := writeFileAtomic(path, out, 0o644); err != nil {
		return false, fmt.Errorf("writing %s after backup %s: %w", path, backup, err)
	}
	return true, nil
}

// pamFailureHookState describes whether failed logins through a shared auth
// stack reach the daemon.
func pamFailureHookState(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "absent"
		}
		return fmt.Sprintf("error reading: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "not reported (" + errPAMSymlinkedStack.Error() + ")"
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is one of pamSharedAuthStacks.
	if err != nil {
		return fmt.Sprintf("error reading: %v", err)
	}
	if pamHasFailureHook(data) {
		return "reported"
	}
	return "not reported (run csm pam install)"
}
