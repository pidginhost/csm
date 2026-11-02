// Package dovecot lists the users of a Dovecot 2.3 host and the Maildir++
// folders of their \Junk mailboxes. It learns everything from Dovecot's own
// commands and imports none of the learning packages that consume it.
package dovecot

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// MaxMailboxes bounds the users one listing may name.
	MaxMailboxes = 10000
	// MaxListBytes bounds the output of every command.
	MaxListBytes = 4 << 20
	// commandTimeout bounds each command.
	commandTimeout = 10 * time.Second
	// batchSize users are looked up per doveadm call.
	batchSize = 100
)

// Skip reasons. A reason is a fixed string and never carries command output.
const (
	SkipInvalidName     = "invalid_name"
	SkipLookupFailed    = "lookup_failed"
	SkipUIDRoot         = "uid_root"
	SkipPluginZlib      = "plugin_zlib"
	SkipPluginMailCrypt = "plugin_mail_crypt"
	SkipDriver          = "driver"
	SkipLayoutFS        = "layout_fs"
	SkipLocation        = "location"
	SkipInvalidHome     = "invalid_home"
	SkipNoJunk          = "no_junk"
)

var (
	// ErrCannotIterate reports a userdb that cannot list its users.
	ErrCannotIterate = errors.New("the Dovecot userdb cannot list users")
	// ErrDovecot24 reports Dovecot 2.4, whose mail settings differ.
	ErrDovecot24 = errors.New("dovecot 2.4 mail settings are not supported yet")
)

// DovecotMailbox is one user whose \Junk folders can be watched. User is the
// userdb name in lower case and Domain its domain, empty for a domainless
// system user. Home is empty when the userdb has none. Junk holds the
// absolute Maildir++ folder of every \Junk mailbox, sorted.
type DovecotMailbox struct {
	User, Domain string
	UID, GID     int
	Home         string
	Junk         []string
}

// Skip is a listed user that is not watched. User is empty when the name
// itself was refused.
type Skip struct {
	User, Reason string
}

// Snapshot is one discovery pass. Complete is set only when the listing,
// every lookup command and a second listing that matches the first all
// succeeded. A user doveadm could not look up is skipped: skipped users are
// present, not removed.
type Snapshot struct {
	Mailboxes []DovecotMailbox
	Skips     []Skip
	Complete  bool
}

// Dovecot discovers mailboxes by running dovecot, doveconf and doveadm
// through Run; a nil Run executes them.
type Dovecot struct {
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Snapshot lists every user and resolves its \Junk folders. Any failure that
// leaves the listing in doubt returns an error and an empty Snapshot. A user
// the listing names but doveadm cannot look up is skipped, not dropped.
func (d Dovecot) Snapshot(ctx context.Context) (Snapshot, error) {
	if err := d.version(ctx); err != nil {
		return Snapshot{}, err
	}
	out, err := d.cmd(ctx, "doveconf", "-n")
	if err != nil {
		return Snapshot{}, err
	}
	conf, err := parseConfig(out)
	if err != nil {
		return Snapshot{}, err
	}
	listed, err := d.users(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	var lookup []string
	seen := map[string]bool{}
	for _, name := range listed {
		user, _, ok := canonical(name)
		switch {
		case !ok:
			snap.Skips = append(snap.Skips, Skip{Reason: SkipInvalidName})
		case !seen[user]:
			seen[user] = true
			lookup = append(lookup, name)
		}
	}
	for batch := range slices.Chunk(lookup, batchSize) {
		found, derr := d.details(ctx, conf, batch)
		if derr != nil {
			return Snapshot{}, derr
		}
		for _, name := range batch {
			user, domain, _ := canonical(name)
			det, ok := found[name]
			if !ok {
				snap.Skips = append(snap.Skips, Skip{User: user, Reason: SkipLookupFailed})
				continue
			}
			m, reason := conf.mailbox(user, domain, det)
			if reason != "" {
				snap.Skips = append(snap.Skips, Skip{User: user, Reason: reason})
				continue
			}
			snap.Mailboxes = append(snap.Mailboxes, m)
		}
	}
	final, err := d.users(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if !slices.Equal(listed, final) {
		return Snapshot{}, errors.New("the Dovecot user list changed during discovery")
	}
	slices.SortFunc(snap.Mailboxes, func(a, b DovecotMailbox) int { return strings.Compare(a.User, b.User) })
	slices.SortFunc(snap.Skips, func(a, b Skip) int { return strings.Compare(a.User, b.User) })
	snap.Complete = true
	return snap, nil
}

// cmd runs one command within commandTimeout and MaxListBytes. On a non-zero
// exit it returns the output with the error.
func (d Dovecot) cmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	run := d.Run
	if run == nil {
		run = runCommand
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := run(ctx, name, args...)
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("%s: %w", name, ctx.Err())
	case len(out) > MaxListBytes:
		return nil, fmt.Errorf("%s: %w", name, errTooLarge)
	case err != nil:
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// version accepts Dovecot 2.3 only: 2.4 renamed the mail settings read here.
func (d Dovecot) version(ctx context.Context) error {
	out, err := d.cmd(ctx, "dovecot", "--version")
	if err != nil {
		return err
	}
	v, _, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	major, rest, _ := strings.Cut(v, ".")
	minor, _, _ := strings.Cut(rest, ".")
	maj, err1 := strconv.Atoi(major)
	low, err2 := strconv.Atoi(minor)
	switch {
	case err1 != nil || err2 != nil:
		return errors.New("unrecognised Dovecot version")
	case maj == 2 && low == 3:
		return nil
	case maj > 2 || maj == 2 && low > 3:
		return ErrDovecot24
	}
	return errors.New("dovecot before 2.3 is not supported")
}

// users returns the sorted distinct names the userdb lists.
func (d Dovecot) users(ctx context.Context) ([]string, error) {
	out, err := d.cmd(ctx, "doveadm", "user", "*")
	var exit *exec.ExitError
	if errors.As(err, &exit) && bytes.Contains(exit.Stderr, []byte("User listing returned failure")) {
		return nil, ErrCannotIterate
	}
	if err != nil {
		return nil, err
	}
	return parseUsers(out)
}

// doveadm user goes on past a user it cannot look up, prints no record for
// it and exits EX_NOUSER (unknown user) or EX_TEMPFAIL (lookup failed).
const (
	exNoUser   = 67
	exTempFail = 75
)

// details looks a batch of users up. Names come after "--" so none is read
// as an option, and none contains a mask character. Any exit but the two
// per-user ones, a signal included, fails the batch.
func (d Dovecot) details(ctx context.Context, conf config, batch []string) (map[string]detail, error) {
	args := append([]string{"user", "-e", conf.template(), "--"}, batch...)
	out, err := d.cmd(ctx, "doveadm", args...)
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != exNoUser && exit.ExitCode() != exTempFail) {
		return nil, err
	}
	found, perr := parseDetails(out, batch, len(conf.locs))
	switch {
	case perr != nil:
		return nil, perr
	case err == nil && len(found) != len(batch):
		return nil, errors.New("doveadm user printed no record for a user it found")
	}
	return found, nil
}

// canonical validates a listed name and returns it in lower case with its
// domain. doveadm reads names holding * or ? as masks.
func canonical(name string) (user, domain string, ok bool) {
	if strings.ContainsAny(name, "*?") {
		return "", "", false
	}
	local, domain, found := strings.Cut(name, "@")
	if !ValidMailbox(local) || found && !ValidDomain(domain) {
		return "", "", false
	}
	return strings.ToLower(name), strings.ToLower(domain), true
}

var errTooLarge = errors.New("output exceeds the bound")

// detail is one user's record: its effective uid, gid and home, the userdb
// mail and mail_plugins fields, and the configured locations expanded for
// that user.
type detail struct {
	uid, gid            int
	home, mail, plugins string
	locs                []string
}

// junkBox is a \Junk mailbox of a private namespace; loc 0 is the user's
// mail location, n the namespace location config.locs[n-1].
type junkBox struct {
	name, sep string
	loc       int
}

// config is what Snapshot reads from doveconf -n: the global mail_location,
// mail_plugins of every protocol, and the \Junk mailboxes with the locations
// of namespaces that set their own.
type config struct {
	location string
	plugins  []string
	locs     []string
	junk     []junkBox
}

// template has doveadm print, per user, the fixed fields and every location
// expanded with that user's variables, tab-separated, then the user again.
// The trailer makes a record end with its own user: a newline inside a
// field leaves a first or last fragment that is not a whole record.
func (c config) template() string {
	f := append([]string{"%u", "%{uid}", "%{gid}", "%h", "%{userdb:mail}", "%{userdb:mail_plugins}", c.location}, c.locs...)
	return strings.Join(append(f, "%u"), "\t")
}

func (c config) mailbox(user, domain string, d detail) (DovecotMailbox, string) {
	plugins := append(strings.Fields(d.plugins), c.plugins...)
	switch {
	case d.uid == 0:
		return DovecotMailbox{}, SkipUIDRoot
	case slices.Contains(plugins, "zlib"):
		return DovecotMailbox{}, SkipPluginZlib
	case slices.Contains(plugins, "mail_crypt") || slices.Contains(plugins, "mail_crypt_acl"):
		return DovecotMailbox{}, SkipPluginMailCrypt
	case d.home != "" && !absClean(d.home):
		return DovecotMailbox{}, SkipInvalidHome
	case len(c.junk) == 0:
		return DovecotMailbox{}, SkipNoJunk
	}
	var junk []string
	for _, j := range c.junk {
		loc := cmp.Or(d.mail, d.locs[0])
		if j.loc > 0 {
			loc = d.locs[j.loc]
		}
		root, utf8Names, reason := parseLocation(loc, d.home)
		if reason != "" {
			return DovecotMailbox{}, reason
		}
		dir, ok := folderDir(j.name, j.sep, utf8Names)
		if !ok {
			return DovecotMailbox{}, SkipInvalidName
		}
		junk = append(junk, filepath.Join(root, dir))
	}
	slices.Sort(junk)
	home := d.home
	if home != "" {
		home = filepath.Clean(home)
	}
	return DovecotMailbox{User: user, Domain: domain, UID: d.uid, GID: d.gid, Home: home, Junk: slices.Compact(junk)}, ""
}

// parseUsers reads one name per line, at most MaxMailboxes lines.
func parseUsers(out []byte) ([]string, error) {
	var names []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if line != "" {
			names = append(names, line)
		}
	}
	switch {
	case len(names) == 0:
		return nil, errors.New("doveadm listed no users")
	case len(names) > MaxMailboxes:
		return nil, fmt.Errorf("doveadm listed more than %d users", MaxMailboxes)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// parseDetails maps each requested name to its record. Every non-empty line
// must be one whole record of a requested user, matched case-insensitively,
// without control bytes; anything else fails the batch.
func parseDetails(out []byte, batch []string, nloc int) (map[string]detail, error) {
	errFraming := errors.New("doveadm user printed a malformed record")
	want := make(map[string]string, len(batch))
	for _, name := range batch {
		want[strings.ToLower(name)] = name
	}
	found := map[string]detail{}
	for line := range strings.SplitSeq(string(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 8+nloc || f[len(f)-1] != f[0] || strings.ContainsFunc(line, func(r rune) bool { return r != '\t' && control(r) }) {
			return nil, errFraming
		}
		name, ok := want[strings.ToLower(f[0])]
		uid, err1 := strconv.ParseUint(f[1], 10, 32)
		gid, err2 := strconv.ParseUint(f[2], 10, 32)
		if _, dup := found[name]; !ok || dup || err1 != nil || err2 != nil {
			return nil, errFraming
		}
		found[name] = detail{uid: int(uid), gid: int(gid), home: f[3], mail: f[4], plugins: f[5], locs: f[6 : len(f)-1]}
	}
	return found, nil
}

// parseConfig reads doveconf -n output: settings as "key = value", sections
// as "kind [name] {" ... "}". Values and names may be double-quoted.
func parseConfig(out []byte) (config, error) {
	errSyntax := errors.New("doveconf -n printed a malformed configuration")
	var c config
	var stack []string
	var nsType, nsSep, nsLoc string
	var boxes []string
	var box string
	var junk bool
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		inNS := len(stack) > 0 && stack[0] == "namespace"
		switch {
		case line == "" || line[0] == '#':
		case line == "}":
			if len(stack) == 0 {
				return config{}, errSyntax
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			switch {
			case len(stack) == 1 && inNS && top == "mailbox" && junk:
				boxes = append(boxes, box)
			case len(stack) == 0 && inNS && (nsType == "" || nsType == "private"):
				c.addNamespace(boxes, cmp.Or(nsSep, "."), nsLoc)
			}
		case strings.HasSuffix(line, "{"):
			kind, name, _ := strings.Cut(strings.TrimSpace(strings.TrimSuffix(line, "{")), " ")
			stack = append(stack, kind)
			switch {
			case len(stack) == 1 && kind == "namespace":
				nsType, nsSep, nsLoc, boxes = "", "", "", nil
			case len(stack) == 2 && inNS && kind == "mailbox":
				box, junk = unquote(strings.TrimSpace(name)), false
			}
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return config{}, errSyntax
			}
			key, value = strings.TrimSpace(key), unquote(strings.TrimSpace(value))
			switch {
			case key == "mail_plugins":
				c.plugins = append(c.plugins, strings.Fields(value)...)
			case len(stack) == 0 && key == "mail_location":
				c.location = value
			case len(stack) == 1 && inNS && key == "type":
				nsType = value
			case len(stack) == 1 && inNS && key == "separator":
				nsSep = value
			case len(stack) == 1 && inNS && key == "location":
				nsLoc = value
			case len(stack) == 2 && inNS && stack[1] == "mailbox" && key == "special_use":
				junk = slices.ContainsFunc(strings.Fields(value), func(f string) bool { return strings.EqualFold(f, `\Junk`) })
			}
		}
	}
	if len(stack) != 0 {
		return config{}, errSyntax
	}
	return c, nil
}

func (c *config) addNamespace(boxes []string, sep, location string) {
	loc := 0
	if location != "" && len(boxes) > 0 {
		c.locs = append(c.locs, location)
		loc = len(c.locs)
	}
	for _, b := range boxes {
		c.junk = append(c.junk, junkBox{name: b, sep: sep, loc: loc})
	}
}

// unquote strips the quotes doveconf puts around names and values with
// spaces. doveconf prints backslashes as they are.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// harmlessParams are maildir location parameters that leave folder paths
// unchanged.
var harmlessParams = map[string]bool{
	"INBOX": true, "INDEX": true, "INDEXPVT": true, "CONTROL": true, "VOLATILEDIR": true,
	"LISTINDEX": true, "SUBSCRIPTIONS": true, "BROKENCHAR": true, "ITERINDEX": true, "NO-NOSELECT": true,
}

// parseLocation returns the Maildir++ root of a mail location and whether
// folder names are stored as UTF-8. A leading ~ expands to home only.
func parseLocation(loc, home string) (root string, utf8Names bool, reason string) {
	driver, rest, ok := strings.Cut(loc, ":")
	if !ok || !strings.EqualFold(driver, "maildir") {
		return "", false, SkipDriver
	}
	params := strings.Split(rest, ":")
	root = params[0]
	for _, p := range params[1:] {
		key, value, _ := strings.Cut(p, "=")
		switch {
		case key == "LAYOUT" && value == "fs":
			return "", false, SkipLayoutFS
		case key == "LAYOUT" && value == "maildir++":
		case key == "UTF-8":
			utf8Names = true
		case !harmlessParams[key]:
			// Includes "" from a "::" escape, DIRNAME and MAILBOXDIR.
			return "", false, SkipLocation
		}
	}
	if root == "~" || strings.HasPrefix(root, "~/") {
		if !absClean(home) {
			return "", false, SkipInvalidHome
		}
		root = home + root[1:]
	}
	// doveadm expands every location but a userdb mail field, which Dovecot
	// expands later: a % left there is a variable, not a path.
	if !absClean(root) || strings.Contains(root, "%") {
		return "", false, SkipLocation
	}
	return filepath.Clean(root), utf8Names, ""
}

// absClean accepts absolute paths without ".." components. Control bytes
// never get here: parseDetails refuses them in every field.
func absClean(p string) bool {
	return strings.HasPrefix(p, "/") && !slices.Contains(strings.Split(p, "/"), "..")
}

func control(r rune) bool { return r < 0x20 || r == 0x7f }

// folderDir is the Maildir++ directory of a namespace-relative mailbox name:
// a dot, then the hierarchy levels joined by dots. A level holding a dot or a
// slash cannot be stored, so the name is refused.
func folderDir(name, sep string, utf8Names bool) (string, bool) {
	if len(sep) != 1 || !utf8.ValidString(name) || strings.EqualFold(name, "INBOX") {
		return "", false
	}
	levels := strings.Split(name, sep)
	for i, l := range levels {
		if l == "" || strings.ContainsAny(l, "./") || strings.ContainsFunc(l, unicode.IsControl) {
			return "", false
		}
		if !utf8Names {
			levels[i] = mutf7(l)
		}
	}
	return "." + strings.Join(levels, "."), true
}

var imapBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)

// mutf7 is IMAP modified UTF-7 (RFC 3501 5.1.3), the encoding Dovecot uses
// for folder names on disk unless the location says UTF-8.
func mutf7(s string) string {
	var b strings.Builder
	var wide []rune
	flush := func() {
		if len(wide) == 0 {
			return
		}
		var raw []byte
		for _, u := range utf16.Encode(wide) {
			raw = binary.BigEndian.AppendUint16(raw, u)
		}
		b.WriteString("&" + imapBase64.EncodeToString(raw) + "-")
		wide = wide[:0]
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			wide = append(wide, r)
			continue
		}
		flush()
		b.WriteRune(r)
		if r == '&' {
			b.WriteByte('-')
		}
	}
	flush()
	return b.String()
}

// runCommand executes a command with stdin closed. Stdout over MaxListBytes
// stops it with an error; the first stderr bytes ride on an exec.ExitError.
// Cancelling ctx kills its whole process group, since doveconf forks.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	stdout := &capped{limit: MaxListBytes}
	stderr := &head{limit: 4096}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed Dovecot tools; arguments are constants, doveconf locations and validated user names after "--"
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if stdout.over {
		return nil, errTooLarge
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		exit.Stderr = stderr.buf.Bytes()
	}
	return stdout.buf.Bytes(), err
}

// capped fails a write past limit, which closes the pipe on the child. The
// buffer is a field, not embedded: an embedded ReadFrom would bypass Write.
type capped struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		c.over = true
		return 0, errTooLarge
	}
	return c.buf.Write(p)
}

// head keeps the first limit bytes and drops the rest.
type head struct {
	buf   bytes.Buffer
	limit int
}

func (h *head) Write(p []byte) (int, error) {
	h.buf.Write(p[:min(len(p), max(h.limit-h.buf.Len(), 0))])
	return len(p), nil
}

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
