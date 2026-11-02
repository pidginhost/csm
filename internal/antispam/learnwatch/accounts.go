// Package learnwatch finds new reports in tenants' Spam folders and hands
// them to the learning engine (spec 7.1 to 7.3).
package learnwatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/admission"
)

// MaxPasswdBytes bounds the password database read.
const MaxPasswdBytes = 8 << 20

// Account skip reasons.
const (
	SkipNoPasswd = "no_passwd_entry"
	SkipBadHome  = "bad_home"
	SkipRootUID  = "root_uid"
)

// Account is one cPanel account with its passwd identity, or a Postfix
// reporter with only its id. Home may sit on any partition; its owner is
// checked when it is opened.
type Account struct {
	Name     string
	UID, GID int
	Home     string
}

// Skip is a name left out, with the reason. UID is the passwd UID when
// known: a skipped account still exists and holds it.
type Skip struct {
	Name   string
	Reason string
	UID    int
}

// Source supplies the account registry and the password database.
type Source interface {
	CPanelUsers() ([]string, error)
	Passwd() ([]byte, error)
}

// LiveSource reads /var/cpanel/users and /etc/passwd.
type LiveSource struct {
	UsersDir   string
	PasswdPath string
}

// DefaultSource is the host's registry.
var DefaultSource = LiveSource{UsersDir: "/var/cpanel/users", PasswdPath: "/etc/passwd"}

// CPanelUsers lists regular account records without following symlinks.
func (s LiveSource) CPanelUsers() ([]string, error) {
	entries, err := os.ReadDir(s.UsersDir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// Passwd reads the password database, one byte past the bound so an
// oversized file is detected.
func (s LiveSource) Passwd() ([]byte, error) {
	f, err := os.Open(s.PasswdPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxPasswdBytes+1))
}

type pwEntry struct {
	uid, gid int
	home     string
}

// registry is one pass's reporters: cPanel accounts with their homes, or
// Postfix reporters with their Junk folders.
type registry struct {
	accounts []Account
	// skips holds the reason of every name left out.
	skips []string
	// held are the ids that keep their reservations: every reporter, and
	// those that only skipped names still hold.
	held map[int]bool
	// junk maps each Postfix reporter's Junk folders to the uid that owns
	// their mailbox's files.
	junk map[int]map[FolderKey]int
	// unchecked ids keep their folder state; complete false keeps every
	// reporter's.
	unchecked []int
	complete  bool
	// removed rechecks with a fresh read that uid is gone.
	removed func(ctx context.Context, uid int) (bool, error)
}

func cpanelRegistry(src Source) (registry, error) {
	accounts, skips, err := Accounts(src)
	if err != nil {
		return registry{}, err
	}
	// A registry name without a usable UID cannot be distinguished from a
	// deleted account by the UID-keyed persisted state.
	reg := registry{accounts: accounts, held: map[int]bool{}, complete: len(skips) == 0}
	for _, a := range accounts {
		reg.held[a.UID] = true
	}
	// An account CSM cannot read still holds its UID.
	for _, s := range skips {
		reg.skips = append(reg.skips, s.Reason)
		if s.Reason == SkipBadHome {
			reg.held[s.UID] = true
		}
	}
	reg.removed = func(_ context.Context, uid int) (bool, error) {
		current, skipped, err := Accounts(src)
		if err != nil {
			return false, err
		}
		return !slices.ContainsFunc(current, func(a Account) bool { return a.UID == uid }) &&
			!slices.ContainsFunc(skipped, func(s Skip) bool { return s.Reason == SkipBadHome && s.UID == uid }), nil
	}
	return reg, nil
}

// Accounts joins registry names with passwd. Names outside the account
// alphabet and root are not accounts and are dropped silently.
func Accounts(src Source) ([]Account, []Skip, error) {
	names, err := src.CPanelUsers()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot list cPanel accounts: %w", err)
	}
	names = slices.Clone(names)
	data, err := src.Passwd()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read the password database: %w", err)
	}
	if len(data) > MaxPasswdBytes {
		return nil, nil, errors.New("the password database is larger than the limit")
	}
	pw := parsePasswd(data)
	var out []Account
	var skips []Skip
	for _, name := range names {
		if name == "root" || !admission.ValidAccountName(name) {
			continue
		}
		e, ok := pw[name]
		switch {
		case !ok:
			skips = append(skips, Skip{Name: name, Reason: SkipNoPasswd})
		case e.uid == 0:
			skips = append(skips, Skip{Name: name, Reason: SkipRootUID})
		case !filepath.IsAbs(e.home) || e.home == "/" || filepath.Clean(e.home) != e.home || strings.ContainsRune(e.home, 0):
			skips = append(skips, Skip{Name: name, Reason: SkipBadHome, UID: e.uid})
		default:
			out = append(out, Account{Name: name, UID: e.uid, GID: e.gid, Home: e.home})
		}
	}
	// A rename or UID reuse between the two reads must not make a held
	// UID appear removed. Retry the pass instead of joining mixed lists.
	after, err := src.CPanelUsers()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot recheck cPanel accounts: %w", err)
	}
	after = slices.Clone(after)
	before := slices.Clone(names)
	slices.Sort(before)
	slices.Sort(after)
	if !slices.Equal(before, after) {
		return nil, nil, errors.New("cPanel account registry changed during read")
	}
	return out, skips, nil
}

// parsePasswd keeps the first well-formed entry per name, as getpwnam does.
func parsePasswd(data []byte) map[string]pwEntry {
	out := map[string]pwEntry{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		f := strings.Split(string(line), ":")
		if len(f) != 7 {
			continue
		}
		if _, dup := out[f[0]]; dup {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
			continue
		}
		// Linux IDs are 32-bit; the all-ones value is a syscall sentinel.
		if int64(uid) >= math.MaxUint32 || int64(gid) >= math.MaxUint32 {
			continue
		}
		out[f[0]] = pwEntry{uid: uid, gid: gid, home: f[5]}
	}
	return out
}
