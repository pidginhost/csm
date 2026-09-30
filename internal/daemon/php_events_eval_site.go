package daemon

import (
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

// phpEvalCodeSuffix is how PHP names code run by eval(): the file of the
// eval() call, its line in parentheses, then this suffix.
const phpEvalCodeSuffix = ") : eval()'d code"

const phpShieldSystemEvalNote = "The reported eval() site is a root-owned file no account can change. The evaluated code and event sender were not verified."

var (
	// phpShieldEvalSiteLstat is replaceable so tests can describe root-owned
	// trees they cannot create.
	phpShieldEvalSiteLstat = os.Lstat
	// phpShieldEvalSiteTimeout bounds how long one event may hold the Shield
	// event reader while its eval site is inspected.
	phpShieldEvalSiteTimeout = 500 * time.Millisecond
	// phpShieldEvalSiteProbe admits one inspection at a time. A probe stuck in
	// a hung mount keeps it, so later events are graded at once instead of
	// each stalling the reader and leaving another blocked thread behind.
	phpShieldEvalSiteProbe = make(chan struct{}, 1)
)

// phpShieldEvalSiteIsSystemCode reports whether errorFile names a single
// reported eval() call in a root-owned file that no account can change.
//
// WP Toolkit's bundled wp-cli running "wp eval" as the account is the common
// case. An account that runs that script with its own code gains nothing from
// the lower grade: the Shield is loaded by that account's own PHP process,
// which can already turn it off. The event fields do not prove who sent it
// or which code ran. A web request that reaches such an eval() is still
// reported at Warning. A reported site in a file an account can write must
// stay High, so ownership is checked on the live filesystem at receipt for
// the file and every directory above it, without following symlinks. cPanel
// account homes are owned by the account, so no path under one qualifies.
// Anything this cannot prove keeps the High grade.
func phpShieldEvalSiteIsSystemCode(errorFile string) bool {
	site, ok := strings.CutSuffix(errorFile, phpEvalCodeSuffix)
	if !ok {
		return false
	}
	open := strings.LastIndexByte(site, '(')
	if open < 0 {
		return false
	}
	file, line := site[:open], site[open+1:]
	if line == "" || strings.Trim(line, "0123456789") != "" {
		return false
	}
	// PHP reports resolved paths, so anything else did not come from PHP. A
	// nested eval() blames the outer eval()'d code, which is no file, so the
	// walk refuses it.
	if !path.IsAbs(file) || path.Clean(file) != file {
		return false
	}
	return phpShieldEvalSiteProven(file)
}

// phpShieldEvalSiteProven runs the ownership walk with a deadline. Event
// fields are forgeable by any local user, so a path on a hung network mount
// must cost the reader one timeout at most, and then nothing until it clears.
func phpShieldEvalSiteProven(file string) bool {
	select {
	case phpShieldEvalSiteProbe <- struct{}{}:
	default:
		return false
	}
	result := make(chan bool, 1)
	go func() {
		proven := rootOwnedUnwritableChain(file)
		// Release before publishing, including after a timeout. The next
		// event must not depend on a separate waiter being scheduled.
		<-phpShieldEvalSiteProbe
		result <- proven
	}()
	timer := time.NewTimer(phpShieldEvalSiteTimeout)
	defer timer.Stop()
	select {
	case proven := <-result:
		return proven
	case <-timer.C:
		return false
	}
}

// rootOwnedUnwritableChain reports whether file is a regular file and it and
// every directory from / down to it are real (not symlinks), owned by root,
// and without group or other write permission.
func rootOwnedUnwritableChain(file string) bool {
	current := "/"
	components := strings.Split(file[1:], "/")
	for i := -1; i < len(components); i++ {
		if i >= 0 {
			current = path.Join(current, components[i])
		}
		info, err := phpShieldEvalSiteLstat(current)
		if err != nil {
			return false
		}
		last := i == len(components)-1
		if (last && !info.Mode().IsRegular()) || (!last && !info.Mode().IsDir()) {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
	}
	return true
}
