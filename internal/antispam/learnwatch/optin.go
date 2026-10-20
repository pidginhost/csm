package learnwatch

import (
	"errors"
	"io/fs"
	"os"
)

// GlobalOptInPath makes every account eligible; core then warns that no
// account can opt out.
const GlobalOptInPath = "/etc/global_spamassassin_enable"

// optInName is the per-account Spam Filters switch in the home directory.
const optInName = ".spamassassinenable"

// Eligibility skip reasons.
const (
	SkipOptedOut        = "opted_out"
	SkipOptInSymlink    = "optin_symlink"
	SkipOptInNotRegular = "optin_not_regular"
)

// GlobalOptIn reports whether the host-wide override exists. Errors other
// than absence are returned, never read as off.
func GlobalOptIn(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

// Eligible applies core's Spam Filters rule under the pinned home. The
// switch must be a regular file; a symlink or other type is off with a
// reason. A stat failure is an error so the caller retries.
func (h *Home) Eligible(global bool) (bool, string, error) {
	if global {
		return true, "", nil
	}
	fi, err := lstatAt(h.dir, optInName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, SkipOptedOut, nil
	case err != nil:
		return false, "", err
	case fi.Mode()&fs.ModeSymlink != 0:
		return false, SkipOptInSymlink, nil
	case !fi.Mode().IsRegular():
		return false, SkipOptInNotRegular, nil
	}
	return true, "", nil
}
