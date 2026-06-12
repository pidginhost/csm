package checks

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// pkgManagerLogs is the ordered set of package-manager log files whose
// recent mtime acts as evidence of a legitimate root-driven file system
// change. RPM-family hosts touch dnf.rpm.log / yum.log; Debian-family
// hosts touch dpkg.log; minimal installs add history.log for unattended-
// upgrades. The variable is package-private (no operator override) so an
// attacker who learns CSM is here cannot point the daemon at an empty
// path -- the trade-off is that mtime spoofing requires root, which is
// already game-over for this detector class.
var pkgManagerLogs = []string{
	"/var/log/dnf.rpm.log",
	"/var/log/dnf.log",
	"/var/log/yum.log",
	"/var/log/dpkg.log",
	"/var/log/apt/history.log",
}

// AncestryProbe reports whether the process tree rooted at pid contains a
// package-manager process. Nil on hosts without BPF process context, in
// which case ancestry checks no-op and the pkg-window + cron-content layers
// still apply. The BPF daemon wires this from processctx at startup.
var AncestryProbe func(pid uint32) bool

// pkgManagerWindow returns true when any pkgManagerLogs file was modified
// within window. Reads file mtime only; does not parse log contents.
func pkgManagerWindow(now time.Time, window time.Duration) bool {
	cutoff := now.Add(-window)
	for _, p := range pkgManagerLogs {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.ModTime().After(cutoff) {
			return true
		}
	}
	return false
}

// cronDangerTokens are byte fragments whose presence in a cron drop-in is
// inconsistent with vendor-shipped automation and consistent with
// post-exploitation persistence. The list is intentionally narrow: false
// positives here cancel the demote, which is the safe failure mode.
var cronDangerTokens = [][]byte{
	[]byte("| sh"),
	[]byte("|sh "),
	[]byte("| bash"),
	[]byte("|bash "),
	[]byte("; sh "),
	[]byte(";sh "),
	[]byte("; bash"),
	[]byte(";bash "),
	[]byte("base64 -d"),
	[]byte("base64 --decode"),
	[]byte("base64_decode"),
	[]byte("eval("),
	[]byte("eval $("),
	[]byte("eval \""),
	[]byte("/tmp/"),
	[]byte("/var/tmp/"),
	[]byte("/dev/shm/"),
	[]byte("python -c"),
	[]byte("python3 -c"),
	[]byte("perl -e"),
	[]byte("ruby -e"),
	[]byte("nc -e"),
	[]byte("ncat -e"),
	[]byte("bash -i"),
	[]byte("\\x"),
	[]byte("curl "),
	[]byte("wget "),
}

// cronHasDangerTokens returns true if any cronDangerTokens byte fragment
// appears in content. Case-sensitive; cron content is shell, so case
// matters (PATH lookups, builtins). The curl/wget tokens are broad on
// purpose: a vendor cron that needs to fetch is rare enough that flagging
// is the right default.
func cronHasDangerTokens(content []byte) bool {
	for _, tok := range cronDangerTokens {
		if bytes.Contains(content, tok) {
			return true
		}
	}
	return false
}

// rescoreSensitive returns f with severity adjusted per provenance signals:
//   - package-manager activity inside pkgWindowDefault demotes High to Warning
//   - AncestryProbe(pid) returning true demotes High to Warning
//   - cron class with cronHasDangerTokens(content) vetoes any demote
//
// content and pid are optional (nil / 0). class is "" for non-classified
// findings. now is injected for deterministic testing.
func rescoreSensitive(f alert.Finding, class string, content []byte, pid uint32, now time.Time) alert.Finding {
	if f.Severity != alert.High {
		return f
	}
	veto := class == "cron" && len(content) > 0 && cronHasDangerTokens(content)
	if veto {
		return f
	}
	var reason string
	if pkgManagerWindow(now, pkgWindowDefault) {
		reason = "package manager active within window"
	} else if pid != 0 && AncestryProbe != nil && AncestryProbe(pid) {
		reason = "ancestor is package manager"
	}
	if reason == "" {
		return f
	}
	f.Severity = alert.Warning
	if f.Details == "" {
		f.Details = fmt.Sprintf("Demoted: %s", reason)
	} else {
		f.Details = fmt.Sprintf("%s [demoted: %s]", f.Details, reason)
	}
	return f
}

// PkgManagerRecentlyActive reports whether any package-manager log was
// modified within the provenance demotion window. Exported for the fanotify
// /tmp-executable demotion, which gates on the same evidence as
// rescoreSensitive.
func PkgManagerRecentlyActive(now time.Time) bool {
	return pkgManagerWindow(now, pkgWindowDefault)
}

// pkgWindowDefault is the slack we give for a legitimate root-driven file
// system change after a package transaction. dnf scriptlets observed up to
// a few seconds between the rpm log entry and post-install file drops; 2
// minutes covers slower scriptlets without inviting a multi-minute window
// for an attacker who happened to time a transaction.
const pkgWindowDefault = 2 * time.Minute
