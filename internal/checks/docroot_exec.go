package checks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/processctx"
	"github.com/pidginhost/csm/internal/yara"
)

var elfMagic = []byte("\x7fELF")

// docrootBinaryVerdict is what reading one program file established.
type docrootBinaryVerdict struct {
	program bool // the file is an ELF image, not a script
	matches []yara.Match
	sha256  string
	gap     string // why the content was not scanned; empty when it was
}

type docrootBinaryKey struct {
	id      selfWriteFileIdentity
	size    int64
	version string
}

// docrootBinaryCacheMax bounds the verdict cache. Reaching it drops the whole
// cache, which costs only a rescan of the programs that start next.
const docrootBinaryCacheMax = 4096

// docrootBinaryCache keeps verdicts per file version so a program a site runs
// on every request is read once. The key includes the inode change time,
// which a writer cannot set back, so changed content is always read again.
var docrootBinaryCache = struct {
	sync.Mutex
	verdicts map[docrootBinaryKey]docrootBinaryVerdict
}{}

func resetDocrootBinaryCache() {
	docrootBinaryCache.Lock()
	docrootBinaryCache.verdicts = nil
	docrootBinaryCache.Unlock()
}

func procExePath(pid int) string {
	return "/proc/" + strconv.Itoa(pid) + "/exe"
}

// InspectDocrootExec judges a non-root process whose program file sits in a
// document root. Web servers run CGI programs from there and build tools run
// from node_modules, so the location alone is not a finding: a program that
// matches a YARA rule is reported at the rule's severity whoever started it,
// and one started directly by a PHP interpreter is reported as a Warning,
// because that is how a webshell launches a dropper or miner.
//
// filename is the name the process was started with and may be relative.
// /proc decides what actually runs: a script names its interpreter there,
// which lies outside the document root. Only when the process has already
// exited is the started name read instead, and then a file without the ELF
// magic is taken to be a script.
func InspectDocrootExec(cfg *config.Config, pid, uid int, filename, parentComm string, roots *DocrootIndex) *alert.Finding {
	if uid == 0 || pid <= 0 {
		return nil
	}
	exe, source := "", procExePath(pid)
	if target, err := osFS.Readlink(source); err == nil {
		// The kernel keeps a deleted program running and marks its path.
		exe = strings.TrimSuffix(target, " (deleted)")
	} else if filepath.IsAbs(filename) {
		exe = filepath.Clean(filename)
		source = exe
	} else {
		return nil
	}
	docroot := roots.Lookup(exe)
	if docroot == "" {
		return nil
	}
	v, ok := inspectDocrootBinary(cfg, source)
	if !ok || !v.program {
		return nil
	}

	details := fmt.Sprintf("UID: %d\nParent process: %s\nDocument root: %s", uid, parentComm, docroot)
	finding := alert.Finding{
		Check:         "docroot_binary_exec",
		Details:       details,
		FilePath:      exe,
		PID:           pid,
		ContentSHA256: v.sha256,
		Timestamp:     time.Now(),
	}
	if userName, account := processIdentityForUID(uid); userName != "" {
		finding.Process = &processctx.ProcessContext{PID: pid, UID: uid, User: userName, Account: account}
	}
	if len(v.matches) > 0 {
		names := make([]string, 0, len(v.matches))
		finding.Severity = alert.Warning
		for _, m := range v.matches {
			names = append(names, m.RuleName)
			if sev := yaraMatchSeverity(m.Meta["severity"]); sev > finding.Severity {
				finding.Severity = sev
			}
		}
		finding.Message = fmt.Sprintf("Program matching YARA rule %s started from document root: %s", strings.Join(names, ", "), exe)
		return &finding
	}
	if !isPHPInterpreterComm(parentComm) {
		return nil
	}
	note := "No YARA rule matched the program."
	if v.gap != "" {
		note = "The program was not scanned: " + v.gap + "."
	}
	finding.Severity = alert.Warning
	finding.Message = fmt.Sprintf("PHP started a program from document root: %s", exe)
	finding.Details = note + "\n" + details
	return &finding
}

// inspectDocrootBinary returns the verdict for the file at path, reading it
// only when this version of the file has no verdict yet. ok is false when the
// file cannot be opened or is not a regular file.
func inspectDocrootBinary(cfg *config.Config, path string) (docrootBinaryVerdict, bool) {
	file, err := osFS.Open(path)
	if err != nil {
		return docrootBinaryVerdict{}, false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return docrootBinaryVerdict{}, false
	}
	id, keyed := selfWriteIdentityFromFileInfo(info)
	key := docrootBinaryKey{id: id, size: info.Size(), version: ContentDetectionVersion()}
	if keyed {
		docrootBinaryCache.Lock()
		v, hit := docrootBinaryCache.verdicts[key]
		docrootBinaryCache.Unlock()
		if hit {
			return v, true
		}
	}

	maxBytes := FullScanMaxFileBytes(cfg)
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return docrootBinaryVerdict{}, false
	}
	v := docrootBinaryVerdict{program: bytes.HasPrefix(data, elfMagic)}
	final := true
	switch {
	case !v.program:
	case int64(len(data)) > maxBytes:
		v.gap = fmt.Sprintf("it is larger than the %d-byte scan limit", maxBytes)
	default:
		v.sha256 = fmt.Sprintf("%x", sha256.Sum256(data))
		backend := activeYARABackend()
		if backend == nil || backend.RuleCount() == 0 {
			v.gap, final = "no YARA rules are loaded", false
			break
		}
		// #nosec G115 -- maxBytes is FullScanMaxFileBytes, at most a few hundred MiB.
		matches, scannedSHA, scanErr := yara.ScanContentOrPathChecked(backend, path, data, int(maxBytes))
		if scanErr != nil {
			v.gap, final = "YARA scan failed: "+scanErr.Error(), false
			break
		}
		if scannedSHA != "" {
			v.sha256 = scannedSHA
		}
		v.matches = matches
	}
	if keyed && final {
		docrootBinaryCache.Lock()
		if len(docrootBinaryCache.verdicts) >= docrootBinaryCacheMax || docrootBinaryCache.verdicts == nil {
			docrootBinaryCache.verdicts = make(map[docrootBinaryKey]docrootBinaryVerdict)
		}
		docrootBinaryCache.verdicts[key] = v
		docrootBinaryCache.Unlock()
	}
	return v, true
}

// isPHPInterpreterComm reports whether a process name is a PHP interpreter:
// lsphp, php-fpm, php-cgi or the php CLI, with an optional version suffix as
// distributions install them (php8.2, php-fpm8.1). A process started through
// a symlink is named after the link, which covers cPanel's ea-php81 commands.
func isPHPInterpreterComm(comm string) bool {
	for _, name := range []string{"lsphp", "php-fpm", "php-cgi", "ea-php", "php"} {
		if rest, ok := strings.CutPrefix(comm, name); ok && strings.Trim(rest, "0123456789.") == "" {
			return true
		}
	}
	return false
}
