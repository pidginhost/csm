package checks

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/processctx"
	"github.com/pidginhost/csm/internal/safepath"
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
	id             selfWriteFileIdentity
	size           int64
	version        string
	maxBytes       int64
	yaraGeneration uint64
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
	} else {
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
			return nil
		}
		// Cleaning '..' before refusing symlinks can name a different file
		// than execve did. An exited process cannot disambiguate that path.
		if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
			return nil
		}
		exe, source = filename, filename
	}
	docroot := roots.Lookup(exe)
	if docroot == "" {
		return nil
	}
	file, err := openDocrootBinary(source, source == procExePath(pid))
	if err != nil {
		return nil
	}
	defer file.Close()
	if _, production := osFS.(realOS); production && source == procExePath(pid) {
		// A PID can exec again between Readlink and Open. Attribute the
		// pinned image, never the path observed before the open.
		target, err := osFS.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
		if err != nil {
			return nil
		}
		exe = strings.TrimSuffix(target, " (deleted)")
		docroot = roots.Lookup(exe)
		if docroot == "" {
			return nil
		}
	}
	v, ok := inspectDocrootBinary(cfg, file)
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

// openDocrootBinary follows only kernel-owned /proc executable links. An
// exited process's start name is tenant-controlled, including every parent.
func openDocrootBinary(path string, proc bool) (*os.File, error) {
	if fs, production := osFS.(realOS); production {
		if proc {
			return fs.openRegularFile(path, 0)
		}
		dir, err := safepath.OpenDirNoFollow(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		defer func() { _ = dir.Close() }()
		return dir.OpenFile(filepath.Base(path), os.O_RDONLY, 0)
	}
	return osFS.Open(path)
}

// inspectDocrootBinary returns the verdict for the opened image, reading it
// only when this version of the file has no verdict yet. Non-regular files,
// failed reads and files changed during the read have no usable verdict.
func inspectDocrootBinary(cfg *config.Config, file *os.File) (docrootBinaryVerdict, bool) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return docrootBinaryVerdict{}, false
	}
	id, keyed := selfWriteIdentityFromFileInfo(info)
	maxBytes := FullScanMaxFileBytes(cfg)
	key := docrootBinaryKey{id: id, size: info.Size(), version: ContentDetectionVersion(), maxBytes: maxBytes, yaraGeneration: yara.CacheGeneration()}
	if keyed {
		docrootBinaryCache.Lock()
		v, hit := docrootBinaryCache.verdicts[key]
		docrootBinaryCache.Unlock()
		if hit {
			return v, true
		}
	}

	var header [4]byte
	_, err = file.ReadAt(header[:], 0)
	if err != nil && err != io.EOF {
		return docrootBinaryVerdict{}, false
	}
	v := docrootBinaryVerdict{program: bytes.Equal(header[:], elfMagic)}
	final := true
	switch {
	case !v.program:
	case info.Size() > maxBytes:
		v.gap = fmt.Sprintf("it is larger than the %d-byte scan limit", maxBytes)
	default:
		data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
		if readErr != nil || int64(len(data)) != info.Size() {
			return docrootBinaryVerdict{}, false
		}
		afterRead, statErr := file.Stat()
		if statErr != nil || !sameFileSnapshot(info, afterRead) {
			return docrootBinaryVerdict{}, false
		}
		if readID, ok := selfWriteIdentityFromFileInfo(afterRead); keyed && (!ok || id != readID) {
			return docrootBinaryVerdict{}, false
		}
		v.sha256 = fmt.Sprintf("%x", sha256.Sum256(data))
		backend := activeYARABackend()
		if backend == nil || backend.RuleCount() == 0 {
			v.gap, final = "no YARA rules are loaded", false
			break
		}
		// The worker has its own descriptor table. Keep our descriptor open
		// through the synchronous retry so exit or rename cannot redirect it.
		snapshotPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
		// #nosec G115 -- maxBytes is FullScanMaxFileBytes, at most a few hundred MiB.
		matches, scannedSHA, scanErr := yara.ScanContentOrPathChecked(backend, snapshotPath, data, int(maxBytes))
		if scanErr != nil {
			v.gap, final = "YARA scan failed: "+scanErr.Error(), false
			break
		}
		if scannedSHA != "" && scannedSHA != v.sha256 {
			return docrootBinaryVerdict{}, false
		}
		v.matches = matches
	}
	after, err := file.Stat()
	if err != nil || !sameFileSnapshot(info, after) {
		final = false
	}
	if err == nil {
		if afterID, ok := selfWriteIdentityFromFileInfo(after); keyed && (!ok || id != afterID) {
			final = false
		}
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
