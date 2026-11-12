package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// DetachedWebProcessCheck reports a process holding a PHP listener without a
// live web worker in its ancestry. Legitimate background jobs also do this,
// so only a shell, the loop shape a webshell leaves behind, is Critical and
// may be stopped; anything else is a Warning to review.
const DetachedWebProcessCheck = "detached_web_process"

// detachedWebProcessMinAge keeps short jobs a request starts in the
// background, such as an image conversion, out of the report.
const detachedWebProcessMinAge = 5 * time.Minute

type webSocketHolder struct {
	pid     int
	exe     string
	uid     string
	start   uint64
	sockets []string
}

// CheckDetachedWebProcesses reports non-root processes that hold a PHP
// handler's listening socket without a web runtime in their ancestry.
func CheckDetachedWebProcesses(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	listeners := unixListeners()
	if len(listeners) == 0 || ctx.Err() != nil {
		return nil
	}
	procs, _ := osFS.Glob("/proc/[0-9]*")
	heldByPHP := make(map[string]bool)
	var holders []webSocketHolder
	now := time.Now()
	for _, dir := range procs {
		if ctx.Err() != nil {
			return nil
		}
		id := filepath.Base(dir)
		pid, ok := parseProcessPID(id)
		if !ok {
			continue
		}
		start, ok := procStartTicks(id)
		if !ok {
			continue
		}
		exe := getProcessExe(id)
		php := isServerPHPExe(exe)
		uid := getProcessUID(id)
		// Descriptor tables can be large. Only PHP workers and eligible detached
		// processes can contribute evidence, so reject other processes first.
		if !php && (exe == "" || uid == "" || uid == "0" || isWebServerExe(exe) ||
			!processStartedBefore(id, now.Add(-detachedWebProcessMinAge))) {
			continue
		}
		if !php {
			if _, ok := detachedWebParent(id); !ok {
				continue
			}
		}
		held := heldListeners(ctx, id, listeners)
		if len(held) == 0 {
			continue
		}
		h := webSocketHolder{pid: pid, exe: exe, uid: uid, start: start, sockets: held}
		if !h.current() {
			continue
		}
		if php {
			for _, inode := range held {
				heldByPHP[inode] = true
			}
			continue
		}
		holders = append(holders, h)
	}

	var findings []alert.Finding
	for _, h := range holders {
		if ctx.Err() != nil {
			return nil
		}
		var sockets []string
		for _, inode := range h.sockets {
			if heldByPHP[inode] || phpHandlerSocketPath(listeners[inode]) {
				sockets = append(sockets, listeners[inode])
			}
		}
		if len(sockets) == 0 {
			continue
		}
		id := strconv.Itoa(h.pid)
		parent, ok := detachedWebParent(id)
		if !ok {
			continue
		}
		cmdline, _ := osFS.ReadFile(filepath.Join("/proc", id, "cmdline"))
		// A scan spans many processes. Do not attach an old process's socket
		// evidence to a replacement PID, executable or account.
		if !h.current() {
			continue
		}
		f := alert.Finding{
			Severity:  alert.Warning,
			Check:     DetachedWebProcessCheck,
			Message:   fmt.Sprintf("Detached process holds a PHP handler socket: %s (PID %d)", h.exe, h.pid),
			Details:   fmt.Sprintf("PID: %d, UID: %s, parent PID: %d, exe: %s, cmdline: %s\nHolds PHP handler socket: %s\nSocket inheritance also occurs in legitimate background jobs; review before taking action.", h.pid, h.uid, parent, h.exe, redactProcCommandLine(cmdline), strings.Join(sockets, ", ")),
			PID:       h.pid,
			TenantID:  HostingAccountForUser(uidStringToUser(h.uid)),
			Timestamp: now,
		}
		if isShellExe(h.exe) {
			f.Severity = alert.Critical
			f.Message = fmt.Sprintf("Shell left running by a web request: %s (PID %d)", h.exe, h.pid)
			f.Details = fmt.Sprintf("PID: %d, UID: %s, parent PID: %d, exe: %s, cmdline: %s\nHolds PHP handler socket: %s", h.pid, h.uid, parent, h.exe, redactProcCommandLine(cmdline), strings.Join(sockets, ", "))
			// The rules for a process that writes back a removed file decide
			// what may be stopped: nil with a terminal or an SSH, cron or
			// cPanel session in the ancestry.
			f.WriterChain = restoreWriterChain(h.pid, now, false)
			f.WriterObservedAt = now
		}
		findings = append(findings, f)
	}
	return dropCoveredDetachedProcesses(findings)
}

// isShellExe matches the command shells a webshell's loop runs in.
func isShellExe(exe string) bool {
	switch filepath.Base(strings.TrimSuffix(exe, " (deleted)")) {
	case "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "csh", "tcsh", "busybox":
		return true
	}
	return false
}

// dropCoveredDetachedProcesses keeps one finding per process tree: a process
// already in another finding's stop chain is stopped with it.
func dropCoveredDetachedProcesses(findings []alert.Finding) []alert.Finding {
	covered := make(map[int]bool)
	for _, f := range findings {
		for _, pid := range f.WriterChain {
			if pid != f.PID {
				covered[pid] = true
			}
		}
	}
	out := findings[:0]
	for _, f := range findings {
		if !covered[f.PID] {
			out = append(out, f)
		}
	}
	return out
}

func (h webSocketHolder) current() bool {
	id := strconv.Itoa(h.pid)
	exe, uid := getProcessExe(id), getProcessUID(id)
	start, ok := procStartTicks(id)
	return ok && start == h.start && exe == h.exe && uid == h.uid
}

// detachedWebParent requires a complete ancestry to init with no live web
// runtime. Checking only the immediate parent mistakes a request's shell
// grandchildren for detached jobs. Procfs exposes parents in its own PID
// namespace; missing ancestors or namespace boundaries are inconclusive.
func detachedWebParent(id string) (int, bool) {
	parent, _, ok := procParentAndTTY(id)
	if !ok {
		return 0, false
	}
	for p, depth := parent, 0; depth < maxRestoreChainDepth; depth++ {
		if p == 1 {
			return parent, true
		}
		if p < 1 {
			return 0, false
		}
		ancestor := strconv.Itoa(p)
		exe := getProcessExe(ancestor)
		if exe == "" || isWebServerExe(exe) {
			return 0, false
		}
		p, _, ok = procParentAndTTY(ancestor)
		if !ok {
			return 0, false
		}
	}
	return 0, false
}

// unixListeners maps the inode of each listening unix socket to its path.
func unixListeners() map[string]string {
	data, err := osFS.ReadFile("/proc/net/unix")
	if err != nil {
		return nil
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		inode, path, ok := parseUnixListener(line)
		if ok {
			out[inode] = path
		}
	}
	return out
}

func parseUnixListener(line string) (inode, path string, ok bool) {
	// Only the seven fixed columns are whitespace-delimited. Everything after
	// the inode's separator is the socket name, including spaces and tabs.
	var fields [7]string
	for i := range fields {
		line = strings.TrimLeft(line, " \t")
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			return "", "", false
		}
		fields[i], line = line[:end], line[end+1:]
	}
	flags, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil || flags&0x10000 == 0 || fields[4] != "0001" || line == "" {
		return "", "", false
	}
	number, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil || number == 0 {
		return "", "", false
	}
	return fields[6], line, true
}

// heldListeners returns the inodes of listening sockets in listeners that the
// process holds open.
func heldListeners(ctx context.Context, pid string, listeners map[string]string) []string {
	fds, _ := osFS.Glob(filepath.Join("/proc", pid, "fd", "*"))
	var held []string
	seen := make(map[string]bool)
	for _, fd := range fds {
		if ctx.Err() != nil {
			return nil
		}
		target, err := osFS.Readlink(fd)
		if err != nil {
			continue
		}
		inode, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		inode, ok = strings.CutSuffix(inode, "]")
		if !ok {
			continue
		}
		if _, listening := listeners[inode]; listening && !seen[inode] {
			held = append(held, inode)
			seen[inode] = true
		}
	}
	return held
}

// phpHandlerSocketPath reports a listener a web server hands PHP requests to:
// LiteSpeed's APVH_<user>_<handler>.sock for a PHP handler, or a PHP-FPM
// pool. The account name in a LiteSpeed socket is never taken as the handler.
func phpHandlerSocketPath(path string) bool {
	base := filepath.Base(path)
	if rest, ok := strings.CutPrefix(base, "APVH_"); ok {
		_, handler, ok := strings.Cut(rest, "_")
		return ok && strings.Contains(strings.ToLower(handler), "php")
	}
	return strings.Contains(path, "/php-fpm/") || strings.HasPrefix(base, "php") && strings.Contains(base, "fpm")
}
