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

// DetachedWebProcessCheck reports a process a web request started that kept
// running after the request, still holding the PHP handler's listening socket
// it inherited from the PHP worker.
const DetachedWebProcessCheck = "detached_web_process"

// detachedWebProcessMinAge keeps short jobs a request starts in the
// background, such as an image conversion, out of the report.
const detachedWebProcessMinAge = 5 * time.Minute

type webSocketHolder struct {
	pid     int
	exe     string
	uid     string
	sockets []string
}

// CheckDetachedWebProcesses reports non-root processes that hold a PHP
// handler's listening socket while being neither the PHP or web server
// runtime nor a child of one: a request started them and they outlived it.
// The socket is inherited, so a shell loop or downloader a webshell started
// carries it whatever its name or command line.
func CheckDetachedWebProcesses(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	listeners := unixListeners()
	if len(listeners) == 0 {
		return nil
	}
	procs, _ := osFS.Glob("/proc/[0-9]*")
	heldByPHP := make(map[string]bool)
	var holders []webSocketHolder
	for _, dir := range procs {
		if ctx.Err() != nil {
			return nil
		}
		id := filepath.Base(dir)
		pid, ok := parseProcessPID(id)
		if !ok {
			continue
		}
		held := heldListeners(id, listeners)
		if len(held) == 0 {
			continue
		}
		exe := getProcessExe(id)
		if isServerPHPExe(exe) {
			for _, inode := range held {
				heldByPHP[inode] = true
			}
			continue
		}
		uid := getProcessUID(id)
		if exe == "" || uid == "" || uid == "0" || isWebServerExe(exe) {
			continue
		}
		holders = append(holders, webSocketHolder{pid: pid, exe: exe, uid: uid, sockets: held})
	}

	now := time.Now()
	var findings []alert.Finding
	for _, h := range holders {
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
		parent, _, ok := procParentAndTTY(id)
		// A child of a running PHP worker is still part of its request.
		if !ok || isWebServerExe(getProcessExe(strconv.Itoa(parent))) {
			continue
		}
		if !processStartedBefore(id, now.Add(-detachedWebProcessMinAge)) {
			continue
		}
		cmdline, _ := osFS.ReadFile(filepath.Join("/proc", id, "cmdline"))
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     DetachedWebProcessCheck,
			Message:   fmt.Sprintf("Process left running by a web request: %s (PID %d)", h.exe, h.pid),
			Details:   fmt.Sprintf("PID: %d, UID: %s, parent PID: %d, exe: %s, cmdline: %s\nHolds PHP handler socket: %s", h.pid, h.uid, parent, h.exe, redactProcCommandLine(cmdline), strings.Join(sockets, ", ")),
			PID:       h.pid,
			TenantID:  HostingAccountForUser(uidStringToUser(h.uid)),
			Timestamp: now,
			// The same rules as for a process that writes back a removed file
			// decide what may be stopped: nil when a terminal or an SSH, cron
			// or cPanel session is in its ancestry.
			WriterChain:      restoreWriterChain(h.pid, now, false),
			WriterObservedAt: now,
		})
	}
	return dropCoveredDetachedProcesses(findings)
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

// unixListeners maps the inode of each listening unix socket to its path.
func unixListeners() map[string]string {
	data, err := osFS.ReadFile("/proc/net/unix")
	if err != nil {
		return nil
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n")[1:] {
		// Num RefCount Protocol Flags Type St Inode Path
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x10000 == 0 { // __SO_ACCEPTCON: listening
			continue
		}
		out[fields[6]] = fields[7]
	}
	return out
}

// heldListeners returns the inodes of listening sockets in listeners that the
// process holds open.
func heldListeners(pid string, listeners map[string]string) []string {
	fds, _ := osFS.Glob(filepath.Join("/proc", pid, "fd", "*"))
	var held []string
	for _, fd := range fds {
		target, err := osFS.Readlink(fd)
		if err != nil {
			continue
		}
		inode, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		inode = strings.TrimSuffix(inode, "]")
		if _, listening := listeners[inode]; listening {
			held = append(held, inode)
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
