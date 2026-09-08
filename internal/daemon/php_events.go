package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/phpshield"
	"golang.org/x/sys/unix"
)

const (
	phpEventMaxBytes        = 64 * 1024
	phpEventArchiveMaxBytes = 10 * 1024 * 1024
	phpEventSocketMode      = 0o222
)

var (
	phpEventsLogPath       = phpshield.EventLogPath
	phpEventsSocketPath    = phpshield.EventSocketPath
	phpEventRetryInterval  = 2 * time.Second
	phpShieldEventListener = listenPHPShieldEventSocket
	errPHPEventArchiveFull = errors.New("PHP Shield event archive reached its size cap; rotate it before events can be archived again")
)

type phpEventPacketListener interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
}

type phpEventUnixgramListener struct {
	*net.UnixConn
	path string
	info os.FileInfo
}

func (l *phpEventUnixgramListener) Close() error {
	err := l.UnixConn.Close()
	if info, statErr := os.Lstat(l.path); statErr == nil && os.SameFile(l.info, info) {
		_ = os.Remove(l.path)
	}
	return err
}

func listenPHPShieldEventSocket(path string) (phpEventPacketListener, error) {
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("PHP Shield event socket path is not a socket")
		}
		// Before this release the directory was tenant-writable. Do not trust an
		// active socket a tenant may have planted there before the installer
		// hardened it: otherwise Shield events could be delivered to that tenant.
		stat, statOK := info.Sys().(*syscall.Stat_t)
		foreignSocket := os.Geteuid() == 0 && statOK && stat.Uid != 0
		if !foreignSocket {
			probe, probeErr := net.DialUnix("unixgram", nil, addr)
			if probeErr == nil {
				_ = probe.Close()
				return nil, fmt.Errorf("PHP Shield event socket is already active")
			}
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return nil, fmt.Errorf("removing stale PHP Shield event socket: %w", removeErr)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("checking PHP Shield event socket: %w", err)
	}

	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on PHP Shield event socket: %w", err)
	}
	if chmodErr := os.Chmod(path, phpEventSocketMode); chmodErr != nil {
		_ = conn.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("setting PHP Shield event socket mode: %w", chmodErr)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = conn.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("checking PHP Shield event socket after bind: %w", err)
	}
	return &phpEventUnixgramListener{UnixConn: conn, path: path, info: info}, nil
}

func processPHPShieldEventPacket(data []byte, archivePath string, cfg *config.Config, alertCh chan<- alert.Finding) (bool, error) {
	if len(data) == 0 || len(data) > phpEventMaxBytes {
		return false, nil
	}
	line := strings.TrimSuffix(string(data), "\n")
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return false, nil
	}
	findings := parsePHPShieldLogLine(line, cfg)
	if len(findings) == 0 {
		return false, nil
	}
	_, archiveErr := appendPHPShieldEventArchive(archivePath, line)
	for _, finding := range findings {
		if finding.Timestamp.IsZero() {
			finding.Timestamp = time.Now()
		}
		select {
		case alertCh <- finding:
		default:
			fmt.Fprintln(os.Stderr, "Warning: alert channel full, dropping PHP Shield finding")
		}
	}
	return true, archiveErr
}

func appendPHPShieldEventArchive(path, line string) (archived bool, retErr error) {
	// #nosec G304 G302 -- fixed root-owned archive path; O_NOFOLLOW rejects
	// symlink replacement and mode 0600 keeps tenants from reading/truncating it.
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returned a non-negative fd
	if f == nil {
		_ = unix.Close(fd)
		return false, fmt.Errorf("opening PHP Shield event archive")
	}
	defer func() {
		if err := f.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return false, fmt.Errorf("PHP Shield event archive is not a single-link regular file")
	}
	if err := f.Chmod(0o600); err != nil {
		return false, err
	}
	record := line + "\n"
	if stat.Size > phpEventArchiveMaxBytes-int64(len(record)) {
		return false, errPHPEventArchiveFull
	}
	if _, err := f.WriteString(record); err != nil {
		return false, err
	}
	return true, nil
}

func waitPHPShieldEventRetry(stopCh <-chan struct{}) bool {
	timer := time.NewTimer(phpEventRetryInterval)
	defer timer.Stop()
	select {
	case <-stopCh:
		return false
	case <-timer.C:
		return true
	}
}

func (d *Daemon) watchPHPShieldEvents() {
	defer d.wg.Done()
	buffer := make([]byte, phpEventMaxBytes+1)
	lastError := ""
	var listener phpEventPacketListener
	defer func() {
		if listener != nil {
			_ = listener.Close()
		}
	}()
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}
		if listener == nil {
			var err error
			listener, err = phpShieldEventListener(phpEventsSocketPath)
			if err != nil {
				d.MarkWatcher("php_shield", false)
				if err.Error() != lastError {
					csmlog.Warn("PHP Shield event socket unavailable", "path", phpEventsSocketPath, "err", err)
					lastError = err.Error()
				}
				if !waitPHPShieldEventRetry(d.stopCh) {
					return
				}
				continue
			}
			lastError = ""
			d.MarkWatcher("php_shield", true)
		}

		if err := listener.SetReadDeadline(time.Now().Add(phpEventRetryInterval)); err != nil {
			_ = listener.Close()
			listener = nil
			d.MarkWatcher("php_shield", false)
			if err.Error() != lastError {
				csmlog.Warn("PHP Shield event socket deadline failed", "path", phpEventsSocketPath, "err", err)
				lastError = err.Error()
			}
			if !waitPHPShieldEventRetry(d.stopCh) {
				return
			}
			continue
		}
		n, err := listener.Read(buffer)
		if err == nil {
			processed, processErr := processPHPShieldEventPacket(buffer[:n], phpEventsLogPath, d.cfg, d.alertCh)
			if processErr != nil {
				if processErr.Error() != lastError {
					csmlog.Warn("PHP Shield event archive unavailable", "path", phpEventsLogPath, "err", processErr)
					lastError = processErr.Error()
				}
			} else if processed {
				lastError = ""
			}
			continue
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			continue
		}
		_ = listener.Close()
		listener = nil
		d.MarkWatcher("php_shield", false)
		if err.Error() != lastError {
			csmlog.Warn("PHP Shield event socket read failed", "path", phpEventsSocketPath, "err", err)
			lastError = err.Error()
		}
		if !waitPHPShieldEventRetry(d.stopCh) {
			return
		}
	}
}

// parsePHPShieldLogLine wraps parsePHPShieldLine for the log watcher handler signature.
func parsePHPShieldLogLine(line string, _ *config.Config) []alert.Finding { //nolint:unparam
	f := parsePHPShieldLine(line)
	if f == nil {
		return nil
	}
	return []alert.Finding{*f}
}

// parsePHPShieldLine parses a line from the PHP shield event log and returns
// a finding if it represents a security event.
//
// Format: [2026-03-25 10:00:00] EVENT_TYPE ip=X script=Y uri=Z ua=A details=B
func parsePHPShieldLine(line string) *alert.Finding {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "[") {
		return nil
	}

	// Extract event type (first word after the timestamp bracket)
	closeBracket := strings.Index(line, "]")
	if closeBracket < 0 || closeBracket+2 >= len(line) {
		return nil
	}
	rest := strings.TrimSpace(line[closeBracket+1:])
	fields := strings.SplitN(rest, " ", 2)
	if len(fields) < 1 {
		return nil
	}
	eventType := fields[0]

	// Extract key=value pairs. The URI and user agent are what identify the
	// request: "/alfacgiapi/perl.alfa" from a "Mozlila" agent names the scanner,
	// where the bare parameter name does not. Both were parsed and discarded.
	var ip, script, uri, ua, details string
	if len(fields) > 1 {
		kvPart := fields[1]
		for _, kv := range splitKV(kvPart) {
			switch kv[0] {
			case "ip":
				ip = kv[1]
			case "script":
				script = kv[1]
			case "uri":
				uri = kv[1]
			case "ua":
				ua = kv[1]
			case "details":
				details = kv[1]
			}
		}
	}
	context := phpShieldDetails(ip, uri, ua, details)

	switch eventType {
	case "BLOCK_PATH":
		return &alert.Finding{
			Severity: alert.Critical,
			Check:    "php_shield_block",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield blocked execution from dangerous path: %s", script),
			Details:  context,
		}
	case "WEBSHELL_PARAM":
		// Observation, not a denial: for a document-root script the Shield never
		// reaches its deny branch, so nothing was blocked. Every public site
		// receives these daily, and rating them Critical buries the real blocks.
		return &alert.Finding{
			Severity: alert.Warning,
			Check:    "php_shield_webshell",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield observed a webshell command parameter: %s", script),
			Details:  context,
		}
	case "BLOCK_WEBSHELL":
		return &alert.Finding{
			Severity: alert.Critical,
			Check:    "php_shield_webshell",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield blocked a webshell signature: %s", script),
			Details:  context,
		}
	case "EVAL_FATAL":
		return &alert.Finding{
			Severity: alert.High,
			Check:    "php_shield_eval",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield detected eval() chain failure: %s", script),
			Details:  context,
		}
	}

	return nil
}

// phpShieldDetails renders the context an operator needs to judge a Shield
// event: who sent it, what they asked for, and what they claimed to be. Empty
// fields are omitted rather than printed as blanks.
func phpShieldDetails(ip, uri, ua, details string) string {
	var b strings.Builder
	for _, field := range [][2]string{
		{"IP", ip},
		{"URI", uri},
		{"User-Agent", ua},
	} {
		if field[1] == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s: %s", field[0], field[1])
	}
	if details != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(details)
	}
	return b.String()
}

// splitKV splits "key1=val1 key2=val2" respecting values with spaces.
func splitKV(s string) [][2]string {
	var result [][2]string
	keys := []string{"ip=", "script=", "uri=", "ua=", "details="}

	for i, key := range keys {
		idx := strings.Index(s, key)
		if idx < 0 {
			continue
		}
		valStart := idx + len(key)

		// Value ends at the next key or end of string
		valEnd := len(s)
		for _, nextKey := range keys[i+1:] {
			nextIdx := strings.Index(s[valStart:], " "+nextKey)
			if nextIdx >= 0 {
				valEnd = valStart + nextIdx
				break
			}
		}

		val := strings.TrimSpace(s[valStart:valEnd])
		keyName := strings.TrimSuffix(key, "=")
		result = append(result, [2]string{keyName, val})
	}
	return result
}
