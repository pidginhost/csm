package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/phpshield"
	"golang.org/x/sys/unix"
)

const (
	phpEventMaxBytes        = 64 * 1024
	phpEventArchiveMaxBytes = 10 * 1024 * 1024
	phpEventSocketMode      = 0o222
	// phpShieldURIMaxBytes is the length the Shield cuts REQUEST_URI to before
	// sending it.
	phpShieldURIMaxBytes = 200
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

func processPHPShieldEventPacket(data []byte, archivePath string, _ *config.Config, alertCh chan<- alert.Finding) (bool, error) {
	if len(data) == 0 || len(data) > phpEventMaxBytes {
		return false, nil
	}
	line := strings.TrimSuffix(string(data), "\n")
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return false, nil
	}
	finding, quiet := parsePHPShieldEventLine(line)
	if finding == nil {
		return false, nil
	}
	_, archiveErr := appendPHPShieldEventArchive(archivePath, line)
	if !quiet {
		if finding.Timestamp.IsZero() {
			finding.Timestamp = time.Now()
		}
		if !alert.TryEnqueue(alertCh, *finding) {
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
// Format: [2026-03-25 10:00:00] EVENT_TYPE sha256=H ip=X script=Y uri=Z ua=A details=B
// Older Shields omit sha256; those observations cannot be quieted.
func parsePHPShieldLine(line string) *alert.Finding {
	finding, quiet := parsePHPShieldEventLine(line)
	if quiet {
		return nil
	}
	return finding
}

// Keep the observation even when its alert is quiet: a route mismatch does
// not prove the requested file was absent, or that downstream CMS code is safe.
func parsePHPShieldEventLine(line string) (*alert.Finding, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "[") {
		return nil, false
	}

	// Extract event type (first word after the timestamp bracket)
	closeBracket := strings.Index(line, "]")
	if closeBracket < 0 || closeBracket+2 >= len(line) {
		return nil, false
	}
	rest := strings.TrimSpace(line[closeBracket+1:])
	fields := strings.SplitN(rest, " ", 2)
	if len(fields) < 1 {
		return nil, false
	}
	eventType := fields[0]

	// Extract key=value pairs. The URI and user agent are what identify the
	// request: "/alfacgiapi/perl.alfa" from a "Mozlila" agent names the scanner,
	// where the bare parameter name does not. Both were parsed and discarded.
	var digest, ip, script, uri, ua, details string
	if len(fields) > 1 {
		kvPart := fields[1]
		// Only the producer's first field is content evidence. A URI or user
		// agent containing sha256= must not forge proof for a legacy event.
		if first, rest, ok := strings.Cut(kvPart, " "); ok && strings.HasPrefix(first, "sha256=") {
			digest = strings.TrimPrefix(first, "sha256=")
			kvPart = rest
		}
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
		}, false
	case "WEBSHELL_PARAM":
		// Observation, not a denial: for a document-root script the Shield never
		// reaches its deny branch, so nothing was blocked. Every public site
		// receives these daily, and rating them Critical buries the real blocks.
		// A rewrite can reach a real shell, even one called index.php. Use the
		// scanner's verified content cache and PHP's event-time fingerprint;
		// reopening the path here could inspect a replacement file instead.
		quiet := !phpShieldRequestReachedScript(script, uri) && checks.IsVerifiedCMSHash(digest)
		return &alert.Finding{
			Severity: alert.Warning,
			Check:    "php_shield_webshell",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield observed a webshell command parameter: %s", script),
			Details:  context,
		}, quiet
	case "BLOCK_WEBSHELL":
		// Not gated on the request path: the Shield blocks on the executing
		// script's own source, so a rewrite into a planted shell is still a
		// stopped webshell.
		return &alert.Finding{
			Severity: alert.Critical,
			Check:    "php_shield_webshell",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield blocked a webshell signature: %s", script),
			Details:  context,
		}, false
	case "EVAL_FATAL":
		return &alert.Finding{
			Severity: alert.High,
			Check:    "php_shield_eval",
			SourceIP: ip,
			FilePath: script,
			Message:  fmt.Sprintf("PHP Shield detected eval() chain failure: %s", script),
			Details:  context,
		}, false
	}

	return nil, false
}

// phpShieldRequestReachedScript reports whether the request URI names the
// script that executed, i.e. whether a command parameter was delivered to the
// script the client asked for.
//
// Scanners send cmd= to paths that do not exist. CMS rewrite rules (or a
// 404 handler) can answer with the site's front controller. This is only a
// routing hint: a rewritten request can also execute a real shell. The caller
// must establish content evidence before quieting an alert, and still archive
// the observation. The request names the executing script when a
// leading run of its path segments is a trailing part of the script path (this
// covers PATH_INFO such as /shell.php/extra), or when it names the directory
// holding the script, which is then served as its directory index. A request
// for "/" therefore still fires on the document-root index.php: the client did
// ask for that script, and a shell injected into index.php is reached exactly
// that way.
//
// A leading /~user segment is dropped as well, since that is how a userdir URL
// maps onto the account's document root.
//
// When the path cannot be judged (no URI, a form other than an origin or
// absolute path, a bad escape, or a path cut short by the Shield's truncation)
// the event is kept: silence has to be earned by a path that clearly names a
// different script.
func phpShieldRequestReachedScript(script, uri string) bool {
	if !path.IsAbs(script) || uri == "" || uri == "-" {
		return true
	}
	rawPath, _, hasQuery := strings.Cut(uri, "?")
	if !strings.HasPrefix(rawPath, "/") {
		parsed, err := url.ParseRequestURI(uri)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return true
		}
		if strings.HasPrefix(parsed.Host, "[") && net.ParseIP(parsed.Hostname()) == nil {
			return true
		}
		rawPath = parsed.EscapedPath()
		if rawPath == "" {
			rawPath = "/"
		}
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return true
	}
	for _, c := range decoded {
		if c <= ' ' || c == 0x7f || c == '\\' || c == '#' {
			return true
		}
	}
	requested := path.Clean(decoded)
	script = path.Clean(script)

	candidates := []string{requested}
	if first, rest, _ := strings.Cut(requested[1:], "/"); strings.HasPrefix(first, "~") {
		candidates = append(candidates, "/"+rest)
	}
	for _, candidate := range candidates {
		if phpShieldPathNamesScript(script, candidate) {
			return true
		}
	}
	return !hasQuery && len(uri) >= phpShieldURIMaxBytes
}

// phpShieldPathNamesScript applies the matching rule described on
// phpShieldRequestReachedScript to one cleaned request path.
func phpShieldPathNamesScript(script, requested string) bool {
	if strings.HasSuffix(path.Dir(script), strings.TrimSuffix(requested, "/")) {
		return true
	}
	for end := len(requested); end > 0; end = strings.LastIndexByte(requested[:end], '/') {
		if strings.HasSuffix(script, requested[:end]) {
			return true
		}
	}
	return false
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

		val := s[valStart:valEnd]
		// Preserve the URI byte count and ambiguous whitespace. Trimming a
		// truncated path can make it look complete enough to suppress an alert.
		if key != "uri=" {
			val = strings.TrimSpace(val)
		}
		keyName := strings.TrimSuffix(key, "=")
		result = append(result, [2]string{keyName, val})
	}
	return result
}
