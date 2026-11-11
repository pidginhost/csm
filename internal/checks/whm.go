package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// CheckWHMAccess parses the cPanel access log for WHM (port 2087) logins
// and password change API calls from non-infra IPs.
// Only reads the tail of the log - lightweight.
func CheckWHMAccess(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/usr/local/cpanel/logs/access_log", 200)

	for _, line := range lines {
		rec, ok := ParseCpanelAccessRecord(line)
		if !ok || rec.Port != "2087" {
			continue
		}
		ip := rec.IP

		if !rec.Proxied && (isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1") {
			continue
		}
		source, dedup := "non-infra IP: "+ip, ""
		if rec.Proxied {
			source, dedup = "a service subdomain (client address unverified)", "proxy:"+ip
		}

		// Check for password change actions
		passwordActions := []string{
			"passwd", "change_root_password", "chpasswd",
			"force_password_change", "resetpass",
		}
		// The request names the action; referer and user agent are client text.
		target := strings.ToLower(rec.Target)
		for _, action := range passwordActions {
			if strings.Contains(target, action) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "whm_password_change",
					Message:  fmt.Sprintf("WHM password change from %s", source),
					Details:  truncateString(line, 200),
					DedupKey: dedup,
				})
				break
			}
		}

		// Check for account management from unknown IPs
		accountActions := []string{
			"createacct", "killacct", "suspendacct", "unsuspendacct",
		}
		for _, action := range accountActions {
			if strings.Contains(target, action) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "whm_account_action",
					Message:  fmt.Sprintf("WHM account action from %s", source),
					Details:  truncateString(line, 200),
					DedupKey: dedup,
				})
				break
			}
		}
	}

	return findings
}

var authLogPath = func() string { return platform.Detect().AuthLogPath() }

// CheckSSHLogins parses the platform authentication log for SSH logins from
// non-infra IPs. With a state store it reads the log forward-only from where
// the previous cycle stopped; without one it falls back to a per-cycle tail.
func CheckSSHLogins(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if store != nil {
		return checkSSHLoginsFollow(cfg, store)
	}
	var findings []alert.Finding
	for _, line := range tailFile(authLogPath(), 100) {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		if f, ok := SSHAcceptedLoginFinding(line, cfg); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

// SSHAcceptedLoginFinding parses an sshd "Accepted <method> for <user> from
// <ip> port <n>" line and reports it unless the address is infrastructure.
// The daemon's realtime log watcher calls it so a login seen live and the same
// line re-read by CheckSSHLogins carry one identity; without that the state
// store sees two findings and the operator gets one login reported twice.
func SSHAcceptedLoginFinding(line string, cfg *config.Config) (alert.Finding, bool) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if !strings.Contains(line, "Accepted") {
		return alert.Finding{}, false
	}
	user, ip, ok := sshAcceptedRecord(strings.Fields(line))
	if !ok || isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
		return alert.Finding{}, false
	}
	// sshd authenticated the name, but only a hosting account is a tenant
	// or names an owner; root and service users are neither.
	tenant := HostingAccountForUser(user)
	f := alert.Finding{
		Severity: alert.Critical,
		Check:    "ssh_login_unknown_ip",
		DedupKey: loginRecordKey(line),
		Message:  fmt.Sprintf("SSH login from non-infra IP: %s (user: %s)", ip, user),
		Details:  truncateString(line, 200),
		SourceIP: ip,
		TenantID: tenant,
		// sshd's "from <ip> port" field is the transport peer.
		Attribution: admission.AttributionPeer,
	}
	if tenant != "" {
		f.Claims = []admission.Claim{{Kind: admission.ClaimAccount, Value: tenant}}
	}
	return f, true
}

// sshAcceptedRecord reads sshd's own success record, "Accepted <method> for
// <user> from <address> port <port>", right after the syslog header and the
// sshd program token. sshd also logs the login name a client offers, so these
// words count only at these positions; found anywhere else in a line they
// would let any client name any address.
func sshAcceptedRecord(fields []string) (user, ip string, ok bool) {
	program := -1
	switch {
	case len(fields) > 0 && isSSHDProgramToken(fields[0]):
		program = 0
	case len(fields) >= 2 && isSSHDProgramToken(fields[1]):
		// A host name without a timestamp.
		program = 1
	case len(fields) >= 5 && isSyslogTimestampPrefix(fields) && isSSHDProgramToken(fields[4]):
		program = 4
	case len(fields) >= 3 && isSSHDProgramToken(fields[2]):
		if _, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			program = 2
		}
	}
	if program < 0 {
		return "", "", false
	}
	m := fields[program+1:]
	if len(m) < 8 || m[0] != "Accepted" || m[2] != "for" || m[4] != "from" || m[6] != "port" ||
		m[7] == "" || strings.Trim(m[7], "0123456789") != "" {
		return "", "", false
	}
	if _, err := netip.ParseAddr(m[5]); err != nil {
		return "", "", false
	}
	return m[3], m[5], true
}

func isSSHDProgramToken(field string) bool {
	for _, name := range []string{"sshd", "sshd-session"} {
		if field == name+":" {
			return true
		}
		pid, ok := strings.CutPrefix(field, name+"[")
		if !ok {
			continue
		}
		pid, ok = strings.CutSuffix(pid, "]:")
		if ok && pid != "" && strings.Trim(pid, "0123456789") == "" {
			return true
		}
	}
	return false
}

// tailFile reads the last N lines of a file efficiently.
func tailFile(path string, maxLines int) []string {
	records := tailFileRecords(path, maxLines)
	if records == nil {
		return nil
	}
	lines := make([]string, len(records))
	for i, r := range records {
		lines[i] = r.text
	}
	return lines
}

// tailFileRecords reads the last N lines of a file with the offset each
// starts at and the file's stream, so a scan that re-reads the window names
// a record the way every reader of the file names it.
func tailFileRecords(path string, maxLines int) []syslogRecord {
	if maxLines <= 0 {
		return nil
	}

	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	// Seek to end and read backwards to find last N lines
	info, err := f.Stat()
	if err != nil {
		return nil
	}

	var records []syslogRecord
	if info.Size() < 1024*1024 {
		// For small files, just read all
		records = readAllRecords(f, 0, maxLines)
	} else if data, start, err := readTailWindow(f, info.Size(), maxLines, maxTailWindowBytes); err != nil {
		records = readAllRecords(f, 0, maxLines)
	} else {
		records = readAllRecords(bytes.NewReader(data), start, maxLines)
	}
	if id, ok := selfWriteIdentityFromFileInfo(info); ok {
		stream := alert.FileStream(id.Device, id.Inode)
		for i := range records {
			if !records[i].unterminated {
				records[i].stream = stream
			}
		}
	}
	return records
}

// readTailWindow returns the complete lines of the last maxBytes of the file
// and the offset they start at. A short read cannot be placed in the file,
// so it is an error.
func readTailWindow(f *os.File, size int64, maxLines int, maxBytes int64) ([]byte, int64, error) {
	const chunkSize int64 = 256 * 1024

	if maxBytes <= 0 {
		return nil, size, nil
	}

	offset := size
	newlines := 0
	var totalRead int64
	chunks := make([][]byte, 0, 4)
	for offset > 0 && newlines <= maxLines && totalRead < maxBytes {
		n := chunkSize
		if offset < n {
			n = offset
		}
		if remaining := maxBytes - totalRead; remaining < n {
			n = remaining
		}
		offset -= n

		chunk := make([]byte, n)
		read, err := f.ReadAt(chunk, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		if int64(read) != n {
			return nil, 0, io.ErrUnexpectedEOF
		}
		totalRead += int64(read)
		newlines += bytes.Count(chunk, []byte{'\n'})
		chunks = append(chunks, chunk)
	}

	total := 0
	for _, chunk := range chunks {
		total += len(chunk)
	}
	data := make([]byte, 0, total)
	for i := len(chunks) - 1; i >= 0; i-- {
		data = append(data, chunks[i]...)
	}
	if offset > 0 {
		if firstNewline := bytes.IndexByte(data, '\n'); firstNewline >= 0 {
			return data[firstNewline+1:], offset + int64(firstNewline) + 1, nil
		}
		return nil, size, nil
	}
	return data, offset, nil
}

const (
	// maxLogLineBytes is the per-line cap for periodic log tailers.
	// Oversized records are skipped after the reader advances past the
	// terminator so a crafted long line cannot poison the next record.
	maxLogLineBytes = 256 * 1024

	// maxTailWindowBytes bounds the backward seek window before line
	// parsing starts. Without this, a huge unterminated final record makes
	// the tail reader cache the whole file while looking for maxLines.
	maxTailWindowBytes int64 = 32 * 1024 * 1024
)

func readAllLines(r io.Reader, maxLines int) []string {
	records := readAllRecords(r, 0, maxLines)
	if records == nil {
		return nil
	}
	lines := make([]string, len(records))
	for i, rec := range records {
		lines[i] = rec.text
	}
	return lines
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readAllRecords reads the last maxLines lines of r, which starts at offset
// base of its file, with the offset each line starts at. Oversized lines are
// skipped; their bytes still count toward the next line's offset.
func readAllRecords(r io.Reader, base int64, maxLines int) []syslogRecord {
	if maxLines <= 0 {
		return nil
	}

	counter := &countingReader{r: r}
	br := bufio.NewReaderSize(counter, 64*1024)
	var records []syslogRecord
	for {
		start := base + counter.n - int64(br.Buffered())
		line, truncated, err := readBoundedLineLog(br, maxLogLineBytes)
		if len(line) > 0 && !truncated {
			records = append(records, syslogRecord{text: trimLogLineEnding(line), offset: start, unterminated: err != nil})
		}
		if err != nil {
			break
		}
	}

	if len(records) > maxLines {
		return records[len(records)-maxLines:]
	}
	return records
}

func trimLogLineEnding(line string) string {
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r")
}

// readBoundedLineLog reads up to and including the next '\n'. If the
// line exceeds maxBytes the returned data is truncated to maxBytes and
// the reader is advanced past the line's terminating newline so framing
// stays intact. Returns the same error semantics as
// bufio.Reader.ReadString.
func readBoundedLineLog(r *bufio.Reader, maxBytes int) (string, bool, error) {
	var b strings.Builder
	truncated := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			switch {
			case truncated:
				// drain remainder so the next line is well-framed
			case b.Len()+len(chunk) <= maxBytes:
				b.Write(chunk)
			default:
				if room := maxBytes - b.Len(); room > 0 {
					b.Write(chunk[:room])
				}
				truncated = true
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return b.String(), truncated, err
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
