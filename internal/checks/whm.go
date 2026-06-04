package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// CheckWHMAccess parses the cPanel access log for WHM (port 2087) logins
// and password change API calls from non-infra IPs.
// Only reads the tail of the log - lightweight.
func CheckWHMAccess(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/usr/local/cpanel/logs/access_log", 200)

	for _, line := range lines {
		// Only check WHM (port 2087) entries. Match the service-port token
		// (cPanel logs it as ":2087"), not a bare "2087" anywhere in the
		// line -- a byte count or timestamp containing 2087 would otherwise
		// false-positive a request on a different port as a WHM action.
		if !strings.Contains(line, ":2087") {
			continue
		}

		// Extract IP (first field)
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		ip := fields[0]

		// Skip infra IPs
		if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
			continue
		}

		// Check for password change actions
		passwordActions := []string{
			"passwd", "change_root_password", "chpasswd",
			"force_password_change", "resetpass",
		}
		lineLower := strings.ToLower(line)
		for _, action := range passwordActions {
			if strings.Contains(lineLower, action) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "whm_password_change",
					Message:  fmt.Sprintf("WHM password change from non-infra IP: %s", ip),
					Details:  truncateString(line, 200),
				})
				break
			}
		}

		// Check for account management from unknown IPs
		accountActions := []string{
			"createacct", "killacct", "suspendacct", "unsuspendacct",
		}
		for _, action := range accountActions {
			if strings.Contains(lineLower, action) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "whm_account_action",
					Message:  fmt.Sprintf("WHM account action from non-infra IP: %s", ip),
					Details:  truncateString(line, 200),
				})
				break
			}
		}
	}

	return findings
}

// CheckSSHLogins parses /var/log/secure for SSH logins from non-infra IPs.
func CheckSSHLogins(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/var/log/secure", 100)

	for _, line := range lines {
		if !strings.Contains(line, "Accepted") {
			continue
		}

		// Extract IP - format: "Accepted publickey for root from 1.2.3.4 port 12345"
		parts := strings.Fields(line)
		ipIdx := -1
		for i, p := range parts {
			if p == "from" && i+1 < len(parts) {
				ipIdx = i + 1
				break
			}
		}
		if ipIdx < 0 || ipIdx >= len(parts) {
			continue
		}
		ip := parts[ipIdx]

		if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
			continue
		}

		// Extract user
		user := "unknown"
		for i, p := range parts {
			if p == "for" && i+1 < len(parts) {
				user = parts[i+1]
				break
			}
		}

		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "ssh_login_unknown_ip",
			Message:  fmt.Sprintf("SSH login from non-infra IP: %s (user: %s)", ip, user),
			Details:  truncateString(line, 200),
		})
	}

	return findings
}

// tailFile reads the last N lines of a file efficiently.
func tailFile(path string, maxLines int) []string {
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

	// For small files, just read all
	if info.Size() < 1024*1024 {
		return readAllLines(f, maxLines)
	}

	data, err := readTailWindow(f, info.Size(), maxLines, maxTailWindowBytes)
	if err != nil {
		return readAllLines(f, maxLines)
	}

	return readAllLines(bytes.NewReader(data), maxLines)
}

func readTailWindow(f *os.File, size int64, maxLines int, maxBytes int64) ([]byte, error) {
	const chunkSize int64 = 256 * 1024

	if maxBytes <= 0 {
		return nil, nil
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
			return nil, err
		}
		chunk = chunk[:read]
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
			data = data[firstNewline+1:]
		} else {
			return nil, nil
		}
	}
	return data, nil
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
	if maxLines <= 0 {
		return nil
	}

	br := bufio.NewReaderSize(r, 64*1024)
	var lines []string
	for {
		line, truncated, err := readBoundedLineLog(br, maxLogLineBytes)
		if len(line) > 0 && !truncated {
			lines = append(lines, trimLogLineEnding(line))
		}
		if err != nil {
			break
		}
	}

	if len(lines) > maxLines {
		return lines[len(lines)-maxLines:]
	}
	return lines
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
