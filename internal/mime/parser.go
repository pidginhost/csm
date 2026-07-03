package mime

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// ExtractedPart represents a single extracted attachment.
type ExtractedPart struct {
	Filename    string
	ContentType string
	Size        int64
	TempPath    string
	Nested      bool
	ArchiveName string
}

// ExtractionResult holds all extracted parts and envelope metadata.
type ExtractionResult struct {
	Parts         []ExtractedPart
	Partial       bool
	PartialReason string
	Direction     string
	From          string
	To            []string
	Subject       string
}

// Limits controls resource bounds during extraction.
type Limits struct {
	MaxAttachmentSize int64
	MaxArchiveDepth   int
	MaxArchiveFiles   int
	MaxExtractionSize int64
	// TempDir is the directory CreateTemp uses for extracted parts.
	// Empty falls back to os.TempDir() (/tmp on Linux). Operators
	// should set this to a daemon-owned 0700 path so extracted email
	// attachments are not staged in a world-writable directory where
	// another local uid can race the scanner via symlink swaps.
	TempDir string
}

// DefaultLimits returns the default extraction limits.
func DefaultLimits() Limits {
	return Limits{
		MaxAttachmentSize: 25 * 1024 * 1024,
		MaxArchiveDepth:   1,
		MaxArchiveFiles:   50,
		MaxExtractionSize: 100 * 1024 * 1024,
	}
}

// ParseSpoolMessage parses an Exim spool message (-H and -D files) and
// extracts attachments to a temp directory. Caller must remove the temp
// files in result.Parts[*].TempPath when done.
func ParseSpoolMessage(headerPath, bodyPath string, limits Limits) (*ExtractionResult, error) {
	envelope, hdrs, err := parseEximHeader(headerPath)
	if err != nil {
		return nil, fmt.Errorf("parsing header file: %w", err)
	}

	result := &ExtractionResult{
		From:    envelope.from,
		To:      envelope.to,
		Subject: envelope.subject,
	}

	// Determine direction from Received headers
	result.Direction = detectDirection(hdrs)

	maxBodyBytes := bodyReadLimit(limits)
	bodyData, partial, err := readBodyFileLimited(bodyPath, maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("reading body file: %w", err)
	}
	if partial {
		result.Partial = true
		result.PartialReason = "message body exceeds parser memory budget"
		return result, nil
	}

	// Exim -D files open with a "<message-id>-D" marker line; strip it before
	// any body decode so single-part base64/QP payloads are not corrupted by
	// the marker bytes.
	bodyData = stripSpoolBodyMarker(bodyData, bodyPath)

	ct := hdrs.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}

	mediaType, params, parseErr := mime.ParseMediaType(ct)
	if parseErr != nil {
		// Unparseable content type - treat as plain text, no attachments
		return result, nil //nolint:nilerr // fail-open by design
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return result, nil
		}
		var totalSize int64
		extractErr := extractMultipart(bytes.NewReader(bodyData), boundary, limits, result, &totalSize, 0)
		if extractErr != nil {
			return result, nil //nolint:nilerr // fail-open by design: return what we extracted so far
		}
	} else if !strings.HasPrefix(mediaType, "text/") {
		// Single-part non-text message (e.g. application/octet-stream,
		// application/pdf, image/*). These are attachment-like payloads
		// that must be scanned even without a multipart wrapper.
		cte := strings.ToLower(hdrs.Get("Content-Transfer-Encoding"))
		decoded, truncated := decodeSinglePart(bodyData, cte, limits.MaxAttachmentSize+1)

		if !truncated && int64(len(decoded)) <= limits.MaxAttachmentSize {
			tmpFile, tmpErr := os.CreateTemp(limits.TempDir, "csm-emailav-single-*")
			if tmpErr == nil {
				n, writeErr := tmpFile.Write(decoded)
				closeErr := tmpFile.Close()
				if writeErr != nil || closeErr != nil || n != len(decoded) {
					os.Remove(tmpFile.Name())
					markPartial(result, "could not stage single-part attachment for scanning")
				} else {
					filename := params["name"]
					if filename == "" {
						filename = "attachment"
					}
					filename = sanitizeAttachmentName(filename)
					result.Parts = append(result.Parts, ExtractedPart{
						Filename:    filename,
						ContentType: mediaType,
						Size:        int64(len(decoded)),
						TempPath:    tmpFile.Name(),
					})
				}
			} else {
				markPartial(result, "could not stage single-part attachment for scanning")
			}
		} else {
			result.Partial = true
			result.PartialReason = "single-part attachment exceeds max size"
		}
	}
	// text/* bodies are not attachments - skip

	return result, nil
}

func bodyReadLimit(limits Limits) int64 {
	limit := limits.MaxExtractionSize
	if limit < limits.MaxAttachmentSize*2 {
		limit = limits.MaxAttachmentSize * 2
	}
	if limit <= 0 {
		limit = DefaultLimits().MaxExtractionSize
	}
	return limit
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	// #nosec G304 -- path is mail queue file path from scanner walk.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("message body exceeds parser memory budget")
	}
	return data, nil
}

// readBodyFileLimited opens the spool body file once and reads up to
// limit+1 bytes. Returns (data, partial=true, nil) when the file
// exceeds the limit so the caller can mark the result as partial.
// Folding the size check into the same file descriptor closes the
// TOCTOU window: previously the Stat-then-Open sequence let an
// attacker swap the file for a larger one between the two syscalls
// and bypass the limit.
func readBodyFileLimited(path string, limit int64) ([]byte, bool, error) {
	// #nosec G304 -- path is mail queue file path from scanner walk.
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, true, nil
	}
	return data, false, nil
}

func markPartial(result *ExtractionResult, reason string) {
	result.Partial = true
	if result.PartialReason == "" {
		result.PartialReason = reason
	}
}

func decodeSinglePart(bodyData []byte, cte string, limit int64) ([]byte, bool) {
	var reader io.Reader
	switch cte {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, bytes.NewReader(bodyData))
	case "quoted-printable":
		reader = quotedprintable.NewReader(bytes.NewReader(bodyData))
	default:
		if int64(len(bodyData)) > limit {
			return bodyData[:limit], true
		}
		return bodyData, false
	}

	decoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, true
	}
	if int64(len(decoded)) > limit {
		return decoded[:limit], true
	}
	return decoded, false
}

type envelope struct {
	from    string
	to      []string
	subject string
}

// parseEximHeader reads an Exim -H file and extracts envelope info and headers.
func parseEximHeader(path string) (*envelope, textproto.MIMEHeader, error) {
	// #nosec G304 -- path is Exim -H file path from mail queue scanner walk.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	env, hdrs := parseEximHeaderData(data)
	return env, hdrs, nil
}

// parseEximHeaderData parses the bytes of an Exim -H spool file into the
// envelope fields and the RFC 5322 header set. The -H format is:
//
//	line 1:  <message-id>-H
//	line 2:  <envelope-user> <uid> <gid>
//	         <envelope metadata / options / recipient block>
//	         <blank line>
//	         <RFC headers, each prefixed "<byte-count><flag> ">
//
// Each header line carries a decimal byte count and a single flag character
// ('F' From, 'T' To, 'P' Received, 'R' Reply-To, '*' deleted, space for the
// rest); folded continuations start with whitespace. Real cPanel-Exim writes
// this format, so parsing bare "From:" lines (as an earlier version did) never
// matched and left every field empty. Parsing is fail-open: unparseable input
// yields empty headers, never an error.
func parseEximHeaderData(data []byte) (*envelope, textproto.MIMEHeader) {
	env := &envelope{}
	hdrs := make(textproto.MIMEHeader)

	reconstructed := reconstructEximHeaderBytes(data)
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(reconstructed)))
	// A malformed trailing line makes ReadMIMEHeader return an error alongside
	// the headers it parsed before the fault; keep those and fail open.
	parsed, _ := tp.ReadMIMEHeader()
	if len(parsed) == 0 {
		return env, hdrs // fail-open: no recognizable headers
	}

	hdrs = parsed
	env.from = hdrs.Get("From")
	env.subject = hdrs.Get("Subject")
	if to := hdrs.Get("To"); to != "" {
		for _, addr := range strings.Split(to, ",") {
			env.to = append(env.to, strings.TrimSpace(addr))
		}
	}
	return env, hdrs
}

// reconstructEximHeaderBytes rebuilds a plain RFC 5322 header block from an
// Exim -H file by dropping the two leading metadata lines and the envelope
// preamble, then stripping the "<byte-count><flag> " prefix from each header
// line. Deleted headers (flag '*') and their folds are omitted; folded
// continuation lines are preserved verbatim so textproto can rejoin them.
func reconstructEximHeaderBytes(data []byte) []byte {
	sc := bufio.NewScanner(bytes.NewReader(data))
	// A single header line (DKIM/ARC signatures, long base64) can be large but
	// is bounded by the -H file already in memory.
	sc.Buffer(make([]byte, 0, 8192), len(data)+64)

	var out bytes.Buffer
	lineNum := 0
	inHeaders := false
	skippingDeleted := false
	haveLiveHeader := false
	for sc.Scan() {
		line := sc.Text()
		lineNum++
		if lineNum <= 2 {
			continue // message-id marker, then envelope-user line
		}
		if !inHeaders {
			if line == "" {
				inHeaders = true
			}
			continue // envelope metadata / recipient block
		}
		// Folded continuation: RFC 5322 lines starting with WSP belong to the
		// preceding header.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if !skippingDeleted && haveLiveHeader {
				out.WriteString(line)
				out.WriteString("\r\n")
			}
			continue
		}
		rest, flag, ok := stripEximPrefix(line)
		if !ok {
			skippingDeleted = false
			haveLiveHeader = false
			continue // not a recognizable header start
		}
		if flag == '*' {
			skippingDeleted = true // deleted header: skip it and its folds
			haveLiveHeader = false
			continue
		}
		if !strings.Contains(rest, ":") {
			skippingDeleted = false
			haveLiveHeader = false
			continue
		}
		skippingDeleted = false
		haveLiveHeader = true
		out.WriteString(rest)
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n") // terminate the header block for ReadMIMEHeader
	return out.Bytes()
}

// stripEximPrefix removes the leading "<byte-count><flag> " from an Exim -H
// header line and returns the remaining "Name: value" text plus the flag byte.
// ok is false when the line does not carry a valid prefix.
func stripEximPrefix(line string) (rest string, flag byte, ok bool) {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 0 || i+1 >= len(line) {
		return "", 0, false
	}
	flag = line[i]
	if !isEximFlagByte(flag) || line[i+1] != ' ' {
		return "", 0, false
	}
	return line[i+2:], flag, true
}

func isEximFlagByte(b byte) bool {
	return b == ' ' || b == '*' ||
		(b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// stripSpoolBodyMarker removes the first line of an Exim -D body file when it
// is the "<message-id>-D" marker Exim always writes there. The marker equals
// the -D file's base name, so matching on that is exact: bodies that lack a
// marker (or callers that pass a raw body) are left untouched. Without this,
// single-part base64/QP payloads decode the marker bytes as content and fail.
func stripSpoolBodyMarker(bodyData []byte, bodyPath string) []byte {
	marker := filepath.Base(bodyPath)
	nl := bytes.IndexByte(bodyData, '\n')
	var first []byte
	if nl < 0 {
		first = bodyData
	} else {
		first = bodyData[:nl]
	}
	if string(bytes.TrimRight(first, "\r")) != marker {
		return bodyData
	}
	if nl < 0 {
		return nil
	}
	return bodyData[nl+1:]
}

// detectDirection guesses inbound vs outbound from Received headers.
func detectDirection(hdrs textproto.MIMEHeader) string {
	received := hdrs.Values("Received")
	if len(received) == 0 {
		return "outbound" // locally generated, no Received headers
	}
	// If the first (topmost) Received header contains "authenticated" it's outbound
	first := strings.ToLower(received[0])
	if strings.Contains(first, "(authenticated") || strings.Contains(first, "auth=") {
		return "outbound"
	}
	return "inbound"
}

// maxMIMENestingDepth caps multipart-in-multipart recursion. Legitimate
// mail rarely nests beyond mixed > alternative > related; a crafted message
// can nest arbitrarily and would otherwise consume one stack frame per
// wrapper while hiding attachments below any scanner's patience.
const maxMIMENestingDepth = 16

// extractMultipart recursively walks MIME parts, extracting attachments.
// depth counts archive nesting (zip-in-zip), not MIME nesting: an archive
// attached five multipart levels down is still archive depth 0.
func extractMultipart(r io.Reader, boundary string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) error {
	return extractMultipartNested(r, boundary, limits, result, totalSize, depth, 0)
}

func extractMultipartNested(r io.Reader, boundary string, limits Limits, result *ExtractionResult, totalSize *int64, depth, mimeDepth int) error {
	if mimeDepth >= maxMIMENestingDepth {
		result.Partial = true
		if result.PartialReason == "" {
			result.PartialReason = "MIME nesting exceeds depth limit"
		}
		return nil
	}
	mr := multipart.NewReader(r, boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		ct := part.Header.Get("Content-Type")
		if ct == "" {
			ct = "text/plain"
		}
		mediaType, params, _ := mime.ParseMediaType(ct)

		// Recurse into nested multipart
		if strings.HasPrefix(mediaType, "multipart/") {
			if b := params["boundary"]; b != "" {
				if nestedErr := extractMultipartNested(part, b, limits, result, totalSize, depth, mimeDepth+1); nestedErr != nil {
					return nestedErr
				}
			}
			continue
		}

		// Skip inline text bodies - only extract attachments
		disp := part.Header.Get("Content-Disposition")
		filename := part.FileName()
		if filename == "" {
			// Try Content-Disposition filename param
			if disp != "" {
				_, dparams, _ := mime.ParseMediaType(disp)
				filename = dparams["filename"]
			}
		}
		if filename == "" {
			// No filename and text/* content - this is a body part, skip
			if strings.HasPrefix(mediaType, "text/") {
				continue
			}
			// Non-text without filename - use generic name
			filename = "unnamed_attachment"
		}
		rawFilename := filename
		filename = sanitizeAttachmentName(filename)

		// Decode the part body based on Content-Transfer-Encoding
		cte := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
		var bodyReader io.Reader = part
		switch cte {
		case "base64":
			bodyReader = base64.NewDecoder(base64.StdEncoding, part)
		case "quoted-printable":
			bodyReader = quotedprintable.NewReader(part)
		}

		// Write to temp file with size limit
		tmpFile, err := os.CreateTemp(limits.TempDir, "csm-emailav-*")
		if err != nil {
			markPartial(result, "could not stage attachment for scanning")
			return fmt.Errorf("creating temp file: %w", err)
		}

		limited := io.LimitReader(bodyReader, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		closeErr := tmpFile.Close()
		if err != nil || closeErr != nil {
			os.Remove(tmpFile.Name())
			markPartial(result, "could not stage attachment for scanning")
			continue // fail-open: skip this part
		}

		if n > limits.MaxAttachmentSize {
			os.Remove(tmpFile.Name())
			result.Partial = true
			result.PartialReason = fmt.Sprintf("attachment %q exceeds max size %d", filename, limits.MaxAttachmentSize)
			continue
		}

		*totalSize += n
		if *totalSize > limits.MaxExtractionSize {
			os.Remove(tmpFile.Name())
			result.Partial = true
			result.PartialReason = fmt.Sprintf("total extraction size exceeds %d bytes", limits.MaxExtractionSize)
			return nil // stop extracting
		}

		result.Parts = append(result.Parts, ExtractedPart{
			Filename:    filename,
			ContentType: mediaType,
			Size:        n,
			TempPath:    tmpFile.Name(),
		})

		// Attempt archive extraction
		if depth < limits.MaxArchiveDepth {
			switch archiveKindForAttachmentName(rawFilename, filename) {
			case "zip":
				extractZIP(tmpFile.Name(), filename, limits, result, totalSize, depth+1)
			case "tar.gz":
				extractTarGz(tmpFile.Name(), filename, limits, result, totalSize, depth+1)
			}
		}
	}
}

func extractZIP(zipPath, archiveName string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) {
	// #nosec G304 -- zipPath is CreateTemp-produced path from the caller.
	f, err := os.Open(zipPath)
	if err != nil {
		return // fail-open: skip corrupt archives
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return
	}

	extracted := 0
	for _, zf := range zr.File {
		if extracted >= limits.MaxArchiveFiles {
			result.Partial = true
			result.PartialReason = fmt.Sprintf("archive %q exceeds max files %d", archiveName, limits.MaxArchiveFiles)
			return
		}
		if zf.FileInfo().IsDir() {
			continue
		}

		safeName := sanitizeAttachmentName(zf.Name)

		rc, err := zf.Open()
		if err != nil {
			continue
		}

		tmpFile, err := os.CreateTemp(limits.TempDir, "csm-emailav-zip-*")
		if err != nil {
			rc.Close()
			markPartial(result, fmt.Sprintf("could not stage file %q in archive for scanning", safeName))
			continue
		}

		limited := io.LimitReader(rc, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		closeErr := tmpFile.Close()
		rc.Close()

		if err != nil || closeErr != nil || n > limits.MaxAttachmentSize {
			os.Remove(tmpFile.Name())
			if n > limits.MaxAttachmentSize {
				result.Partial = true
				result.PartialReason = fmt.Sprintf("file %q in archive exceeds max size", safeName)
			} else {
				markPartial(result, fmt.Sprintf("could not stage file %q in archive for scanning", safeName))
			}
			continue
		}

		*totalSize += n
		if *totalSize > limits.MaxExtractionSize {
			os.Remove(tmpFile.Name())
			result.Partial = true
			result.PartialReason = fmt.Sprintf("total extraction size exceeds %d bytes", limits.MaxExtractionSize)
			return
		}

		result.Parts = append(result.Parts, ExtractedPart{
			Filename:    safeName,
			ContentType: "application/octet-stream",
			Size:        n,
			TempPath:    tmpFile.Name(),
			Nested:      true,
			ArchiveName: archiveName,
		})
		extracted++
	}
}

func extractTarGz(tgzPath, archiveName string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) {
	// #nosec G304 -- tgzPath is CreateTemp-produced path from the caller.
	f, err := os.Open(tgzPath)
	if err != nil {
		return
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	extracted := 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			return // EOF or error - done
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if extracted >= limits.MaxArchiveFiles {
			result.Partial = true
			result.PartialReason = fmt.Sprintf("archive %q exceeds max files %d", archiveName, limits.MaxArchiveFiles)
			return
		}
		safeName := sanitizeAttachmentName(hdr.Name)

		tmpFile, err := os.CreateTemp(limits.TempDir, "csm-emailav-tgz-*")
		if err != nil {
			markPartial(result, fmt.Sprintf("could not stage file %q in archive for scanning", safeName))
			continue
		}

		limited := io.LimitReader(tr, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		closeErr := tmpFile.Close()

		if err != nil || closeErr != nil || n > limits.MaxAttachmentSize {
			os.Remove(tmpFile.Name())
			if n > limits.MaxAttachmentSize {
				result.Partial = true
				result.PartialReason = fmt.Sprintf("file %q in archive exceeds max size", safeName)
			} else {
				markPartial(result, fmt.Sprintf("could not stage file %q in archive for scanning", safeName))
			}
			continue
		}

		*totalSize += n
		if *totalSize > limits.MaxExtractionSize {
			os.Remove(tmpFile.Name())
			result.Partial = true
			result.PartialReason = fmt.Sprintf("total extraction size exceeds %d bytes", limits.MaxExtractionSize)
			return
		}

		result.Parts = append(result.Parts, ExtractedPart{
			Filename:    safeName,
			ContentType: "application/octet-stream",
			Size:        n,
			TempPath:    tmpFile.Name(),
			Nested:      true,
			ArchiveName: archiveName,
		})
		extracted++
	}
}

// sanitizeAttachmentName trims an attachment or archive-entry name to
// its base name and truncates at control characters before the name
// reaches logs, alerts, or JSON responses.
func sanitizeAttachmentName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	// Truncate at the first control character so a crafted entry
	// like "good.txt\nFAKE-LOG-LINE" cannot smuggle a forged log
	// record past the visible filename.
	if i := strings.IndexFunc(name, unicode.IsControl); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	switch name {
	case "", ".", "..", "/":
		return "_unnamed_"
	}
	return name
}

func archiveKindForAttachmentName(rawName, safeName string) string {
	for _, name := range []string{safeName, archiveDetectionName(rawName)} {
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".zip"):
			return "zip"
		case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
			return "tar.gz"
		}
	}
	return ""
}

// archiveDetectionName removes controls instead of truncating so a
// filename like "payload\u0085.zip" still gets unpacked while the
// public filename remains log-safe.
func archiveDetectionName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	return strings.TrimSpace(name)
}
