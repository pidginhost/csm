package mime

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/zipdir"
)

// ExtractedPart represents a single extracted attachment.
type ExtractedPart struct {
	Filename    string
	ContentType string
	Size        int64
	// File holds the part's bytes. Its offset is unspecified: read it with
	// io.NewSectionReader(File, 0, Size).
	File *os.File
	// TempPath names the file when the default sink staged it on disk, and
	// is empty for any other sink.
	TempPath    string
	Nested      bool
	ArchiveName string
}

// ExtractionResult holds all extracted parts and envelope metadata.
type ExtractionResult struct {
	Parts            []ExtractedPart
	Partial          bool
	PartialReason    string
	EncryptedEntries []EncryptedArchiveEntry
	// Report names are bounded separately from extraction: encrypted members
	// beyond the reporting limit still must not cause delivery retries.
	EncryptedEntriesOmitted int
	Direction               string
	From                    string
	To                      []string
	Subject                 string
	// Shared across multipart recursion so ambiguous wrappers cannot branch
	// into exponentially many decoding passes.
	transferVariants int
}

// EncryptedArchiveEntry names an archive member CSM cannot read because the
// entry is encrypted. This is deliberately not a partial extraction: a partial
// extraction is a limit or a fault that a later attempt may get past, while an
// encrypted member stays unreadable however many times delivery is retried.
type EncryptedArchiveEntry struct {
	ArchiveName string
	Filename    string
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
	// PartSink creates the file each part is written to. Nil stages parts
	// with os.CreateTemp in TempDir.
	PartSink func(prefix string) (*os.File, error)
	// MaxParts caps how many parts are staged; 0 means no cap. Each staged
	// part holds an open file, so a process with a descriptor limit needs it.
	MaxParts int
}

// MaxParts caps the parts one message stages. Each holds an open file
// until the scan ends, so the cap keeps a message of thousands of tiny
// attachments from exhausting the process's descriptors.
const MaxParts = 200

// DefaultLimits returns the default extraction limits.
func DefaultLimits() Limits {
	return Limits{
		MaxAttachmentSize: 25 * 1024 * 1024,
		MaxArchiveDepth:   1,
		MaxArchiveFiles:   50,
		MaxExtractionSize: 100 * 1024 * 1024,
		MaxParts:          MaxParts,
	}
}

// Close closes every part's file and removes the ones the default sink
// staged on disk.
func (r *ExtractionResult) Close() {
	for _, p := range r.Parts {
		if p.File != nil {
			_ = p.File.Close()
		}
		if p.TempPath != "" {
			_ = os.Remove(p.TempPath)
		}
	}
}

// ParseSpoolMessage parses an Exim spool message (-H and -D files) and
// extracts its attachments. The caller closes the result.
func ParseSpoolMessage(headerPath, bodyPath string, limits Limits) (*ExtractionResult, error) {
	// #nosec G304 -- path is Exim -H file path from mail queue scanner walk.
	header, err := os.Open(headerPath)
	if err != nil {
		return nil, fmt.Errorf("parsing header file: %w", err)
	}
	defer header.Close()
	// #nosec G304 -- path is mail queue file path from scanner walk.
	body, err := os.Open(bodyPath)
	if err != nil {
		return nil, fmt.Errorf("reading body file: %w", err)
	}
	defer body.Close()
	return parseSpool(header, body, filepath.Base(bodyPath), limits)
}

// ParseSpoolFiles is ParseSpoolMessage over open -H and -D files. Both are
// read with positional reads only: a descriptor's offset may be shared with
// whoever opened it. The -D marker line is named after the message ID on
// the first line of -H.
func ParseSpoolFiles(header, body *os.File, limits Limits) (*ExtractionResult, error) {
	return parseSpool(header, body, "", limits)
}

func parseSpool(header, body io.ReaderAt, bodyMarker string, limits Limits) (*ExtractionResult, error) {
	headerData, err := io.ReadAll(io.NewSectionReader(header, 0, maxHeaderFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("parsing header file: %w", err)
	}
	if len(headerData) > maxHeaderFileBytes {
		return &ExtractionResult{Partial: true, PartialReason: "message header exceeds parser memory budget"}, nil
	}
	envelope, hdrs := parseEximHeaderData(headerData)
	if bodyMarker == "" {
		bodyMarker = bodyMarkerFromHeader(headerData)
	}

	result := &ExtractionResult{
		From:    envelope.from,
		To:      envelope.to,
		Subject: envelope.subject,
	}

	// Determine direction from Received headers
	result.Direction = detectDirection(hdrs)

	maxBodyBytes := bodyReadLimit(limits)
	bodyData, partial, err := readBodyLimited(body, maxBodyBytes)
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
	bodyData = stripSpoolBodyMarker(bodyData, bodyMarker)

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
		cte := strings.ToLower(hdrs.Get("Content-Transfer-Encoding"))
		extractEncodedMultipart(bytes.NewReader(bodyData), cte, boundary, limits, result, &totalSize, 0, 0)
	} else if !strings.HasPrefix(mediaType, "text/") {
		// Single-part non-text message (e.g. application/octet-stream,
		// application/pdf, image/*). These are attachment-like payloads
		// that must be scanned even without a multipart wrapper.
		cte := strings.ToLower(hdrs.Get("Content-Transfer-Encoding"))
		readers, _ := transferReaders(cte, bytes.NewReader(bodyData), result)
		var totalSize int64
		for _, reader := range readers {
			decoded, truncated, decodeErr := decodeSinglePart(reader, limits.MaxAttachmentSize+1)

			if decodeErr != nil {
				// The decoded prefix is still scanned; see extractMultipartNested.
				markPartial(result, fmt.Sprintf("could not decode single-part attachment: %v", decodeErr))
			}

			switch {
			case decodeErr != nil && len(decoded) == 0:
				// Nothing decoded, nothing to scan.
			case !truncated && int64(len(decoded)) <= limits.MaxAttachmentSize:
				if int64(len(decoded)) > limits.MaxExtractionSize-totalSize {
					markPartial(result, "total extraction size exceeds limit")
					break
				}
				if partsFull(limits, result) {
					break
				}
				tmpFile, tempPath, tmpErr := limits.createPart("csm-emailav-single-*")
				if tmpErr == nil {
					n, writeErr := tmpFile.Write(decoded)
					if writeErr != nil || n != len(decoded) {
						discardPart(tmpFile, tempPath)
						markPartial(result, "could not stage single-part attachment for scanning")
					} else {
						totalSize += int64(n)
						// Name the body the way a multipart attachment is
						// named: Content-Type name, then the disposition's
						// filename, so a disposition-named archive is unpacked.
						rawFilename := params["name"]
						if rawFilename == "" {
							if _, dparams, err := mime.ParseMediaType(hdrs.Get("Content-Disposition")); err == nil {
								rawFilename = dparams["filename"]
							}
						}
						if rawFilename == "" {
							rawFilename = "attachment"
						}
						filename := SanitizeAttachmentName(rawFilename)
						result.Parts = append(result.Parts, ExtractedPart{
							Filename:    filename,
							ContentType: mediaType,
							Size:        int64(len(decoded)),
							File:        tmpFile,
							TempPath:    tempPath,
						})
						expandArchive(tmpFile, int64(n), rawFilename, filename, limits, result, &totalSize, 0)
					}
				} else {
					markPartial(result, "could not stage single-part attachment for scanning")
				}
			default:
				result.Partial = true
				result.PartialReason = "single-part attachment exceeds max size"
			}
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

// readBodyLimited reads up to limit+1 bytes of the spool body from offset
// 0. Returns (data, partial=true, nil) when the body exceeds the limit so
// the caller can mark the result as partial. Reading the size from the
// same read closes the TOCTOU window a Stat-then-Open sequence had.
func readBodyLimited(r io.ReaderAt, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.NewSectionReader(r, 0, limit+1))
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

// decodeSinglePart returns the decoded body, whether it was cut at limit, and
// any decode error. On error the bytes decoded before it are still returned.
func decodeSinglePart(r io.Reader, limit int64) ([]byte, bool, error) {
	decoded, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(decoded)) > limit {
		return decoded[:limit], true, err
	}
	return decoded, false, err
}

// maxHeaderFileBytes bounds the Exim -H file read into memory. Exim's own
// header size limit keeps real mail far below it.
const maxHeaderFileBytes = 16 << 20

type envelope struct {
	from    string
	to      []string
	subject string
}

// bodyMarkerFromHeader names the -D marker line after the message ID Exim
// writes on the first line of -H ("<id>-H"), or "" when that line is not
// one.
func bodyMarkerFromHeader(headerData []byte) string {
	first, _, _ := bytes.Cut(headerData, []byte("\n"))
	id, ok := strings.CutSuffix(string(bytes.TrimRight(first, "\r")), "-H")
	if !ok || id == "" {
		return ""
	}
	return id + "-D"
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

// ParseSpoolMIMEHeaders returns the live RFC 5322 headers from Exim -H data.
// Folded values are unfolded and deleted headers are omitted, just as they
// are for attachment extraction.
func ParseSpoolMIMEHeaders(data []byte) textproto.MIMEHeader {
	_, headers := parseEximHeaderData(data)
	return headers
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
		if !isMIMEHeaderStart(rest) {
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

func isMIMEHeaderStart(line string) bool {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return false
	}
	for i := 0; i < colon; i++ {
		if !isMIMEHeaderFieldNameByte(line[i]) {
			return false
		}
	}
	return true
}

func isMIMEHeaderFieldNameByte(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		b == '!' || b == '#' || b == '$' || b == '%' ||
		b == '&' || b == '\'' || b == '*' || b == '+' ||
		b == '-' || b == '.' || b == '^' || b == '_' ||
		b == '`' || b == '|' || b == '~'
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
func stripSpoolBodyMarker(bodyData []byte, marker string) []byte {
	if marker == "" {
		return bodyData
	}
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

// extractEncodedMultipart recursively walks MIME parts, extracting attachments.
// depth counts archive nesting (zip-in-zip), not MIME nesting: an archive
// attached five multipart levels down is still archive depth 0.
func extractEncodedMultipart(r io.Reader, cte, boundary string, limits Limits, result *ExtractionResult, totalSize *int64, depth, mimeDepth int) {
	readers, readErr := transferReaders(cte, r, result)
	if readErr != nil {
		markPartial(result, fmt.Sprintf("could not decode multipart body: %v", readErr))
	}
	for _, reader := range readers {
		body := &readErrRecorder{r: reader}
		parseErr := extractMultipartNested(body, boundary, limits, result, totalSize, depth, mimeDepth)
		// A closing MIME delimiter ends parsing before the transfer decoder has
		// necessarily reported its error. Drain the bounded spool body (or this
		// outer part only), including any epilogue, to finish the decoder.
		_, _ = io.Copy(io.Discard, body)
		if body.err != nil {
			markPartial(result, fmt.Sprintf("could not decode multipart body: %v", body.err))
		}
		if parseErr != nil {
			markPartial(result, fmt.Sprintf("could not parse multipart body: %v", parseErr))
		}
	}
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
		part, err := mr.NextRawPart()
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

		cte := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))

		// Recurse into nested multipart. RFC 2045 forbids encoding a
		// multipart body, but a sender can still do it, so decode first.
		if strings.HasPrefix(mediaType, "multipart/") {
			if b := params["boundary"]; b != "" {
				// Failure within one wrapper must not hide its outer siblings.
				extractEncodedMultipart(part, cte, b, limits, result, totalSize, depth, mimeDepth+1)
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
			// Mail clients fall back to the Content-Type name parameter.
			filename = params["name"]
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
		filename = SanitizeAttachmentName(filename)

		readers, readErr := transferReaders(cte, part, result)
		if readErr != nil {
			markPartial(result, fmt.Sprintf("could not decode attachment %q: %v", filename, readErr))
		}
		for _, reader := range readers {
			// Decode the part body based on Content-Transfer-Encoding
			bodyReader := &readErrRecorder{r: reader}

			if partsFull(limits, result) {
				return nil
			}
			tmpFile, tempPath, err := limits.createPart("csm-emailav-*")
			if err != nil {
				markPartial(result, "could not stage attachment for scanning")
				return fmt.Errorf("creating temp file: %w", err)
			}

			limited := io.LimitReader(bodyReader, limits.MaxAttachmentSize+1)
			n, err := io.Copy(tmpFile, limited)
			if err != nil && err != bodyReader.err {
				discardPart(tmpFile, tempPath)
				markPartial(result, "could not stage attachment for scanning")
				continue // fail-open: skip this part
			}
			if bodyReader.err != nil {
				// Keep what decoded: a mail client shows those bytes, so they
				// must be scanned even though the rest of the part is lost.
				markPartial(result, fmt.Sprintf("could not decode attachment %q: %v", filename, bodyReader.err))
				if n == 0 {
					discardPart(tmpFile, tempPath)
					continue
				}
			}

			if n > limits.MaxAttachmentSize {
				discardPart(tmpFile, tempPath)
				result.Partial = true
				result.PartialReason = fmt.Sprintf("attachment %q exceeds max size %d", filename, limits.MaxAttachmentSize)
				continue
			}

			*totalSize += n
			if *totalSize > limits.MaxExtractionSize {
				discardPart(tmpFile, tempPath)
				result.Partial = true
				result.PartialReason = fmt.Sprintf("total extraction size exceeds %d bytes", limits.MaxExtractionSize)
				return nil // stop extracting
			}

			result.Parts = append(result.Parts, ExtractedPart{
				Filename:    filename,
				ContentType: mediaType,
				Size:        n,
				File:        tmpFile,
				TempPath:    tempPath,
			})

			expandArchive(tmpFile, n, rawFilename, filename, limits, result, totalSize, depth)
		}
	}
}

// expandArchive unpacks an archive found at depth (0 for an attachment, 1 for
// a member of an attached archive) while max_archive_depth allows it. Past the
// limit its members were never read, so the message is not fully scanned.
func expandArchive(f *os.File, size int64, rawName, safeName string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) {
	kind := archiveKindForAttachmentName(rawName, safeName)
	if kind == "" {
		return
	}
	if depth >= limits.MaxArchiveDepth {
		markPartial(result, fmt.Sprintf("nested archive %q not expanded", safeName))
		return
	}
	switch kind {
	case "zip":
		extractZIP(f, size, safeName, limits, result, totalSize, depth+1)
	case "tar.gz":
		extractTarGz(f, size, safeName, limits, result, totalSize, depth+1)
	}
}

// maxZipDirectoryBytes bounds the central directory an attached zip may
// declare before any of it is read.
const maxZipDirectoryBytes = 16 << 20

// archiveWalkCap bounds how many entries or headers one archive walk visits,
// of any kind. max_archive_files bounds what is extracted; this bounds the
// work spent getting there.
func archiveWalkCap(limits Limits) int {
	maxInt := int(^uint(0) >> 1)
	if limits.MaxArchiveFiles > maxInt/10 {
		return maxInt
	}
	return 10 * max(limits.MaxArchiveFiles, 1)
}

func markArchiveWalkCap(result *ExtractionResult, archiveName string, walkCap int) {
	markPartial(result, fmt.Sprintf("archive %q lists more than %d entries", archiveName, walkCap))
}

func markExtractionBudget(result *ExtractionResult, limits Limits) {
	result.Partial = true
	result.PartialReason = fmt.Sprintf("total extraction size exceeds %d bytes", limits.MaxExtractionSize)
}

// errExtractionBudget stops a decompressing reader once the message's
// extraction budget is spent.
var errExtractionBudget = errors.New("extraction budget spent")

// budgetReader adds what it yields to the message's shared spent count and
// fails once that count passes limit, reading at most one byte past it.
// Nested archives add to the same count. The first error sticks.
type budgetReader struct {
	r     io.Reader
	spent *int64
	limit int64
	err   error
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if *b.spent > b.limit {
		b.err = errExtractionBudget
		return 0, b.err
	}
	if remaining := b.limit - *b.spent; remaining < int64(len(p)) {
		p = p[:remaining+1]
	}
	n, err := b.r.Read(p)
	*b.spent += int64(n)
	if *b.spent > b.limit {
		err = errExtractionBudget
	}
	// io.ReadFull may suppress an error returned with its final bytes. Keep
	// it visible to the archive driver even when tar.Next reports EOF.
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// markArchiveUnopened records an attached archive whose members could not be
// reached at all.
func markArchiveUnopened(result *ExtractionResult, archiveName string, err error) {
	markPartial(result, fmt.Sprintf("archive %q could not be opened: %v", archiveName, err))
}

// zipEncryptedFlag is bit 0 of the ZIP general purpose bit flag: the entry is
// encrypted. APPNOTE.TXT section 4.4.4.
const zipEncryptedFlag = 0x1

// extractZIP reads the archive from its staged part file, which stays open
// and owned by the result.
func extractZIP(part *os.File, size int64, archiveName string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) {
	// An archive that cannot be opened was not scanned inside: a mail client
	// may still repair and open it, so it must never count as clean.
	f := io.NewSectionReader(part, 0, size)
	// Validate the listing itself before zip.NewReader allocates per entry;
	// the sender controls both the directory and the end record's counts.
	walkCap := archiveWalkCap(limits)
	dir, err := zipdir.Read(f, size, maxZipDirectoryBytes)
	if err != nil {
		markArchiveUnopened(result, archiveName, err)
		return
	}
	if err = validateZIPDirectory(f, size, dir, walkCap); err != nil {
		if errors.Is(err, errArchiveWalk) {
			markArchiveWalkCap(result, archiveName, walkCap)
		} else {
			markArchiveUnopened(result, archiveName, err)
		}
		return
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		markArchiveUnopened(result, archiveName, err)
		return
	}

	extracted, walked := 0, 0
	for _, zf := range zr.File {
		walked++
		if walked > walkCap {
			markArchiveWalkCap(result, archiveName, walkCap)
			return
		}
		safeName := SanitizeAttachmentName(zf.Name)

		// Bit 0 of the general purpose flag marks an encrypted entry. Both
		// encryption schemes in the wild set it, which matters because they
		// fail in different places otherwise: legacy ZipCrypto keeps the
		// deflate method and fails during the read, while WinZip AES uses
		// method 99 and fails when the entry is opened. Reading the flag
		// catches both before either produces a misleading error.
		if zf.Flags&zipEncryptedFlag != 0 {
			if len(result.EncryptedEntries) < limits.MaxArchiveFiles {
				result.EncryptedEntries = append(result.EncryptedEntries, EncryptedArchiveEntry{
					ArchiveName: archiveName,
					Filename:    safeName,
				})
			} else {
				result.EncryptedEntriesOmitted++
			}
			continue
		}
		if zf.FileInfo().IsDir() {
			if dirErr := validateZIPDirectoryEntry(zf); dirErr != nil {
				markPartial(result, fmt.Sprintf("directory %q in archive %q contains unread data", safeName, archiveName))
			}
			continue
		}
		if extracted >= limits.MaxArchiveFiles {
			markPartial(result, fmt.Sprintf("archive %q exceeds max files %d", archiveName, limits.MaxArchiveFiles))
			return
		}

		// A member costs whichever is larger, its compressed or its inflated
		// size. Records can share one compressed stream that inflates to
		// nothing, so the compressed size is charged before inflating.
		before := *totalSize
		compressed := int64(min(zf.CompressedSize64, uint64(limits.MaxExtractionSize)+1)) // #nosec G115 -- bounded by an int64 above.
		if before+compressed > limits.MaxExtractionSize {
			// Never opened, so nothing is spent; the budget is exhausted.
			markExtractionBudget(result, limits)
			return
		}

		rc, err := zf.Open()
		if err != nil {
			markPartial(result, fmt.Sprintf("could not decompress file %q in archive %q: %v", safeName, archiveName, err))
			continue
		}

		if partsFull(limits, result) {
			rc.Close()
			return
		}
		tmpFile, tempPath, err := limits.createPart("csm-emailav-zip-*")
		if err != nil {
			rc.Close()
			markPartial(result, fmt.Sprintf("could not stage file %q in archive %q for scanning: %v", safeName, archiveName, err))
			continue
		}

		// Every decompressed byte spends the budget, kept or thrown away, so
		// a bomb of oversize members cannot decompress without limit.
		var inflated int64
		budget := &budgetReader{r: rc, spent: &inflated, limit: limits.MaxExtractionSize - before}
		limited := io.LimitReader(budget, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		rc.Close()
		*totalSize = before + max(compressed, inflated)

		if errors.Is(err, errExtractionBudget) || *totalSize > limits.MaxExtractionSize {
			discardPart(tmpFile, tempPath)
			markExtractionBudget(result, limits)
			return
		}

		if err != nil || n > limits.MaxAttachmentSize {
			discardPart(tmpFile, tempPath)
			if n > limits.MaxAttachmentSize {
				result.Partial = true
				result.PartialReason = fmt.Sprintf("file %q in archive exceeds max size", safeName)
			} else {
				markPartial(result, fmt.Sprintf("could not decompress file %q in archive %q: %v", safeName, archiveName, err))
			}
			continue
		}

		result.Parts = append(result.Parts, ExtractedPart{
			Filename:    safeName,
			ContentType: "application/octet-stream",
			Size:        n,
			File:        tmpFile,
			TempPath:    tempPath,
			Nested:      true,
			ArchiveName: archiveName,
		})
		extracted++
		expandArchive(tmpFile, n, zf.Name, safeName, limits, result, totalSize, depth)
	}
}

// extractTarGz reads the archive from its staged part file, which stays
// open and owned by the result.
func extractTarGz(part *os.File, size int64, archiveName string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) {
	compressed := bufio.NewReader(io.NewSectionReader(part, 0, size))
	gr, err := gzip.NewReader(compressed)
	if err != nil {
		markArchiveUnopened(result, archiveName, err)
		return
	}
	defer func() { _ = gr.Close() }()
	// Count streams explicitly so empty streams cannot bypass either budget.
	gr.Multistream(false)

	// Everything the gzip stream yields spends the budget, including the
	// remainder tar.Next reads through to skip an oversize member.
	walkCap := archiveWalkCap(limits)
	streams := &gzipStreamReader{compressed: compressed, gr: gr, walkCap: walkCap, streams: 1}
	budget := &budgetReader{r: streams, spent: totalSize, limit: limits.MaxExtractionSize}
	walk := &tarWalkReader{r: budget, walkCap: walkCap}
	tr := tar.NewReader(walk)
	extracted := 0
	for {
		hdr, err := tr.Next()
		if budget.err != nil {
			err = budget.err
		}
		if err == io.EOF {
			err = finishTar(budget)
			if err == nil {
				return
			}
		}
		if errors.Is(err, errExtractionBudget) {
			markExtractionBudget(result, limits)
			return
		}
		if errors.Is(err, errArchiveWalk) {
			markArchiveWalkCap(result, archiveName, walkCap)
			return
		}
		if err != nil {
			// The members after a broken header were never read.
			markPartial(result, fmt.Sprintf("archive %q could not be read: %v", archiveName, err))
			return
		}
		if err = walk.setMember(hdr); err != nil {
			markPartial(result, fmt.Sprintf("archive %q could not be read: %v", archiveName, err))
			return
		}
		if hdr.Typeflag != tar.TypeReg {
			if walk.remaining > 0 && hdr.Typeflag != tar.TypeXGlobalHeader {
				markPartial(result, fmt.Sprintf("unsupported file %q in archive %q contains unread data", SanitizeAttachmentName(hdr.Name), archiveName))
			}
			continue
		}
		if extracted >= limits.MaxArchiveFiles {
			result.Partial = true
			result.PartialReason = fmt.Sprintf("archive %q exceeds max files %d", archiveName, limits.MaxArchiveFiles)
			return
		}
		safeName := SanitizeAttachmentName(hdr.Name)

		if partsFull(limits, result) {
			return
		}
		tmpFile, tempPath, err := limits.createPart("csm-emailav-tgz-*")
		if err != nil {
			markPartial(result, fmt.Sprintf("could not stage file %q in archive %q for scanning: %v", safeName, archiveName, err))
			continue
		}

		// Sparse tar readers synthesize hole bytes outside the gzip stream.
		// Bound logical output too, then charge only the bytes the physical
		// stream did not already spend.
		before := *totalSize
		var logicalN int64
		logical := &budgetReader{r: tr, spent: &logicalN, limit: limits.MaxExtractionSize - before}
		limited := io.LimitReader(logical, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		*totalSize += max(logicalN-(*totalSize-before), 0)
		if *totalSize > limits.MaxExtractionSize {
			budget.err = errExtractionBudget
		}
		if budget.err != nil {
			err = budget.err
		}

		if errors.Is(err, errExtractionBudget) {
			discardPart(tmpFile, tempPath)
			markExtractionBudget(result, limits)
			return
		}
		if err != nil || n > limits.MaxAttachmentSize {
			discardPart(tmpFile, tempPath)
			if n > limits.MaxAttachmentSize {
				result.Partial = true
				result.PartialReason = fmt.Sprintf("file %q in archive exceeds max size", safeName)
			} else {
				markPartial(result, fmt.Sprintf("could not read file %q from archive %q: %v", safeName, archiveName, err))
			}
			continue
		}

		result.Parts = append(result.Parts, ExtractedPart{
			Filename:    safeName,
			ContentType: "application/octet-stream",
			Size:        n,
			File:        tmpFile,
			TempPath:    tempPath,
			Nested:      true,
			ArchiveName: archiveName,
		})
		extracted++
		expandArchive(tmpFile, n, hdr.Name, safeName, limits, result, totalSize, depth)
	}
}

// maxAttachmentNameBytes caps a name that reaches logs, alerts and the parse
// worker's replies.
const maxAttachmentNameBytes = 255

// SanitizeAttachmentName trims an attachment or archive-entry name to its
// base name, truncates at control characters, replaces invalid UTF-8 and
// caps it at 255 bytes before the name reaches logs, alerts, or JSON
// responses.
func SanitizeAttachmentName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	// Truncate at the first control character so a crafted entry
	// like "good.txt\nFAKE-LOG-LINE" cannot smuggle a forged log
	// record past the visible filename.
	if i := strings.IndexFunc(name, unicode.IsControl); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(TruncateUTF8(strings.ToValidUTF8(name, "\uFFFD"), maxAttachmentNameBytes))
	switch name {
	case "", ".", "..", "/":
		return "_unnamed_"
	}
	return name
}

// TruncateUTF8 cuts s to at most max bytes without splitting a rune.
func TruncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// createPart opens the file for one staged part. tempPath is set only when
// the default sink put it on disk.
func (l Limits) createPart(prefix string) (f *os.File, tempPath string, err error) {
	if l.PartSink != nil {
		f, err = l.PartSink(prefix)
		return f, "", err
	}
	f, err = os.CreateTemp(l.TempDir, prefix)
	if err != nil {
		return nil, "", err
	}
	return f, f.Name(), nil
}

func discardPart(f *os.File, tempPath string) {
	_ = f.Close()
	if tempPath != "" {
		_ = os.Remove(tempPath)
	}
}

// partsFull reports, and records as partial, a message that already staged
// MaxParts parts.
func partsFull(limits Limits, result *ExtractionResult) bool {
	if limits.MaxParts <= 0 || len(result.Parts) < limits.MaxParts {
		return false
	}
	markPartial(result, fmt.Sprintf("message has more than %d attachments", limits.MaxParts))
	return true
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
