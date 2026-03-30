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
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
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

	bodyData, err := os.ReadFile(bodyPath)
	if err != nil {
		return nil, fmt.Errorf("reading body file: %w", err)
	}

	result := &ExtractionResult{
		From:    envelope.from,
		To:      envelope.to,
		Subject: envelope.subject,
	}

	// Determine direction from Received headers
	result.Direction = detectDirection(hdrs)

	ct := hdrs.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		// Unparseable content type — treat as plain text, no attachments
		return result, nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return result, nil
		}
		var totalSize int64
		err = extractMultipart(bytes.NewReader(bodyData), boundary, limits, result, &totalSize, 0)
		if err != nil {
			return result, nil // fail-open: return what we have
		}
	} else if !strings.HasPrefix(mediaType, "text/") {
		// Single-part non-text message (e.g. application/octet-stream,
		// application/pdf, image/*). These are attachment-like payloads
		// that must be scanned even without a multipart wrapper.
		cte := strings.ToLower(hdrs.Get("Content-Transfer-Encoding"))
		var decoded []byte
		switch cte {
		case "base64":
			decoded, _ = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(bodyData)))
		case "quoted-printable":
			decoded, _ = io.ReadAll(quotedprintable.NewReader(bytes.NewReader(bodyData)))
		default:
			decoded = bodyData
		}

		if int64(len(decoded)) <= limits.MaxAttachmentSize {
			tmpFile, err := os.CreateTemp("", "csm-emailav-single-*")
			if err == nil {
				tmpFile.Write(decoded)
				tmpFile.Close()
				filename := params["name"]
				if filename == "" {
					filename = "attachment"
				}
				result.Parts = append(result.Parts, ExtractedPart{
					Filename:    filename,
					ContentType: mediaType,
					Size:        int64(len(decoded)),
					TempPath:    tmpFile.Name(),
				})
			}
		} else {
			result.Partial = true
			result.PartialReason = "single-part attachment exceeds max size"
		}
	}
	// text/* bodies are not attachments — skip

	return result, nil
}

type envelope struct {
	from    string
	to      []string
	subject string
}

// parseEximHeader reads an Exim -H file and extracts envelope info and headers.
// Exim -H files have a specific format: the first lines are Exim internal metadata,
// followed by RFC 2822 headers.
func parseEximHeader(path string) (*envelope, textproto.MIMEHeader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	env := &envelope{}

	// Parse as mail message to extract headers — find the header block
	// Exim -H files contain envelope info then headers separated by a blank line pattern.
	// We look for standard RFC headers.
	reader := bufio.NewReader(bytes.NewReader(data))

	// Collect the raw header text by finding lines that look like RFC 822 headers
	var headerBuf bytes.Buffer
	inHeaders := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")

		// Detect start of RFC headers (lines like "From:", "To:", "Subject:", etc.)
		if !inHeaders {
			if len(trimmed) > 0 && strings.Contains(trimmed, ":") {
				lower := strings.ToLower(trimmed)
				if strings.HasPrefix(lower, "from:") ||
					strings.HasPrefix(lower, "to:") ||
					strings.HasPrefix(lower, "subject:") ||
					strings.HasPrefix(lower, "date:") ||
					strings.HasPrefix(lower, "mime-version:") ||
					strings.HasPrefix(lower, "content-type:") ||
					strings.HasPrefix(lower, "received:") ||
					strings.HasPrefix(lower, "message-id:") {
					inHeaders = true
				}
			}
		}

		if inHeaders {
			headerBuf.WriteString(line)
			if trimmed == "" {
				break // end of headers
			}
		}
	}

	// Parse the collected headers
	msg, err := mail.ReadMessage(&headerBuf)
	if err != nil {
		// Try to extract what we can from the raw data
		return env, make(textproto.MIMEHeader), nil
	}

	env.from = msg.Header.Get("From")
	env.subject = msg.Header.Get("Subject")
	if to := msg.Header.Get("To"); to != "" {
		for _, addr := range strings.Split(to, ",") {
			env.to = append(env.to, strings.TrimSpace(addr))
		}
	}

	// Convert mail.Header to textproto.MIMEHeader
	hdrs := make(textproto.MIMEHeader)
	for k, v := range msg.Header {
		hdrs[k] = v
	}

	return env, hdrs, nil
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

// extractMultipart recursively walks MIME parts, extracting attachments.
func extractMultipart(r io.Reader, boundary string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) error {
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
				if err := extractMultipart(part, b, limits, result, totalSize, depth); err != nil {
					return err
				}
			}
			continue
		}

		// Skip inline text bodies — only extract attachments
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
			// No filename and text/* content — this is a body part, skip
			if strings.HasPrefix(mediaType, "text/") {
				continue
			}
			// Non-text without filename — use generic name
			filename = "unnamed_attachment"
		}

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
		tmpFile, err := os.CreateTemp("", "csm-emailav-*")
		if err != nil {
			return fmt.Errorf("creating temp file: %w", err)
		}

		limited := io.LimitReader(bodyReader, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		tmpFile.Close()
		if err != nil {
			os.Remove(tmpFile.Name())
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
		lower := strings.ToLower(filename)
		if depth < limits.MaxArchiveDepth {
			if strings.HasSuffix(lower, ".zip") {
				extractZIP(tmpFile.Name(), filename, limits, result, totalSize, depth+1)
			} else if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
				extractTarGz(tmpFile.Name(), filename, limits, result, totalSize, depth+1)
			}
		}
	}
}

func extractZIP(zipPath, archiveName string, limits Limits, result *ExtractionResult, totalSize *int64, depth int) {
	f, err := os.Open(zipPath)
	if err != nil {
		return // fail-open: skip corrupt archives
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		f.Close()
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

		rc, err := zf.Open()
		if err != nil {
			continue
		}

		tmpFile, err := os.CreateTemp("", "csm-emailav-zip-*")
		if err != nil {
			rc.Close()
			continue
		}

		limited := io.LimitReader(rc, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		tmpFile.Close()
		rc.Close()

		if err != nil || n > limits.MaxAttachmentSize {
			os.Remove(tmpFile.Name())
			if n > limits.MaxAttachmentSize {
				result.Partial = true
				result.PartialReason = fmt.Sprintf("file %q in archive exceeds max size", zf.Name)
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
			Filename:    zf.Name,
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
	f, err := os.Open(tgzPath)
	if err != nil {
		return
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	extracted := 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			return // EOF or error — done
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if extracted >= limits.MaxArchiveFiles {
			result.Partial = true
			result.PartialReason = fmt.Sprintf("archive %q exceeds max files %d", archiveName, limits.MaxArchiveFiles)
			return
		}

		tmpFile, err := os.CreateTemp("", "csm-emailav-tgz-*")
		if err != nil {
			continue
		}

		limited := io.LimitReader(tr, limits.MaxAttachmentSize+1)
		n, err := io.Copy(tmpFile, limited)
		tmpFile.Close()

		if err != nil || n > limits.MaxAttachmentSize {
			os.Remove(tmpFile.Name())
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
			Filename:    filepath.Base(hdr.Name),
			ContentType: "application/octet-stream",
			Size:        n,
			TempPath:    tmpFile.Name(),
			Nested:      true,
			ArchiveName: archiveName,
		})
		extracted++
	}
}
