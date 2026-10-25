//go:build linux

package parseworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"

	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/workerproc"
)

func extractMessage(req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
	if len(fds) != 2 {
		return workerproc.Frame{Error: fmt.Sprintf("extract_message takes two descriptors, got %d", len(fds))}, nil
	}
	for _, f := range fds {
		st, err := f.Stat()
		if err != nil {
			return workerproc.Frame{Error: err.Error()}, nil
		}
		if !st.Mode().IsRegular() {
			return workerproc.Frame{Error: "extract_message descriptor is not a regular file"}, nil
		}
	}
	var args ExtractArgs
	dec := json.NewDecoder(bytes.NewReader(req.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&args); err != nil {
		return workerproc.Frame{Error: fmt.Sprintf("extract_message arguments: %v", err)}, nil
	}
	parsed, err := emime.ParseSpoolFiles(fds[0], fds[1], emime.Limits{
		MaxAttachmentSize: args.MaxAttachmentSize,
		MaxArchiveDepth:   args.MaxArchiveDepth,
		MaxArchiveFiles:   args.MaxArchiveFiles,
		MaxExtractionSize: args.MaxExtractionSize,
		MaxParts:          MaxParts,
		PartSink:          memfdPart,
	})
	if err != nil {
		return extractResult(ExtractResult{Partial: true, PartialReason: cleanText(err.Error(), maxIncomplete)}), nil
	}
	res := ExtractResult{
		Partial:       parsed.Partial,
		PartialReason: cleanText(parsed.PartialReason, maxIncomplete),
		Direction:     parsed.Direction,
		From:          cleanText(parsed.From, maxHeaderBytes),
		Subject:       cleanText(parsed.Subject, maxHeaderBytes),
	}
	for _, to := range parsed.To[:min(len(parsed.To), maxRecipients)] {
		res.To = append(res.To, cleanText(to, maxHeaderBytes))
	}
	entries := make([]EncryptedEntry, 0, len(parsed.EncryptedEntries))
	for _, e := range parsed.EncryptedEntries {
		entries = append(entries, EncryptedEntry{ArchiveName: e.ArchiveName, Filename: e.Filename})
	}
	capEncrypted(&res, entries, parsed.EncryptedEntriesOmitted)
	files := make([]*os.File, 0, len(parsed.Parts))
	for _, p := range parsed.Parts {
		if p.Size == 0 {
			// Nothing to scan; a descriptor for it would only spend the budget.
			_ = p.File.Close()
			continue
		}
		if err := sealFile(p.File); err != nil {
			parsed.Close()
			return workerproc.Frame{Error: fmt.Sprintf("seal part: %v", err)}, nil
		}
		res.Parts = append(res.Parts, ExtractPart{
			Filename:    p.Filename,
			ContentType: cleanText(p.ContentType, maxNameBytes),
			Size:        p.Size,
			Nested:      p.Nested,
			ArchiveName: p.ArchiveName,
		})
		files = append(files, p.File)
	}
	return extractResult(res), files
}

// capEncrypted keeps at most MaxEncryptedEntries names and counts the rest.
func capEncrypted(res *ExtractResult, entries []EncryptedEntry, omitted int) {
	keep := min(len(entries), MaxEncryptedEntries)
	res.EncryptedEntries = entries[:keep]
	res.EncryptedEntriesOmitted = omitted + len(entries) - keep
}

func memfdPart(string) (*os.File, error) {
	fd, err := unix.MemfdCreate("csm-mail-part", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "csm-mail-part"), nil
}

// cleanText makes a header-derived string safe to send: no control
// characters but tab (the daemon refuses them, as they can forge log
// lines), valid UTF-8, at most max bytes. Encoded, such a string is at most
// twice its length, which is what keeps the worst-case reply in its frame.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r != '\t' && unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return emime.TruncateUTF8(strings.ToValidUTF8(s, "\uFFFD"), max)
}

// extractResult encodes without HTML escaping: escaped, '<' alone would
// take six bytes and push a crafted reply past the frame cap.
func extractResult(r ExtractResult) workerproc.Frame {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r) // Numbers, strings and bools cannot fail to encode.
	return workerproc.Frame{Payload: bytes.TrimSuffix(buf.Bytes(), []byte("\n"))}
}
