//go:build linux

package parseworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

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
		return extractResult(ExtractResult{Partial: true, PartialReason: emime.TruncateUTF8(err.Error(), maxIncomplete)}), nil
	}
	res := ExtractResult{
		Partial:       parsed.Partial,
		PartialReason: emime.TruncateUTF8(parsed.PartialReason, maxIncomplete),
		Direction:     parsed.Direction,
		From:          emime.TruncateUTF8(parsed.From, maxHeaderBytes),
		Subject:       emime.TruncateUTF8(parsed.Subject, maxHeaderBytes),
	}
	for _, to := range parsed.To[:min(len(parsed.To), maxRecipients)] {
		res.To = append(res.To, emime.TruncateUTF8(to, maxHeaderBytes))
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
			ContentType: emime.TruncateUTF8(p.ContentType, maxNameBytes),
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

func extractResult(r ExtractResult) workerproc.Frame {
	payload, _ := json.Marshal(r) // Numbers, strings and bools cannot fail to marshal.
	return workerproc.Frame{Payload: payload}
}
